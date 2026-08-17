/**
 * Daemon-side bounded auto-renewal scheduler for ISCP trust grants
 * (frozen contract: InfinimeshCloud docs/10-design/12-managed-provisioning.md
 * §10.4, `POST /v2/relay/devices/auto-renew-grant`; OPS 2026-08-17 §8.3/§8.4).
 *
 * The scheduler lives in the long-lived daemon process, one evaluation per
 * enrolled profile per tick. It never depends on the phone app being
 * foreground or a session being open; the only inputs are the on-disk
 * profile bundle and this module's own state file.
 *
 * Renewal window: min(24h, grantTTL / 5), where grantTTL is approximated as
 * `expires_at − not_before` (the bundle carries no separate issued_at). The
 * first attempt for a grant is jittered inside the window; an EXPIRED grant
 * with a live server-side authorization is a recoverable state — it renews
 * immediately (the E2E session correctly stays authorization_expired until
 * the new grant lands; nothing fails open and nothing re-enrolls).
 *
 * ## Retry ladder (thought through against §10.4's server order)
 *
 * The server processes: [idempotency replay] → flag → proof verify → nonce
 * replay-cache insert → authorization lookup → thumbprint/audience gates →
 * eligibility gate → issue + store idempotent response. The client-generated
 * unguessable Idempotency-Key doubles as the proof challenge, so one LOGICAL
 * renewal = one key; the proof nonce is per-transmission.
 *
 * 1. Fresh attempt: mint key K, mint proof P (challenge = K), persist
 *    {K, P, predecessor grant id} to the state file BEFORE the request is
 *    sent — a crash at any later point leaves enough to converge.
 * 2. Known outcome:
 *    - 201 → verify + atomically apply the grant (generation+1), clear the
 *      in-flight record, reschedule from the NEW grant's window, hot-reload
 *      the peers (single-flight).
 *    - terminal reason → persist action-required (stable reason), STOP.
 *      These need a human (re-authorize / step-up / replace); tight-retrying
 *      or falling back to enroll would be wrong and is never done.
 *    - transient reason (renewal_not_yet_eligible / rate_limited / 5xx) →
 *      nothing was issued and error responses are also idempotently stored,
 *      so the NEXT attempt is a new logical renewal: clear the in-flight
 *      record and back off (bounded exponential + jitter, Retry-After wins
 *      when the server provides it).
 * 3. Unknown outcome (network error / timeout / daemon crash): the in-flight
 *    record survives; the retry resends the SAME key K with the SAME proof P
 *    verbatim. If the first transmission completed, the idempotency layer
 *    replays the stored 201 BEFORE proof verification, so a stale/burned
 *    proof does not matter.
 * 4. Verbatim retry rejected with proof_replay_detected / device_proof_invalid:
 *    this is the "key unknown to the idempotency layer, but proof P is dead"
 *    case (P's nonce entered the replay cache without a completed response,
 *    or P aged past the ±5 min window). The nonce is single-use, but the
 *    CHALLENGE binding is to K, not the nonce — so the ladder escalates ONCE
 *    to a freshly minted proof P' for the SAME K (persisted before sending):
 *    - if the server had completed after all → replay, done;
 *    - if not → clean re-execution with a valid fresh proof.
 * 5. proof_replay_detected AGAIN for the fresh nonce of P' is a contract
 *    anomaly (a brand-new nonce cannot legitimately be in the replay cache)
 *    → surface an action-required error state instead of looping.
 *    device_proof_invalid for a FRESH proof means clock skew or a local/Cloud
 *    key mismatch → bounded transient backoff (skew heals; a real mismatch
 *    keeps surfacing in the status output and eventually needs the manual
 *    §9 path).
 *
 * A key is never reused across logical renewals: after any KNOWN-outcome
 * failure the next attempt mints a fresh key (replaying a stored error
 * response forever would wedge the scheduler). A retried key that the server
 * has already completed replays the stored 201; a DIFFERENT key inside the
 * eligibility window yields 429 renewal_not_yet_eligible — never a double
 * issue — which the transient path absorbs.
 *
 * This module NEVER creates devices, consumes tickets, touches device keys,
 * or falls back to re-enrollment — it only re-issues `trust_grant` via the
 * shared verify+apply step of the manual renewal path.
 */

import { randomBytes } from 'node:crypto'
import { chmodSync, existsSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

import {
  createDeviceProof,
  createNobleProvider,
  IscpError,
  RelayHttpClient,
  toBase64Url,
  verifyRelayDescriptor,
  type CryptoProvider,
  type DeviceProof,
  type GrantRenewal,
  type TrustGrant,
} from '@slopus/iscp'

import {
  inspectProfile,
  iscpProfileDir,
  listProfiles,
  resolveTrustDescriptorForVerification,
  verifyAndApplyRenewedGrant,
  withProfileLock,
  type IscpProfileBundle,
} from '@/iscp/enrollment'

// ---------------------------------------------------------------------------
// Window math (OPS §8.3: window = min(24h, grantTTL/5))
// ---------------------------------------------------------------------------

export const MAX_RENEWAL_WINDOW_MS = 24 * 3600 * 1000

/** Grant TTL approximated as expires_at − not_before. */
export function grantTtlMs(grant: TrustGrant): number {
  return Math.max(0, new Date(grant.expires_at).getTime() - new Date(grant.not_before).getTime())
}

export function renewalWindowMs(grant: TrustGrant): number {
  return Math.min(MAX_RENEWAL_WINDOW_MS, Math.floor(grantTtlMs(grant) / 5))
}

/** Epoch ms at which the renewal window opens (clamped by the caller to now for expired grants). */
export function renewalWindowOpensAtMs(grant: TrustGrant): number {
  return new Date(grant.expires_at).getTime() - renewalWindowMs(grant)
}

// ---------------------------------------------------------------------------
// State file (per profile, next to the bundle; the daemon is the only writer)
// ---------------------------------------------------------------------------

export interface AutoRenewalInflight {
  idempotency_key: string
  /** The exact proof sent with the first transmission (verbatim retry). */
  proof: DeviceProof
  /** Set when the verbatim proof was already rejected and a fresh proof for the same key was minted. */
  proof_reminted?: boolean
  started_at: string
  predecessor_grant_id: string
}

export interface AutoRenewalActionRequired {
  /** Stable server reason (renewal_authorization_expired, require_mfa, ...) or proof_replay_anomaly. */
  reason: string
  at: string
  /** The grant that was current when auto-renewal stopped; a different current grant clears this state. */
  grant_id: string
  detail?: string
}

export interface AutoRenewalState {
  version: 1
  /** First-attempt schedule for the current grant (windowOpen + jitter), persisted across restarts. */
  scheduled?: { grant_id: string; next_attempt_at: string }
  inflight?: AutoRenewalInflight
  action_required?: AutoRenewalActionRequired
  last_attempt_at?: string
  /** 'renewed' or the stable failure reason of the last attempt. */
  last_result?: string
  last_success_at?: string
  /** Consecutive non-success attempts — the exponential backoff index. */
  failure_count?: number
}

export function autoRenewalStateFile(profileId: string): string {
  return join(iscpProfileDir(profileId), 'auto-renewal.json')
}

export function readAutoRenewalState(profileId: string): AutoRenewalState | null {
  const file = autoRenewalStateFile(profileId)
  if (!existsSync(file)) return null
  try {
    const raw = JSON.parse(readFileSync(file, 'utf8')) as AutoRenewalState
    return raw !== null && typeof raw === 'object' && raw.version === 1 ? raw : null
  } catch {
    return null
  }
}

/** Atomic write (temp + rename, 0600) so a crash never leaves a torn state file. */
export function writeAutoRenewalState(profileId: string, state: AutoRenewalState): void {
  const file = autoRenewalStateFile(profileId)
  const tempPath = `${file}.tmp-${process.pid}-${randomBytes(6).toString('hex')}`
  writeFileSync(tempPath, JSON.stringify(state, null, 2), { mode: 0o600 })
  chmodSync(tempPath, 0o600)
  renameSync(tempPath, file)
}

// ---------------------------------------------------------------------------
// Outcome classification (stable reasons frozen in §10.4)
// ---------------------------------------------------------------------------

/**
 * Action-required outcomes: auto-renewal STOPS (no tight retry, never a
 * fallback to enroll/replace) until a human re-authorizes / steps up /
 * replaces — observed as a NEW current grant, which clears the state.
 */
export const TERMINAL_RENEWAL_REASONS: ReadonlySet<string> = new Set([
  'renewal_authorization_not_found',
  'renewal_authorization_revoked',
  'renewal_authorization_expired',
  'renewal_identity_conflict',
  'device_revoked',
  'grant_audience_not_active',
  'require_mfa',
  'auto_renewal_disabled',
])

export type RenewalFailure =
  | { kind: 'terminal'; reason: string }
  | { kind: 'transient'; reason: string; retryAfterMs?: number }
  | { kind: 'proof-stale'; reason: 'proof_replay_detected' | 'device_proof_invalid' }
  | { kind: 'unknown'; reason: string }

/** IscpError.details is a wire-shaped string map; numeric metadata is string-encoded. */
function detailNumber(value: unknown): number | undefined {
  return typeof value === 'string' && /^\d+$/.test(value) ? Number(value) : undefined
}

export function classifyRenewalFailure(error: unknown): RenewalFailure {
  if (error instanceof IscpError) {
    const reason = typeof error.details?.reason === 'string' ? error.details.reason : undefined
    const httpStatus = detailNumber(error.details?.httpStatus)
    const retryAfterSeconds = detailNumber(error.details?.retryAfterSeconds)
    if (reason !== undefined && TERMINAL_RENEWAL_REASONS.has(reason)) {
      return { kind: 'terminal', reason }
    }
    if (reason === 'proof_replay_detected' || reason === 'device_proof_invalid') {
      return { kind: 'proof-stale', reason }
    }
    if (reason === 'renewal_not_yet_eligible' || reason === 'rate_limited') {
      return {
        kind: 'transient',
        reason,
        ...(retryAfterSeconds !== undefined ? { retryAfterMs: retryAfterSeconds * 1000 } : {}),
      }
    }
    // 5xx (upstream fail-closed) and any other enveloped rejection: a known
    // outcome, nothing issued — bounded backoff with a fresh key.
    return { kind: 'transient', reason: reason ?? `http_${httpStatus ?? 'error'}` }
  }
  // No response at all (fetch/socket failure, abort): the outcome is UNKNOWN —
  // the in-flight key must be kept and retried verbatim.
  return { kind: 'unknown', reason: error instanceof Error ? error.message : 'network_error' }
}

// ---------------------------------------------------------------------------
// One profile evaluation (policy core — fully dependency-injected)
// ---------------------------------------------------------------------------

/** Bounded backoff for non-success attempts: 1m, 5m, 15m, 1h, 6h (capped). */
export const AUTO_RENEWAL_BACKOFF_MS = [60_000, 300_000, 900_000, 3_600_000, 21_600_000]

export interface ProfileRenewalDeps {
  profileId: string
  bundle: IscpProfileBundle
  /** Single-shot wire call: POST auto-renew-grant with exactly this key + proof. */
  send: (opts: { idempotencyKey: string; proof: DeviceProof }) => Promise<GrantRenewal>
  /** Mint a possession proof for the given challenge (= the idempotency key). */
  makeProof: (challenge: string) => DeviceProof
  /** Unguessable idempotency key generator. */
  newKey: () => string
  /** Verify + atomically persist the renewed grant (generation+1) and hot-reload. */
  applyGrant: (renewal: GrantRenewal) => Promise<void>
  readState: () => AutoRenewalState | null
  writeState: (state: AutoRenewalState) => void
  now: () => number
  /** Random in [0,1); injectable for deterministic tests. */
  random?: () => number
  backoffScheduleMs?: number[]
  log: (line: string) => void
}

function backoffDelayMs(deps: ProfileRenewalDeps, failureCount: number, retryAfterMs?: number): number {
  const schedule = deps.backoffScheduleMs ?? AUTO_RENEWAL_BACKOFF_MS
  const base = schedule[Math.min(Math.max(failureCount - 1, 0), schedule.length - 1)]!
  const withFloor = Math.max(base, retryAfterMs ?? 0)
  const random = deps.random ?? Math.random
  // ±20% jitter, never below a server-provided Retry-After.
  const jittered = Math.round(withFloor * (1 + (random() * 2 - 1) * 0.2))
  return Math.max(jittered, retryAfterMs ?? 0)
}

/** First-attempt jitter inside the window: up to min(1h, window/10). */
export function firstAttemptAtMs(grant: TrustGrant, now: number, random: () => number): number {
  const opensAt = Math.max(renewalWindowOpensAtMs(grant), 0)
  const jitterSpan = Math.min(3_600_000, Math.floor(renewalWindowMs(grant) / 10))
  const base = Math.max(opensAt, now)
  // An expired grant renews immediately: no jitter once past expiry.
  if (now >= new Date(grant.expires_at).getTime()) return now
  return base + Math.floor(random() * jitterSpan)
}

export type ProfileEvaluation =
  | { acted: false; state: 'action-required' | 'waiting' | 'scheduled' | 'no-grant' }
  | { acted: true; result: 'renewed' | 'terminal' | 'transient' | 'unknown-kept' | 'anomaly' }

/**
 * Evaluate one profile once: reconcile the state file with the current
 * grant, and run at most one renewal attempt (including the single
 * fresh-proof escalation of ladder step 4) when it is due.
 */
export async function evaluateProfileRenewal(deps: ProfileRenewalDeps): Promise<ProfileEvaluation> {
  const now = deps.now()
  const random = deps.random ?? Math.random
  const grant = deps.bundle.trust_grant
  let state: AutoRenewalState = deps.readState() ?? { version: 1 }

  // A different CURRENT grant (manual renewal, re-authorization, replace)
  // recovers a stopped scheduler and invalidates stale bookkeeping.
  if (state.action_required !== undefined && state.action_required.grant_id !== grant.grant_id) {
    deps.log(`profile ${deps.profileId}: grant changed since action-required (${state.action_required.reason}); resuming auto-renewal`)
    state = { ...state, action_required: undefined, failure_count: 0 }
    deps.writeState(state)
  }
  if (state.inflight !== undefined && state.inflight.predecessor_grant_id !== grant.grant_id) {
    // The logical attempt targeted a grant that is no longer current; its
    // idempotent replay could only return an OLDER grant. Drop it.
    deps.log(`profile ${deps.profileId}: dropping stale in-flight renewal (grant changed underneath it)`)
    state = { ...state, inflight: undefined }
    deps.writeState(state)
  }
  if (state.action_required !== undefined) {
    return { acted: false, state: 'action-required' }
  }

  // (Re)compute the first-attempt schedule whenever the grant changed.
  if (state.inflight === undefined && (state.scheduled === undefined || state.scheduled.grant_id !== grant.grant_id)) {
    state = {
      ...state,
      scheduled: { grant_id: grant.grant_id, next_attempt_at: new Date(firstAttemptAtMs(grant, now, random)).toISOString() },
      failure_count: 0,
    }
    deps.writeState(state)
  }

  const windowOpensAt = renewalWindowOpensAtMs(grant)
  const inWindow = now >= windowOpensAt
  if (!inWindow && state.inflight === undefined) {
    return { acted: false, state: 'waiting' }
  }
  const dueAt = new Date(state.scheduled?.next_attempt_at ?? 0).getTime()
  if (now < dueAt && state.inflight === undefined) {
    return { acted: false, state: 'scheduled' }
  }
  // An unresolved in-flight attempt also honors the backoff pacing.
  if (state.inflight !== undefined && now < dueAt) {
    return { acted: false, state: 'scheduled' }
  }

  // ---- run one attempt ----
  let key: string
  let proof: DeviceProof
  let verbatim = false
  if (state.inflight !== undefined) {
    // Unknown-outcome recovery (ladder step 3): same key, same proof verbatim
    // — unless the verbatim proof was already rejected once, in which case
    // the persisted proof is already the reminted one.
    key = state.inflight.idempotency_key
    proof = state.inflight.proof
    verbatim = state.inflight.proof_reminted !== true
    state = { ...state, last_attempt_at: new Date(now).toISOString() }
    deps.writeState(state)
  } else {
    key = deps.newKey()
    proof = deps.makeProof(key)
    // Persist BEFORE the request leaves: a crash mid-flight must recover
    // with the SAME key so the Cloud replays instead of double-issuing.
    state = {
      ...state,
      inflight: { idempotency_key: key, proof, started_at: new Date(now).toISOString(), predecessor_grant_id: grant.grant_id },
      last_attempt_at: new Date(now).toISOString(),
    }
    deps.writeState(state)
  }

  const finishTransient = (reason: string, retryAfterMs?: number): ProfileEvaluation => {
    const failureCount = (state.failure_count ?? 0) + 1
    const delay = backoffDelayMs(deps, failureCount, retryAfterMs)
    // Known outcome, nothing issued (and error responses are idempotently
    // stored): the next attempt is a NEW logical renewal with a fresh key.
    state = {
      ...state,
      inflight: undefined,
      failure_count: failureCount,
      last_result: reason,
      scheduled: { grant_id: grant.grant_id, next_attempt_at: new Date(deps.now() + delay).toISOString() },
    }
    deps.writeState(state)
    deps.log(`profile ${deps.profileId}: auto-renewal attempt failed (${reason}); next attempt in ${Math.round(delay / 1000)}s`)
    return { acted: true, result: 'transient' }
  }

  const finishTerminal = (reason: string, detail?: string): ProfileEvaluation => {
    state = {
      ...state,
      inflight: undefined,
      last_result: reason,
      action_required: { reason, at: new Date(deps.now()).toISOString(), grant_id: grant.grant_id, ...(detail !== undefined ? { detail } : {}) },
    }
    deps.writeState(state)
    deps.log(`profile ${deps.profileId}: auto-renewal STOPPED — action required (${reason}). Manual fallback: happy iscp renew <renewal-id>`)
    return { acted: true, result: reason === 'proof_replay_anomaly' ? 'anomaly' : 'terminal' }
  }

  const finishSuccess = async (renewal: GrantRenewal): Promise<ProfileEvaluation> => {
    await deps.applyGrant(renewal)
    state = {
      ...state,
      inflight: undefined,
      failure_count: 0,
      last_result: 'renewed',
      last_success_at: new Date(deps.now()).toISOString(),
      // The next cycle reschedules from the NEW grant (grant_id changed).
      scheduled: undefined,
    }
    deps.writeState(state)
    deps.log(`profile ${deps.profileId}: trust grant auto-renewed (new grant ${renewal.grant.grant_id}, expires ${renewal.grant.expires_at})`)
    return { acted: true, result: 'renewed' }
  }

  try {
    return await finishSuccess(await deps.send({ idempotencyKey: key, proof }))
  } catch (error) {
    const failure = classifyRenewalFailure(error)
    switch (failure.kind) {
      case 'terminal':
        return finishTerminal(failure.reason)
      case 'transient':
        return finishTransient(failure.reason, failure.retryAfterMs)
      case 'unknown': {
        // Keep the in-flight record verbatim; pace the retry with backoff.
        const failureCount = (state.failure_count ?? 0) + 1
        const delay = backoffDelayMs(deps, failureCount)
        state = {
          ...state,
          failure_count: failureCount,
          last_result: `unknown_outcome (${failure.reason})`,
          scheduled: { grant_id: grant.grant_id, next_attempt_at: new Date(deps.now() + delay).toISOString() },
        }
        deps.writeState(state)
        deps.log(`profile ${deps.profileId}: auto-renewal outcome unknown (${failure.reason}); will retry the SAME idempotency key in ${Math.round(delay / 1000)}s`)
        return { acted: true, result: 'unknown-kept' }
      }
      case 'proof-stale': {
        if (verbatim) {
          // Ladder step 4: the idempotency layer does not know the key but
          // the verbatim proof is dead — escalate ONCE to a fresh proof for
          // the SAME key (persisted before sending).
          const freshProof = deps.makeProof(key)
          state = {
            ...state,
            inflight: { ...state.inflight!, proof: freshProof, proof_reminted: true },
          }
          deps.writeState(state)
          try {
            return await finishSuccess(await deps.send({ idempotencyKey: key, proof: freshProof }))
          } catch (secondError) {
            const second = classifyRenewalFailure(secondError)
            if (second.kind === 'terminal') return finishTerminal(second.reason)
            if (second.kind === 'transient') return finishTransient(second.reason, second.retryAfterMs)
            if (second.kind === 'unknown') {
              const failureCount = (state.failure_count ?? 0) + 1
              const delay = backoffDelayMs(deps, failureCount)
              state = {
                ...state,
                failure_count: failureCount,
                last_result: `unknown_outcome (${second.reason})`,
                scheduled: { grant_id: grant.grant_id, next_attempt_at: new Date(deps.now() + delay).toISOString() },
              }
              deps.writeState(state)
              return { acted: true, result: 'unknown-kept' }
            }
            // proof-stale AGAIN:
            if (second.reason === 'proof_replay_detected') {
              // A brand-new nonce cannot legitimately be in the replay cache —
              // contract anomaly (ladder step 5): surface, do not loop.
              return finishTerminal('proof_replay_anomaly', 'a freshly minted proof nonce was reported as replayed while the idempotency key is unknown to the server')
            }
            // device_proof_invalid for a FRESH proof: clock skew or key
            // mismatch — bounded transient backoff (fresh key next time).
            return finishTransient(second.reason)
          }
        }
        // First transmission of a fresh proof rejected: clock skew or a
        // local/Cloud key mismatch — bounded transient backoff. (A real
        // mismatch keeps surfacing in status and needs the manual §9 path.)
        return finishTransient(failure.reason)
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Status surface (read-only; used by `happy iscp status`, works daemon-down)
// ---------------------------------------------------------------------------

export type AutoRenewalDisplay =
  | { kind: 'action-required'; reason: string; at: string; detail?: string }
  | { kind: 'retrying-unknown-outcome'; startedAt: string; nextAttemptAt?: string }
  | { kind: 'scheduled'; nextAttemptAt: string }
  | { kind: 'waiting'; windowOpensAt: string }

export interface AutoRenewalStatusView {
  display: AutoRenewalDisplay
  lastResult?: string
  lastSuccessAt?: string
  lastAttemptAt?: string
}

export function autoRenewalStatusView(bundle: IscpProfileBundle, state: AutoRenewalState | null, now: number): AutoRenewalStatusView {
  const grant = bundle.trust_grant
  const common = {
    lastResult: state?.last_result,
    lastSuccessAt: state?.last_success_at,
    lastAttemptAt: state?.last_attempt_at,
  }
  if (state?.action_required !== undefined && state.action_required.grant_id === grant.grant_id) {
    const { reason, at, detail } = state.action_required
    return { display: { kind: 'action-required', reason, at, ...(detail !== undefined ? { detail } : {}) }, ...common }
  }
  if (state?.inflight !== undefined && state.inflight.predecessor_grant_id === grant.grant_id) {
    return {
      display: {
        kind: 'retrying-unknown-outcome',
        startedAt: state.inflight.started_at,
        ...(state.scheduled?.grant_id === grant.grant_id ? { nextAttemptAt: state.scheduled.next_attempt_at } : {}),
      },
      ...common,
    }
  }
  if (state?.scheduled !== undefined && state.scheduled.grant_id === grant.grant_id) {
    return { display: { kind: 'scheduled', nextAttemptAt: state.scheduled.next_attempt_at }, ...common }
  }
  const opensAt = Math.max(renewalWindowOpensAtMs(grant), 0)
  if (now >= opensAt) {
    // In-window but no scheduler state yet: the daemon will attempt on its
    // next tick — display as due now.
    return { display: { kind: 'scheduled', nextAttemptAt: new Date(now).toISOString() }, ...common }
  }
  return { display: { kind: 'waiting', windowOpensAt: new Date(opensAt).toISOString() }, ...common }
}

// ---------------------------------------------------------------------------
// Daemon wiring (real dependencies)
// ---------------------------------------------------------------------------

export interface DaemonAutoRenewalOptions {
  /** Single-flight hot reload of the ISCP peers after a successful renewal. */
  reloadPeers: () => Promise<unknown>
  log: (line: string) => void
  /** Evaluation cadence (default 60s). */
  checkIntervalMs?: number
  /** Injectable for tests. */
  provider?: CryptoProvider
  relayUrlOverride?: string
}

export interface DaemonAutoRenewalHandle {
  stop: () => void
  /** One synchronous pass over every enrolled profile (exposed for tests). */
  tick: () => Promise<void>
}

/**
 * Start the scheduler inside the daemon. Profiles are re-scanned every tick,
 * so profiles enrolled (or renewed manually) after startup are picked up
 * without a restart. Failures are contained per profile and never propagate.
 */
export function startDaemonAutoRenewal(opts: DaemonAutoRenewalOptions): DaemonAutoRenewalHandle {
  const provider = opts.provider ?? createNobleProvider()
  const intervalMs = opts.checkIntervalMs ?? 60_000
  let stopped = false

  const tick = async (): Promise<void> => {
    for (const profileId of listProfiles()) {
      if (stopped) return
      try {
        const inspection = inspectProfile(provider, profileId)
        if (inspection.state !== 'healthy') continue
        const { bundle, device } = inspection
        const enrolledRelay = verifyRelayDescriptor(provider, bundle.relay_descriptor, { now: new Date(bundle.enrolled_at) })
        const relayHttp = new RelayHttpClient({
          baseUrl: opts.relayUrlOverride ?? enrolledRelay.base_url,
          relayId: bundle.relay_id,
          provider,
        })
        await evaluateProfileRenewal({
          profileId,
          bundle,
          send: ({ idempotencyKey, proof }) => relayHttp.autoRenewGrant(device, { idempotencyKey, proof }),
          makeProof: (challenge) => createDeviceProof(provider, device, { audience: bundle.relay_id, challenge }),
          newKey: () => toBase64Url(provider.randomBytes(18)),
          applyGrant: async (renewal) => {
            await withProfileLock(profileId, async () => {
              // Re-inspect under the lock: credentials may have rotated since
              // this tick's snapshot, and only trust_grant may change here.
              const fresh = inspectProfile(provider, profileId)
              if (fresh.state !== 'healthy') {
                throw new Error(`profile ${profileId} is no longer healthy; not applying the renewed grant`)
              }
              const trustDescriptor = await resolveTrustDescriptorForVerification(provider, fresh.bundle, { log: opts.log })
              verifyAndApplyRenewedGrant(provider, {
                profileId,
                bundle: fresh.bundle,
                device: fresh.device,
                relayId: fresh.bundle.relay_id,
                trustDescriptor,
                renewal,
              })
            })
            try {
              await opts.reloadPeers()
              opts.log(`profile ${profileId}: peers hot-reloaded with the renewed grant`)
            } catch (error) {
              opts.log(`profile ${profileId}: peer hot-reload failed (${error instanceof Error ? error.message : String(error)}); the renewed grant is on disk and loads on the next reload`)
            }
          },
          readState: () => readAutoRenewalState(profileId),
          writeState: (state) => writeAutoRenewalState(profileId, state),
          now: () => Date.now(),
          log: opts.log,
        })
      } catch (error) {
        opts.log(`profile ${profileId}: auto-renewal evaluation failed (${error instanceof Error ? error.message : String(error)})`)
      }
    }
  }

  let running = false
  const timer = setInterval(() => {
    if (running || stopped) return
    running = true
    void tick().finally(() => {
      running = false
    })
  }, intervalMs)
  timer.unref?.()

  return {
    stop: () => {
      stopped = true
      clearInterval(timer)
    },
    tick,
  }
}
