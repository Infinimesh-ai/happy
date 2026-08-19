/**
 * Existing-device relay credential recovery for happy-cli — client side of
 * the frozen Infinimesh Cloud contract (InfinimeshCloud
 * docs/10-design/12-managed-provisioning.md §11; OPS 2026-08-18 rollout
 * §8/§10; upstream gap ISCP#11).
 *
 * When the refresh bearer reaches a terminal state (expired past the 24h
 * TTL, revoked chain, lost/stale local state) the profile recovers a fresh
 * access/refresh pair with a possession proof over its enrolled key plus the
 * currently valid Trust Grant. This module NEVER creates devices, consumes
 * tickets, touches device keys, or falls back to enroll/replace — recovery
 * failure surfaces as a stable state, not a new identity.
 *
 * ## Retry ladder (mirrors autoRenewal.ts against the §11.3 server order)
 *
 * One LOGICAL recovery = one Idempotency-Key + one X25519 wrap key pair +
 * one proof (challenge = key \0 wrapPublic). All three are persisted to the
 * per-profile state file BEFORE the first transmission:
 *
 * 1. Known outcome 201 → open the sealed pair with the persisted wrap
 *    private key, cross-check the metadata, atomically persist the bundle
 *    credentials WITH the full expiry facts, clear the state.
 * 2. Terminal reason (grant missing/revoked/expired, identity conflict,
 *    device revoked, feature disabled) → persist action-required, STOP.
 *    recovery_grant_expired routes to §9/§10 grant renewal FIRST — a grant
 *    change clears the stop and recovery re-runs.
 * 3. Transient (5xx, rate limits) → clear the in-flight record; the next
 *    invocation is a fresh logical recovery.
 * 4. Unknown outcome (network) → keep the record; the retry resends the
 *    SAME key + wrap key + proof verbatim and the Cloud replays the stored
 *    ciphertext-only response, which the persisted wrap private key opens.
 * 5. Verbatim proof rejected (replay-cache orphan / aged past ±5 min) →
 *    escalate ONCE to a fresh proof for the SAME key + wrap key; a second
 *    proof_replay_detected for that fresh nonce is a contract anomaly.
 */

import { randomBytes } from 'node:crypto'
import { chmodSync, existsSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

import {
  IscpError,
  RelayHttpClient,
  X25519PrivateKey,
  assertRecoveredPairMatchesMetadata,
  createDeviceProof,
  createNobleProvider,
  fromBase64Url,
  generateRecoveryWrapKey,
  openRecoveredCredentials,
  recoveryChallenge,
  toBase64Url,
  verifyRelayDescriptor,
  type CredentialRecovery,
  type CryptoProvider,
  type DeviceProof,
} from '@slopus/iscp'

import {
  inspectProfile,
  iscpProfileDir,
  withProfileLock,
  writeProfileCredentialsLocked,
  type IscpProfileBundle,
} from '@/iscp/enrollment'

// ---------------------------------------------------------------------------
// State file (per profile, next to the bundle)
// ---------------------------------------------------------------------------

export interface CredentialRecoveryInflight {
  idempotency_key: string
  /** base64url X25519 wrap private key — required to open a replayed response. */
  wrap_private: string
  wrap_public: string
  /** The exact proof sent with the first transmission (verbatim retry). */
  proof: DeviceProof
  proof_reminted?: boolean
  started_at: string
}

export interface CredentialRecoveryActionRequired {
  /** Stable server reason (recovery_grant_expired, ...) or proof_replay_anomaly. */
  reason: string
  at: string
  /** The grant that was current when recovery stopped; a different grant clears this. */
  grant_id: string
  detail?: string
}

export interface CredentialRecoveryState {
  version: 1
  inflight?: CredentialRecoveryInflight
  action_required?: CredentialRecoveryActionRequired
  last_attempt_at?: string
  last_result?: string
  last_success_at?: string
}

export function credentialRecoveryStateFile(profileId: string): string {
  return join(iscpProfileDir(profileId), 'credential-recovery.json')
}

export function readCredentialRecoveryState(profileId: string): CredentialRecoveryState | null {
  const file = credentialRecoveryStateFile(profileId)
  if (!existsSync(file)) return null
  try {
    const raw = JSON.parse(readFileSync(file, 'utf8')) as CredentialRecoveryState
    return raw !== null && typeof raw === 'object' && raw.version === 1 ? raw : null
  } catch {
    return null
  }
}

/** Atomic write (temp + rename, 0600) — the file holds the wrap PRIVATE key while an attempt is in flight. */
export function writeCredentialRecoveryState(profileId: string, state: CredentialRecoveryState): void {
  const file = credentialRecoveryStateFile(profileId)
  const tempPath = `${file}.tmp-${process.pid}-${randomBytes(6).toString('hex')}`
  writeFileSync(tempPath, JSON.stringify(state, null, 2), { mode: 0o600 })
  chmodSync(tempPath, 0o600)
  renameSync(tempPath, file)
}

// ---------------------------------------------------------------------------
// Outcome classification (stable reasons frozen in §11.3)
// ---------------------------------------------------------------------------

/**
 * Action-required outcomes: recovery STOPS (no tight retry, never a fallback
 * to enroll/replace) until the blocking fact changes — a renewed grant
 * clears grant-related stops automatically.
 */
export const TERMINAL_RECOVERY_REASONS: ReadonlySet<string> = new Set([
  'credential_recovery_disabled',
  'device_revoked',
  'recovery_identity_conflict',
  'recovery_grant_missing',
  'recovery_grant_revoked',
  'recovery_grant_expired',
])

export type RecoveryFailure =
  | { kind: 'terminal'; reason: string }
  | { kind: 'transient'; reason: string }
  | { kind: 'proof-stale'; reason: 'proof_replay_detected' | 'device_proof_invalid' }
  | { kind: 'unknown'; reason: string }

export function classifyRecoveryFailure(error: unknown): RecoveryFailure {
  if (error instanceof IscpError) {
    const reason = typeof error.details?.reason === 'string' ? error.details.reason : undefined
    if (reason !== undefined && TERMINAL_RECOVERY_REASONS.has(reason)) {
      return { kind: 'terminal', reason }
    }
    if (reason === 'proof_replay_detected' || reason === 'device_proof_invalid') {
      return { kind: 'proof-stale', reason }
    }
    const httpStatus = typeof error.details?.httpStatus === 'string' ? error.details.httpStatus : undefined
    return { kind: 'transient', reason: reason ?? `http_${httpStatus ?? 'error'}` }
  }
  return { kind: 'unknown', reason: error instanceof Error ? error.message : 'network_error' }
}

/**
 * Whether the bundle's refresh credential can no longer rotate by itself.
 * Metadata-based — a stale legacy bundle may under-report, which is why the
 * peer's terminal-401 hook exists as the authoritative runtime trigger.
 */
export function refreshCredentialTerminal(bundle: IscpProfileBundle, nowMs: number): boolean {
  const expires = new Date(bundle.refresh_credential.expires_at).getTime()
  return Number.isFinite(expires) && nowMs >= expires
}

// ---------------------------------------------------------------------------
// One recovery run (policy core — fully dependency-injected)
// ---------------------------------------------------------------------------

export interface CredentialRecoveryDeps {
  profileId: string
  bundle: IscpProfileBundle
  provider: CryptoProvider
  /** Single-shot wire call: POST recover-credentials with exactly these values. */
  send: (opts: { idempotencyKey: string; wrapPublicKey: string; proof: DeviceProof }) => Promise<CredentialRecovery>
  /** Mint a possession proof for the given challenge (= key \0 wrapPublic). */
  makeProof: (challenge: string) => DeviceProof
  newKey: () => string
  newWrapKey: () => { privateKey: X25519PrivateKey; publicKey: string }
  /** Atomically persist the opened pair + full metadata into the bundle. */
  applyCredentials: (credentials: {
    accessToken: string
    refreshToken: string
    access: { expires_at: string; issued_at: string; credential_id: string }
    refresh: { expires_at: string; issued_at: string; credential_id: string; rotation_counter?: number }
  }) => void
  readState: () => CredentialRecoveryState | null
  writeState: (state: CredentialRecoveryState) => void
  now: () => number
  log: (line: string) => void
  /** Explicit operator override: clear a persisted action-required stop and retry. */
  force?: boolean
}

export type CredentialRecoveryOutcome =
  | { result: 'recovered'; accessToken: string; refreshToken: string }
  | { result: 'action-required'; reason: string }
  | { result: 'transient'; reason: string }
  | { result: 'unknown-kept'; reason: string }

export async function runCredentialRecovery(deps: CredentialRecoveryDeps): Promise<CredentialRecoveryOutcome> {
  const now = deps.now()
  const grant = deps.bundle.trust_grant
  let state: CredentialRecoveryState = deps.readState() ?? { version: 1 }

  // A different CURRENT grant (renewal, re-authorization) clears a stop:
  // recovery_grant_expired in particular is resolved by renewing the grant.
  if (state.action_required !== undefined && (state.action_required.grant_id !== grant.grant_id || deps.force === true)) {
    deps.log(`profile ${deps.profileId}: clearing credential-recovery stop (${state.action_required.reason}) — ${deps.force === true ? 'forced' : 'grant changed'}`)
    state = { ...state, action_required: undefined }
    deps.writeState(state)
  }
  if (state.action_required !== undefined) {
    return { result: 'action-required', reason: state.action_required.reason }
  }

  let key: string
  let wrapPrivate: X25519PrivateKey
  let wrapPublic: string
  let proof: DeviceProof
  let verbatim = false
  if (state.inflight !== undefined) {
    // Unknown-outcome convergence: same key + wrap key; the proof is the
    // verbatim original unless a rejected verbatim retry already reminted it.
    key = state.inflight.idempotency_key
    wrapPrivate = new X25519PrivateKey(fromBase64Url(state.inflight.wrap_private))
    wrapPublic = state.inflight.wrap_public
    proof = state.inflight.proof
    verbatim = state.inflight.proof_reminted !== true
    state = { ...state, last_attempt_at: new Date(now).toISOString() }
    deps.writeState(state)
  } else {
    key = deps.newKey()
    const wrap = deps.newWrapKey()
    wrapPrivate = wrap.privateKey
    wrapPublic = wrap.publicKey
    proof = deps.makeProof(recoveryChallenge(key, wrapPublic))
    // Persist BEFORE the request leaves: a crash mid-flight must recover with
    // the SAME key + wrap key so the replayed ciphertext stays openable.
    state = {
      ...state,
      inflight: {
        idempotency_key: key,
        wrap_private: toBase64Url(wrapPrivate.bytes),
        wrap_public: wrapPublic,
        proof,
        started_at: new Date(now).toISOString(),
      },
      last_attempt_at: new Date(now).toISOString(),
    }
    deps.writeState(state)
  }

  const finishSuccess = (recovery: CredentialRecovery): CredentialRecoveryOutcome => {
    if (recovery.data.device_id !== deps.bundle.device_identity.device_id ||
      recovery.data.domain_id !== deps.bundle.device_identity.domain_id) {
      throw new Error('credential recovery returned a different device identity; refusing to touch the local profile')
    }
    const pair = openRecoveredCredentials(deps.provider, {
      wrapPrivateKey: wrapPrivate,
      wrapPublicKey: wrapPublic,
      wrapped: recovery.credentials_wrapped,
      domainId: deps.bundle.device_identity.domain_id,
      deviceId: deps.bundle.device_identity.device_id,
      thumbprint: deps.bundle.device_identity.public_key.kid,
    })
    assertRecoveredPairMatchesMetadata(pair, recovery)
    deps.applyCredentials({
      accessToken: pair.access.token,
      refreshToken: pair.refresh.token,
      access: { expires_at: pair.access.expires_at, issued_at: pair.access.issued_at, credential_id: pair.access.credential_id },
      refresh: {
        expires_at: pair.refresh.expires_at,
        issued_at: pair.refresh.issued_at,
        credential_id: pair.refresh.credential_id,
        ...(pair.refresh.rotation_counter !== undefined ? { rotation_counter: pair.refresh.rotation_counter } : {}),
      },
    })
    state = {
      ...state,
      inflight: undefined,
      last_result: 'recovered',
      last_success_at: new Date(deps.now()).toISOString(),
    }
    deps.writeState(state)
    deps.log(`profile ${deps.profileId}: relay credentials recovered (refresh rotation ${pair.refresh.rotation_counter ?? '?'}, expires ${pair.refresh.expires_at})`)
    return { result: 'recovered', accessToken: pair.access.token, refreshToken: pair.refresh.token }
  }

  const finishTerminal = (reason: string, detail?: string): CredentialRecoveryOutcome => {
    state = {
      ...state,
      inflight: undefined,
      last_result: reason,
      action_required: { reason, at: new Date(deps.now()).toISOString(), grant_id: grant.grant_id, ...(detail !== undefined ? { detail } : {}) },
    }
    deps.writeState(state)
    deps.log(`profile ${deps.profileId}: credential recovery STOPPED — action required (${reason}). Never re-enroll to work around this.`)
    return { result: 'action-required', reason }
  }

  const finishTransient = (reason: string): CredentialRecoveryOutcome => {
    state = { ...state, inflight: undefined, last_result: reason }
    deps.writeState(state)
    deps.log(`profile ${deps.profileId}: credential recovery attempt failed (${reason}); the next invocation starts a fresh attempt`)
    return { result: 'transient', reason }
  }

  const finishUnknown = (reason: string): CredentialRecoveryOutcome => {
    state = { ...state, last_result: `unknown_outcome (${reason})` }
    deps.writeState(state)
    deps.log(`profile ${deps.profileId}: credential recovery outcome unknown (${reason}); the next invocation retries the SAME idempotency key`)
    return { result: 'unknown-kept', reason }
  }

  // Post-send verification failures (identity mismatch, unopenable seal,
  // metadata drift) are NEVER retried as unknown-outcome: an idempotent
  // replay would return the identical bad response forever. They surface as
  // a stable action-required anomaly instead.
  const finishVerified = (recovery: CredentialRecovery): CredentialRecoveryOutcome => {
    try {
      return finishSuccess(recovery)
    } catch (error) {
      return finishTerminal('recovery_response_invalid', error instanceof Error ? error.message : String(error))
    }
  }

  try {
    return finishVerified(await deps.send({ idempotencyKey: key, wrapPublicKey: wrapPublic, proof }))
  } catch (error) {
    const failure = classifyRecoveryFailure(error)
    switch (failure.kind) {
      case 'terminal':
        return finishTerminal(failure.reason)
      case 'transient':
        return finishTransient(failure.reason)
      case 'unknown':
        return finishUnknown(failure.reason)
      case 'proof-stale': {
        if (!verbatim) {
          // A FRESH proof was rejected: clock skew or a local/Cloud key
          // mismatch — transient (a real mismatch keeps surfacing and needs
          // the identity-conflict path server-side, never a re-enroll).
          return finishTransient(failure.reason)
        }
        // Escalate ONCE to a fresh proof for the SAME key + wrap key
        // (persisted before sending) — same ladder as auto-renewal step 4.
        const freshProof = deps.makeProof(recoveryChallenge(key, wrapPublic))
        state = { ...state, inflight: { ...state.inflight!, proof: freshProof, proof_reminted: true } }
        deps.writeState(state)
        try {
          return finishVerified(await deps.send({ idempotencyKey: key, wrapPublicKey: wrapPublic, proof: freshProof }))
        } catch (secondError) {
          const second = classifyRecoveryFailure(secondError)
          if (second.kind === 'terminal') return finishTerminal(second.reason)
          if (second.kind === 'transient') return finishTransient(second.reason)
          if (second.kind === 'unknown') return finishUnknown(second.reason)
          if (second.reason === 'proof_replay_detected') {
            return finishTerminal('proof_replay_anomaly', 'a freshly minted proof nonce was reported as replayed while the idempotency key is unknown to the server')
          }
          return finishTransient(second.reason)
        }
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Real wiring (profile lock + relay client + atomic bundle write)
// ---------------------------------------------------------------------------

export interface RecoverNowOptions {
  profileId: string
  provider?: CryptoProvider
  relayUrlOverride?: string
  force?: boolean
  /**
   * Cross-process fence (OPS 2026-08-18 §10.6.2): the exact refresh bearer
   * whose terminal failure triggered this call. When the persisted bundle
   * already holds a DIFFERENT, non-terminal refresh credential, another
   * process (manual CLI, another daemon epoch) recovered or rotated in the
   * meantime — the caller ADOPTS that pair instead of issuing a second
   * logical recovery for an epoch that already ended.
   */
  staleRefreshToken?: string
  log: (line: string) => void
}

/**
 * Run one full recovery for a profile under the per-profile mutation lock:
 * inspect (healthy only — a corrupt profile is NEVER "fixed" by recovery),
 * call the Cloud, open + verify, atomically persist the bundle credentials
 * with their full expiry metadata. Throws on lock contention or a corrupt
 * profile; returns the ladder outcome otherwise.
 */
export async function recoverProfileCredentialsNow(opts: RecoverNowOptions): Promise<CredentialRecoveryOutcome> {
  const provider = opts.provider ?? createNobleProvider()
  return withProfileLock(opts.profileId, async () => {
    const inspection = inspectProfile(provider, opts.profileId)
    if (inspection.state !== 'healthy') {
      throw new Error(`ISCP profile "${opts.profileId}" is ${inspection.state === 'corrupt' ? `corrupt (${inspection.reason})` : 'not enrolled'}; credential recovery needs a healthy profile and never re-enrolls`)
    }
    const { bundle, device } = inspection
    if (opts.staleRefreshToken !== undefined &&
      bundle.refresh_credential.token !== opts.staleRefreshToken &&
      !refreshCredentialTerminal(bundle, Date.now())) {
      opts.log(`profile ${opts.profileId}: adopting a concurrent recovery/rotation — the failing refresh credential is no longer the current one`)
      return {
        result: 'recovered',
        accessToken: bundle.access_credential.token,
        refreshToken: bundle.refresh_credential.token,
      }
    }
    const enrolledRelay = verifyRelayDescriptor(provider, bundle.relay_descriptor, { now: new Date(bundle.enrolled_at) })
    const relayHttp = new RelayHttpClient({
      baseUrl: opts.relayUrlOverride ?? enrolledRelay.base_url,
      relayId: bundle.relay_id,
      provider,
    })
    return runCredentialRecovery({
      profileId: opts.profileId,
      bundle,
      provider,
      send: ({ idempotencyKey, wrapPublicKey, proof }) => relayHttp.recoverCredentials(device, { idempotencyKey, wrapPublicKey, proof }),
      makeProof: (challenge) => createDeviceProof(provider, device, { audience: bundle.relay_id, challenge }),
      newKey: () => toBase64Url(provider.randomBytes(18)),
      newWrapKey: () => generateRecoveryWrapKey(provider),
      applyCredentials: (credentials) => writeProfileCredentialsLocked(opts.profileId, credentials),
      readState: () => readCredentialRecoveryState(opts.profileId),
      writeState: (state) => writeCredentialRecoveryState(opts.profileId, state),
      now: () => Date.now(),
      log: opts.log,
      force: opts.force,
    })
  })
}
