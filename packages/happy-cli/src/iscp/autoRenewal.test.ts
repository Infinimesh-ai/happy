/**
 * Bounded auto-renewal scheduler (frozen contract: InfinimeshCloud
 * docs/10-design/12-managed-provisioning.md §10.4; OPS 2026-08-17 §8.3/§8.4):
 *
 *   - window math: min(24h, grantTTL/5) for 1h / 24h / 7d grants;
 *   - jittered first attempt inside the window, controlled clock throughout;
 *   - persist-before-send: the idempotency key survives any crash;
 *   - daemon-restart recovery: same key verbatim → idempotent replay;
 *   - burned-nonce recovery: fresh proof for the SAME key (ladder step 4);
 *   - proof_replay for a fresh nonce → surfaced anomaly, no loop;
 *   - terminal vs transient classification incl. Retry-After honoring;
 *   - expired grant + live authorization = immediate recoverable renewal;
 *   - success replaces ONLY trust_grant (generation+1, atomic) + hot reload;
 *   - no code path can ever enroll/replace/touch the device key.
 */

import { mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import {
  createDeviceProof,
  createNobleProvider,
  encodeTicketForTransport,
  iscpError,
  IscpErrorCodes,
  toBase64Url,
  type DeviceProof,
  type GrantRenewal,
  type TrustGrant,
} from '@slopus/iscp'

import { CloudFixture } from '@/iscp/testing/cloudFixture'

const homeDir = mkdtempSync(join(tmpdir(), 'happy-iscp-autorenew-'))
process.env.HAPPY_HOME_DIR = homeDir

const RELAY_ID = 'relay-cloud-test'
const TRUST_ROOT_ID = 'trust-cloud-test'
const DOMAIN_ID = 'dom_fixture'
const PHONE_DEVICE_ID = 'dev_phone_fixture'

const provider = createNobleProvider()

type AutoRenewal = typeof import('@/iscp/autoRenewal')
type Enrollment = typeof import('@/iscp/enrollment')

const HOUR = 3600_000
const DAY = 24 * HOUR

/** Minimal grant shape for the pure policy/window tests (no signature needed there). */
function fakeGrant(opts: { id?: string; notBeforeMs: number; expiresMs: number }): TrustGrant {
  return {
    grant_id: opts.id ?? 'grant_fake_1',
    not_before: new Date(opts.notBeforeMs).toISOString(),
    expires_at: new Date(opts.expiresMs).toISOString(),
    audience: PHONE_DEVICE_ID,
  } as unknown as TrustGrant
}

function cloudReason(status: number, reason: string, retryAfterSeconds?: number): Error {
  // Mirrors the SDK's parseError shape: details is a wire string map.
  return iscpError(IscpErrorCodes.AccessInvalid, `grant auto-renewal failed with status ${status}: x (${reason})`, {
    details: {
      reason,
      httpStatus: String(status),
      ...(retryAfterSeconds !== undefined ? { retryAfterSeconds: String(retryAfterSeconds) } : {}),
    },
  })
}

describe('auto-renewal scheduler', () => {
  const fixture = new CloudFixture({ relayId: RELAY_ID, trustRootId: TRUST_ROOT_ID, domainId: DOMAIN_ID, phoneDeviceId: PHONE_DEVICE_ID })
  let autoRenewal: AutoRenewal
  let enrollment: Enrollment

  beforeAll(async () => {
    await fixture.start()
    // Dynamic imports so HAPPY_HOME_DIR (temp) is set before configuration loads.
    autoRenewal = await import('@/iscp/autoRenewal')
    enrollment = await import('@/iscp/enrollment')
  })

  afterAll(async () => {
    await fixture.stop()
    rmSync(homeDir, { recursive: true, force: true })
    delete process.env.HAPPY_HOME_DIR
  })

  // -------------------------------------------------------------------------
  // Window math (controlled clock)
  // -------------------------------------------------------------------------

  describe('window math: min(24h, grantTTL/5)', () => {
    const t0 = Date.parse('2026-08-17T00:00:00Z')

    it('1h grant → 12min window', () => {
      const grant = fakeGrant({ notBeforeMs: t0, expiresMs: t0 + HOUR })
      expect(autoRenewal.renewalWindowMs(grant)).toBe(12 * 60_000)
      expect(autoRenewal.renewalWindowOpensAtMs(grant)).toBe(t0 + HOUR - 12 * 60_000)
    })

    it('24h grant → 4.8h window', () => {
      const grant = fakeGrant({ notBeforeMs: t0, expiresMs: t0 + DAY })
      expect(autoRenewal.renewalWindowMs(grant)).toBe(DAY / 5)
    })

    it('7d grant → capped at 24h', () => {
      const grant = fakeGrant({ notBeforeMs: t0, expiresMs: t0 + 7 * DAY })
      expect(autoRenewal.renewalWindowMs(grant)).toBe(DAY)
      expect(autoRenewal.renewalWindowOpensAtMs(grant)).toBe(t0 + 6 * DAY)
    })

    it('first attempt is jittered inside the window and immediate once expired', () => {
      const grant = fakeGrant({ notBeforeMs: t0, expiresMs: t0 + 7 * DAY })
      const opensAt = t0 + 6 * DAY
      // random = 0.5 → half of the jitter span (min(1h, window/10) = 1h).
      expect(autoRenewal.firstAttemptAtMs(grant, opensAt, () => 0.5)).toBe(opensAt + HOUR / 2)
      // Already deep in the window: jitter is applied from "now".
      expect(autoRenewal.firstAttemptAtMs(grant, opensAt + 5 * HOUR, () => 0)).toBe(opensAt + 5 * HOUR)
      // Expired grant with a live authorization renews IMMEDIATELY.
      const past = t0 + 7 * DAY + 60_000
      expect(autoRenewal.firstAttemptAtMs(grant, past, () => 0.99)).toBe(past)
    })
  })

  // -------------------------------------------------------------------------
  // Failure classification
  // -------------------------------------------------------------------------

  describe('classification of the frozen error reasons', () => {
    it('maps every action-required reason to terminal', () => {
      for (const reason of [
        'renewal_authorization_not_found',
        'renewal_authorization_revoked',
        'renewal_authorization_expired',
        'renewal_identity_conflict',
        'device_revoked',
        'grant_audience_not_active',
        'require_mfa',
        'auto_renewal_disabled',
      ]) {
        expect(autoRenewal.classifyRenewalFailure(cloudReason(403, reason))).toEqual({ kind: 'terminal', reason })
      }
    })

    it('maps pacing gates to transient with Retry-After honored', () => {
      expect(autoRenewal.classifyRenewalFailure(cloudReason(429, 'renewal_not_yet_eligible', 1800)))
        .toEqual({ kind: 'transient', reason: 'renewal_not_yet_eligible', retryAfterMs: 1_800_000 })
      expect(autoRenewal.classifyRenewalFailure(cloudReason(429, 'rate_limited', 60)))
        .toEqual({ kind: 'transient', reason: 'rate_limited', retryAfterMs: 60_000 })
    })

    it('maps 5xx to transient and raw network failures to unknown-outcome', () => {
      expect(autoRenewal.classifyRenewalFailure(cloudReason(503, 'upstream_unavailable')))
        .toMatchObject({ kind: 'transient', reason: 'upstream_unavailable' })
      expect(autoRenewal.classifyRenewalFailure(new TypeError('fetch failed')))
        .toEqual({ kind: 'unknown', reason: 'fetch failed' })
    })

    it('maps proof rejections to the ladder escalation', () => {
      expect(autoRenewal.classifyRenewalFailure(cloudReason(409, 'proof_replay_detected')))
        .toEqual({ kind: 'proof-stale', reason: 'proof_replay_detected' })
      expect(autoRenewal.classifyRenewalFailure(cloudReason(401, 'device_proof_invalid')))
        .toEqual({ kind: 'proof-stale', reason: 'device_proof_invalid' })
    })
  })

  // -------------------------------------------------------------------------
  // Policy core (in-memory deps, controlled clock)
  // -------------------------------------------------------------------------

  describe('evaluateProfileRenewal policy', () => {
    const t0 = Date.parse('2026-08-17T00:00:00Z')

    interface Harness {
      deps: import('@/iscp/autoRenewal').ProfileRenewalDeps
      state: () => import('@/iscp/autoRenewal').AutoRenewalState | null
      setNow: (ms: number) => void
      sends: Array<{ idempotencyKey: string; proof: DeviceProof }>
      applied: GrantRenewal[]
      setGrant: (grant: TrustGrant) => void
    }

    function harness(opts: {
      grant: TrustGrant
      send?: (call: { idempotencyKey: string; proof: DeviceProof }) => Promise<GrantRenewal>
    }): Harness {
      let stored: import('@/iscp/autoRenewal').AutoRenewalState | null = null
      let now = t0
      let keyCounter = 0
      const sends: Harness['sends'] = []
      const applied: GrantRenewal[] = []
      const bundle = { trust_grant: opts.grant } as import('@/iscp/enrollment').IscpProfileBundle
      const deps: import('@/iscp/autoRenewal').ProfileRenewalDeps = {
        profileId: 'policy-test',
        bundle,
        send: async (call) => {
          sends.push(call)
          if (opts.send) return await opts.send(call)
          return {
            data: { device_id: 'dev_1', domain_id: DOMAIN_ID },
            grant: fakeGrant({ id: `grant_renewed_${sends.length}`, notBeforeMs: now, expiresMs: now + 7 * DAY }),
          } as GrantRenewal
        },
        makeProof: (challenge) => ({ nonce: `nonce_${challenge}_${sends.length}_${Math.random()}`, challenge } as unknown as DeviceProof),
        newKey: () => `key_${++keyCounter}`,
        applyGrant: async (renewal) => {
          applied.push(renewal)
        },
        readState: () => stored,
        writeState: (s) => {
          stored = s
        },
        now: () => now,
        random: () => 0.5,
        log: () => {},
      }
      return {
        deps,
        state: () => stored,
        setNow: (ms) => {
          now = ms
        },
        sends,
        applied,
        setGrant: (grant) => {
          bundle.trust_grant = grant
        },
      }
    }

    it('waits outside the window, schedules a jittered first attempt inside it, then renews', async () => {
      const grant = fakeGrant({ notBeforeMs: t0, expiresMs: t0 + 7 * DAY })
      const h = harness({ grant })

      expect(await autoRenewal.evaluateProfileRenewal(h.deps)).toEqual({ acted: false, state: 'waiting' })
      expect(h.sends).toHaveLength(0)

      // Window opens at t0+6d; jitter (random 0.5, span 1h) → due +30min.
      h.setNow(t0 + 6 * DAY)
      expect(await autoRenewal.evaluateProfileRenewal(h.deps)).toEqual({ acted: false, state: 'scheduled' })
      expect(h.state()?.scheduled?.next_attempt_at).toBe(new Date(t0 + 6 * DAY + HOUR / 2).toISOString())
      expect(h.sends).toHaveLength(0)

      h.setNow(t0 + 6 * DAY + HOUR / 2)
      expect(await autoRenewal.evaluateProfileRenewal(h.deps)).toEqual({ acted: true, result: 'renewed' })
      expect(h.sends).toHaveLength(1)
      expect(h.applied).toHaveLength(1)
      const state = h.state()!
      expect(state.inflight).toBeUndefined()
      expect(state.last_result).toBe('renewed')
      expect(state.scheduled).toBeUndefined()

      // With the NEW grant in the bundle, the cycle restarts as waiting.
      h.setGrant(fakeGrant({ id: 'grant_renewed_1', notBeforeMs: t0 + 6 * DAY, expiresMs: t0 + 13 * DAY }))
      expect(await autoRenewal.evaluateProfileRenewal(h.deps)).toEqual({ acted: false, state: 'waiting' })
    })

    it('persists the idempotency key + proof BEFORE the request leaves', async () => {
      const grant = fakeGrant({ notBeforeMs: t0 - 7 * DAY, expiresMs: t0 - 1 })
      let observedAtSendTime: import('@/iscp/autoRenewal').AutoRenewalInflight | undefined
      const h = harness({
        grant,
        send: async (call) => {
          observedAtSendTime = h.state()?.inflight
          return {
            data: { device_id: 'dev_1', domain_id: DOMAIN_ID },
            grant: fakeGrant({ id: 'g2', notBeforeMs: t0, expiresMs: t0 + 7 * DAY }),
          } as GrantRenewal
        },
      })
      await autoRenewal.evaluateProfileRenewal(h.deps)
      expect(observedAtSendTime).toBeDefined()
      expect(observedAtSendTime!.idempotency_key).toBe(h.sends[0]!.idempotencyKey)
      expect(observedAtSendTime!.proof).toEqual(h.sends[0]!.proof)
      expect(observedAtSendTime!.predecessor_grant_id).toBe(grant.grant_id)
    })

    it('an expired grant with a live authorization renews immediately (recoverable, no re-enroll)', async () => {
      const grant = fakeGrant({ notBeforeMs: t0 - 7 * DAY, expiresMs: t0 - HOUR })
      const h = harness({ grant })
      expect(await autoRenewal.evaluateProfileRenewal(h.deps)).toEqual({ acted: true, result: 'renewed' })
      expect(h.sends).toHaveLength(1)
    })

    it('terminal reasons persist action-required and stop all further attempts', async () => {
      const grant = fakeGrant({ notBeforeMs: t0 - 7 * DAY, expiresMs: t0 - 1 })
      const h = harness({
        grant,
        send: async () => {
          throw cloudReason(410, 'renewal_authorization_expired')
        },
      })
      expect(await autoRenewal.evaluateProfileRenewal(h.deps)).toEqual({ acted: true, result: 'terminal' })
      const state = h.state()!
      expect(state.action_required).toMatchObject({ reason: 'renewal_authorization_expired', grant_id: grant.grant_id })
      expect(state.inflight).toBeUndefined()

      // Hours later: still stopped, zero additional wire calls.
      h.setNow(t0 + 12 * HOUR)
      expect(await autoRenewal.evaluateProfileRenewal(h.deps)).toEqual({ acted: false, state: 'action-required' })
      expect(h.sends).toHaveLength(1)
    })

    it('a NEW current grant (manual renew / re-authorization) clears action-required', async () => {
      const grant = fakeGrant({ notBeforeMs: t0 - 7 * DAY, expiresMs: t0 - 1 })
      const h = harness({
        grant,
        send: async () => {
          throw cloudReason(403, 'require_mfa')
        },
      })
      await autoRenewal.evaluateProfileRenewal(h.deps)
      expect(h.state()?.action_required?.reason).toBe('require_mfa')

      h.setGrant(fakeGrant({ id: 'grant_manual', notBeforeMs: t0, expiresMs: t0 + 7 * DAY }))
      expect(await autoRenewal.evaluateProfileRenewal(h.deps)).toEqual({ acted: false, state: 'waiting' })
      expect(h.state()?.action_required).toBeUndefined()
    })

    it('transient failures back off with Retry-After as the floor and rotate to a fresh key', async () => {
      const grant = fakeGrant({ notBeforeMs: t0 - 7 * DAY, expiresMs: t0 - 1 })
      let failures = 0
      const h = harness({
        grant,
        send: async () => {
          failures += 1
          if (failures === 1) throw cloudReason(429, 'rate_limited', 1800)
          return {
            data: { device_id: 'dev_1', domain_id: DOMAIN_ID },
            grant: fakeGrant({ id: 'g2', notBeforeMs: t0, expiresMs: t0 + 7 * DAY }),
          } as GrantRenewal
        },
      })
      expect(await autoRenewal.evaluateProfileRenewal(h.deps)).toEqual({ acted: true, result: 'transient' })
      const afterFailure = h.state()!
      expect(afterFailure.inflight).toBeUndefined()
      expect(afterFailure.last_result).toBe('rate_limited')
      const nextAt = Date.parse(afterFailure.scheduled!.next_attempt_at)
      // Retry-After (30min) is the floor; jitter never undercuts it.
      expect(nextAt).toBeGreaterThanOrEqual(t0 + 1_800_000)

      // Not due yet → no wire call.
      h.setNow(nextAt - 1)
      expect(await autoRenewal.evaluateProfileRenewal(h.deps)).toEqual({ acted: false, state: 'scheduled' })
      expect(h.sends).toHaveLength(1)

      h.setNow(nextAt)
      expect(await autoRenewal.evaluateProfileRenewal(h.deps)).toEqual({ acted: true, result: 'renewed' })
      // A new LOGICAL renewal after a known failure = a fresh key.
      expect(h.sends[1]!.idempotencyKey).not.toBe(h.sends[0]!.idempotencyKey)
    })

    it('unknown outcome keeps the in-flight key and retries it VERBATIM after backoff', async () => {
      const grant = fakeGrant({ notBeforeMs: t0 - 7 * DAY, expiresMs: t0 - 1 })
      let calls = 0
      const h = harness({
        grant,
        send: async () => {
          calls += 1
          if (calls === 1) throw new TypeError('fetch failed')
          return {
            data: { device_id: 'dev_1', domain_id: DOMAIN_ID },
            grant: fakeGrant({ id: 'g2', notBeforeMs: t0, expiresMs: t0 + 7 * DAY }),
          } as GrantRenewal
        },
      })
      expect(await autoRenewal.evaluateProfileRenewal(h.deps)).toEqual({ acted: true, result: 'unknown-kept' })
      const inflight = h.state()!.inflight!
      expect(inflight.idempotency_key).toBe(h.sends[0]!.idempotencyKey)

      h.setNow(Date.parse(h.state()!.scheduled!.next_attempt_at))
      expect(await autoRenewal.evaluateProfileRenewal(h.deps)).toEqual({ acted: true, result: 'renewed' })
      // Same key AND byte-identical proof: the server can replay the stored
      // response without re-verifying the (stale) proof.
      expect(h.sends[1]!.idempotencyKey).toBe(h.sends[0]!.idempotencyKey)
      expect(h.sends[1]!.proof).toEqual(h.sends[0]!.proof)
    })

    it('ladder step 4: burned verbatim proof escalates ONCE to a fresh proof for the SAME key', async () => {
      const grant = fakeGrant({ notBeforeMs: t0 - 7 * DAY, expiresMs: t0 - 1 })
      let calls = 0
      const h = harness({
        grant,
        send: async () => {
          calls += 1
          if (calls === 1) throw new TypeError('fetch failed')          // unknown → keep key
          if (calls === 2) throw cloudReason(409, 'proof_replay_detected') // verbatim rejected
          return {
            data: { device_id: 'dev_1', domain_id: DOMAIN_ID },
            grant: fakeGrant({ id: 'g2', notBeforeMs: t0, expiresMs: t0 + 7 * DAY }),
          } as GrantRenewal
        },
      })
      await autoRenewal.evaluateProfileRenewal(h.deps)
      h.setNow(Date.parse(h.state()!.scheduled!.next_attempt_at))
      expect(await autoRenewal.evaluateProfileRenewal(h.deps)).toEqual({ acted: true, result: 'renewed' })
      expect(h.sends).toHaveLength(3)
      // All three transmissions carried the SAME logical key…
      expect(new Set(h.sends.map((s) => s.idempotencyKey)).size).toBe(1)
      // …but the escalation minted a fresh proof (new nonce), same challenge.
      expect(h.sends[2]!.proof).not.toEqual(h.sends[1]!.proof)
    })

    it('ladder step 5: proof_replay for a FRESH nonce is surfaced as an anomaly, never looped', async () => {
      const grant = fakeGrant({ notBeforeMs: t0 - 7 * DAY, expiresMs: t0 - 1 })
      let calls = 0
      const h = harness({
        grant,
        send: async () => {
          calls += 1
          if (calls === 1) throw new TypeError('fetch failed')
          throw cloudReason(409, 'proof_replay_detected')
        },
      })
      await autoRenewal.evaluateProfileRenewal(h.deps)
      h.setNow(Date.parse(h.state()!.scheduled!.next_attempt_at))
      expect(await autoRenewal.evaluateProfileRenewal(h.deps)).toEqual({ acted: true, result: 'anomaly' })
      expect(h.state()!.action_required?.reason).toBe('proof_replay_anomaly')
      expect(h.sends).toHaveLength(3)
    })

    it('device_proof_invalid on a FRESH first proof is a bounded transient failure', async () => {
      const grant = fakeGrant({ notBeforeMs: t0 - 7 * DAY, expiresMs: t0 - 1 })
      const h = harness({
        grant,
        send: async () => {
          throw cloudReason(401, 'device_proof_invalid')
        },
      })
      expect(await autoRenewal.evaluateProfileRenewal(h.deps)).toEqual({ acted: true, result: 'transient' })
      expect(h.state()!.action_required).toBeUndefined()
      expect(h.state()!.last_result).toBe('device_proof_invalid')
    })

    it('drops a stale in-flight attempt when the grant changed underneath it', async () => {
      const grant = fakeGrant({ notBeforeMs: t0 - 7 * DAY, expiresMs: t0 - 1 })
      let calls = 0
      const h = harness({
        grant,
        send: async () => {
          calls += 1
          if (calls === 1) throw new TypeError('fetch failed')
          return {
            data: { device_id: 'dev_1', domain_id: DOMAIN_ID },
            grant: fakeGrant({ id: 'g3', notBeforeMs: t0, expiresMs: t0 + 7 * DAY }),
          } as GrantRenewal
        },
      })
      await autoRenewal.evaluateProfileRenewal(h.deps)
      expect(h.state()!.inflight).toBeDefined()
      // Manual renewal landed a new grant while the attempt was unresolved.
      h.setGrant(fakeGrant({ id: 'grant_manual', notBeforeMs: t0, expiresMs: t0 + 7 * DAY }))
      expect(await autoRenewal.evaluateProfileRenewal(h.deps)).toEqual({ acted: false, state: 'waiting' })
      expect(h.state()!.inflight).toBeUndefined()
    })
  })

  // -------------------------------------------------------------------------
  // State file + status view
  // -------------------------------------------------------------------------

  describe('state file + status view', () => {
    it('round-trips atomically with 0600 and tolerates a torn file', () => {
      const state: import('@/iscp/autoRenewal').AutoRenewalState = { version: 1, last_result: 'renewed' }
      // The profile dir must exist (state lives next to the bundle).
      const dir = enrollment.iscpProfileDir('statefile-test')
      rmSync(dir, { recursive: true, force: true })
      expect(autoRenewal.readAutoRenewalState('statefile-test')).toBeNull()
      mkdirSync(dir, { recursive: true })
      autoRenewal.writeAutoRenewalState('statefile-test', state)
      expect(autoRenewal.readAutoRenewalState('statefile-test')).toEqual(state)
      expect(statSync(autoRenewal.autoRenewalStateFile('statefile-test')).mode & 0o777).toBe(0o600)
      writeFileSync(autoRenewal.autoRenewalStateFile('statefile-test'), '{"version":1,"last_re')
      expect(autoRenewal.readAutoRenewalState('statefile-test')).toBeNull()
      rmSync(dir, { recursive: true, force: true })
    })

    it('renders the distinct auto-renewal layer states', () => {
      const t0 = Date.parse('2026-08-17T00:00:00Z')
      const grant = fakeGrant({ id: 'g1', notBeforeMs: t0, expiresMs: t0 + 7 * DAY })
      const bundle = { trust_grant: grant } as import('@/iscp/enrollment').IscpProfileBundle

      expect(autoRenewal.autoRenewalStatusView(bundle, null, t0).display)
        .toEqual({ kind: 'waiting', windowOpensAt: new Date(t0 + 6 * DAY).toISOString() })

      expect(autoRenewal.autoRenewalStatusView(bundle, {
        version: 1,
        scheduled: { grant_id: 'g1', next_attempt_at: new Date(t0 + 6 * DAY + HOUR).toISOString() },
      }, t0).display).toEqual({ kind: 'scheduled', nextAttemptAt: new Date(t0 + 6 * DAY + HOUR).toISOString() })

      expect(autoRenewal.autoRenewalStatusView(bundle, {
        version: 1,
        inflight: { idempotency_key: 'k', proof: {} as DeviceProof, started_at: new Date(t0).toISOString(), predecessor_grant_id: 'g1' },
      }, t0).display).toMatchObject({ kind: 'retrying-unknown-outcome' })

      expect(autoRenewal.autoRenewalStatusView(bundle, {
        version: 1,
        action_required: { reason: 'require_mfa', at: new Date(t0).toISOString(), grant_id: 'g1' },
      }, t0).display).toMatchObject({ kind: 'action-required', reason: 'require_mfa' })

      // Action-required recorded for a PREVIOUS grant does not stick to a new one.
      expect(autoRenewal.autoRenewalStatusView(bundle, {
        version: 1,
        action_required: { reason: 'require_mfa', at: new Date(t0).toISOString(), grant_id: 'g_old' },
      }, t0).display.kind).toBe('waiting')

      // In-window with no scheduler state yet → effectively due now.
      expect(autoRenewal.autoRenewalStatusView(bundle, null, t0 + 6 * DAY + 1).display.kind).toBe('scheduled')
    })
  })

  // -------------------------------------------------------------------------
  // Integration: real profile on disk + CloudFixture + real daemon wiring
  // -------------------------------------------------------------------------

  describe('daemon wiring against the Cloud fixture', () => {
    async function enrollProfile(profileId: string): Promise<void> {
      await enrollment.enroll({
        relayUrl: fixture.baseUrl,
        trustUrl: fixture.baseUrl,
        relayId: RELAY_ID,
        trustRootId: TRUST_ROOT_ID,
        ticket: encodeTicketForTransport(fixture.issueTicket()),
        profileId,
        log: () => {},
      })
    }

    /** Force the on-disk grant to be expired so the next tick renews immediately. */
    function expireGrantOnDisk(profileId: string): void {
      const file = join(enrollment.iscpProfileDir(profileId), 'bundle.json')
      const bundle = JSON.parse(readFileSync(file, 'utf8')) as { trust_grant: { not_before: string; expires_at: string } }
      bundle.trust_grant.not_before = new Date(Date.now() - 7 * DAY).toISOString()
      bundle.trust_grant.expires_at = new Date(Date.now() - 60_000).toISOString()
      writeFileSync(file, JSON.stringify(bundle, null, 2))
    }

    function handle(reloads: unknown[]): import('@/iscp/autoRenewal').DaemonAutoRenewalHandle {
      return autoRenewal.startDaemonAutoRenewal({
        reloadPeers: async () => {
          reloads.push(1)
        },
        log: () => {},
        checkIntervalMs: 3600_000, // driven manually via tick()
      })
    }

    it('renews an expired grant end-to-end: generation+1, only trust_grant changes, peers hot-reloaded', async () => {
      fixture.autoRenewal = { enabled: true, authorization: 'active' }
      await enrollProfile('itg-success')
      const before = JSON.parse(readFileSync(join(enrollment.iscpProfileDir('itg-success'), 'bundle.json'), 'utf8')) as Record<string, unknown>
      const keyBefore = readFileSync(join(enrollment.iscpProfileDir('itg-success'), 'device.key'))
      expireGrantOnDisk('itg-success')

      const reloads: unknown[] = []
      const scheduler = handle(reloads)
      try {
        const registerCallsBefore = fixture.registerCalls
        await scheduler.tick()
        expect(fixture.registerCalls).toBe(registerCallsBefore) // NEVER enrolls
        const after = JSON.parse(readFileSync(join(enrollment.iscpProfileDir('itg-success'), 'bundle.json'), 'utf8')) as Record<string, unknown>
        expect((after.generation as number)).toBe((before.generation as number) + 1)
        expect((after.trust_grant as { grant_id: string }).grant_id).not.toBe((before.trust_grant as { grant_id: string }).grant_id)
        // Identity, credentials and the device key are untouched.
        expect(after.device_identity).toEqual(before.device_identity)
        expect(after.access_credential).toEqual(before.access_credential)
        expect(after.refresh_credential).toEqual(before.refresh_credential)
        expect(readFileSync(join(enrollment.iscpProfileDir('itg-success'), 'device.key')).equals(keyBefore)).toBe(true)
        expect(reloads).toHaveLength(1)
        const state = autoRenewal.readAutoRenewalState('itg-success')!
        expect(state.last_result).toBe('renewed')
        expect(state.inflight).toBeUndefined()
      } finally {
        scheduler.stop()
        rmSync(enrollment.iscpProfileDir('itg-success'), { recursive: true, force: true })
      }
    })

    it('daemon restart after a server-side commit: the SAME persisted key replays the stored 201', async () => {
      fixture.autoRenewal = { enabled: true, authorization: 'active' }
      await enrollProfile('itg-replay')
      expireGrantOnDisk('itg-replay')
      const inspection = enrollment.inspectProfile(provider, 'itg-replay')
      if (inspection.state !== 'healthy') throw new Error('setup failed')

      // First transmission "crashed after the server committed": drive the
      // real wire call directly, then persist the in-flight record WITHOUT
      // applying the response — exactly what a crash right after fetch does.
      const { RelayHttpClient } = await import('@slopus/iscp')
      const relay = new RelayHttpClient({ baseUrl: fixture.baseUrl, relayId: RELAY_ID, provider })
      const key = toBase64Url(provider.randomBytes(18))
      const proof = createDeviceProof(provider, inspection.device, { audience: RELAY_ID, challenge: key })
      const committed = await relay.autoRenewGrant(inspection.device, { idempotencyKey: key, proof })
      autoRenewal.writeAutoRenewalState('itg-replay', {
        version: 1,
        inflight: {
          idempotency_key: key,
          proof,
          started_at: new Date().toISOString(),
          predecessor_grant_id: inspection.bundle.trust_grant.grant_id,
        },
      })

      const callsBefore = fixture.autoRenewCalls
      const reloads: unknown[] = []
      const scheduler = handle(reloads)
      try {
        await scheduler.tick() // the "restarted daemon"
        // The stale proof was replayed VERBATIM under the same key and the
        // fixture answered from the idempotency store (no re-execution).
        expect(fixture.autoRenewCalls).toBe(callsBefore) // replay short-circuits before the handler
        expect(fixture.lastAutoRenewKey).toBe(key)
        const after = JSON.parse(readFileSync(join(enrollment.iscpProfileDir('itg-replay'), 'bundle.json'), 'utf8')) as { trust_grant: { grant_id: string } }
        expect(after.trust_grant.grant_id).toBe(committed.grant.grant_id)
        expect(autoRenewal.readAutoRenewalState('itg-replay')!.inflight).toBeUndefined()
        expect(reloads).toHaveLength(1)
      } finally {
        scheduler.stop()
        rmSync(enrollment.iscpProfileDir('itg-replay'), { recursive: true, force: true })
      }
    })

    it('burned nonce without a stored response: fresh proof for the SAME key completes the renewal', async () => {
      fixture.autoRenewal = { enabled: true, authorization: 'active' }
      await enrollProfile('itg-burned')
      expireGrantOnDisk('itg-burned')
      const inspection = enrollment.inspectProfile(provider, 'itg-burned')
      if (inspection.state !== 'healthy') throw new Error('setup failed')

      // The first transmission reached the server far enough to burn the
      // nonce, but no idempotent response was stored (server-side crash).
      const key = toBase64Url(provider.randomBytes(18))
      const proof = createDeviceProof(provider, inspection.device, { audience: RELAY_ID, challenge: key })
      fixture.burnNonce(proof.nonce)
      autoRenewal.writeAutoRenewalState('itg-burned', {
        version: 1,
        inflight: {
          idempotency_key: key,
          proof,
          started_at: new Date().toISOString(),
          predecessor_grant_id: inspection.bundle.trust_grant.grant_id,
        },
      })

      const callsBefore = fixture.autoRenewCalls
      const scheduler = handle([])
      try {
        await scheduler.tick()
        // The ladder ran within one tick: the verbatim attempt hit
        // proof_replay_detected (an early rejection, NOT idempotently
        // stored), then the fresh-proof escalation for the SAME key landed.
        expect(fixture.autoRenewCalls).toBe(callsBefore + 2)
        expect(fixture.lastAutoRenewKey).toBe(key)
        const state = autoRenewal.readAutoRenewalState('itg-burned')!
        expect(state.last_result).toBe('renewed')
      } finally {
        scheduler.stop()
        rmSync(enrollment.iscpProfileDir('itg-burned'), { recursive: true, force: true })
      }
    })

    it('terminal server answers stop the scheduler with a persisted action-required state', async () => {
      fixture.autoRenewal = { enabled: true, authorization: 'expired' }
      await enrollProfile('itg-terminal')
      expireGrantOnDisk('itg-terminal')
      const scheduler = handle([])
      try {
        await scheduler.tick()
        const state = autoRenewal.readAutoRenewalState('itg-terminal')!
        expect(state.action_required).toMatchObject({ reason: 'renewal_authorization_expired' })
        const callsAfterFirst = fixture.autoRenewCalls
        await scheduler.tick()
        expect(fixture.autoRenewCalls).toBe(callsAfterFirst) // stopped, no tight retry
        // The grant was NOT touched and nothing re-enrolled.
        const bundle = JSON.parse(readFileSync(join(enrollment.iscpProfileDir('itg-terminal'), 'bundle.json'), 'utf8')) as { generation?: number }
        expect(bundle.generation).toBe(1)
      } finally {
        scheduler.stop()
        rmSync(enrollment.iscpProfileDir('itg-terminal'), { recursive: true, force: true })
        fixture.autoRenewal = { enabled: true, authorization: 'active' }
      }
    })
  })

  // -------------------------------------------------------------------------
  // Guard: the scheduler can never enroll/replace or touch key material
  // -------------------------------------------------------------------------

  it('has no code path into enrollment, replacement, or key handling', () => {
    const source = readFileSync(fileURLToPath(new URL('./autoRenewal.ts', import.meta.url)), 'utf8')
    expect(source).not.toMatch(/\benroll\s*\(/)
    expect(source).not.toMatch(/registerWithSignedTicket|registerWithTicket|bindSelf/)
    expect(source).not.toMatch(/persistProfile|writeProfileFiles|device\.key/)
    expect(source).not.toMatch(/--replace|replace:\s*true/)
    // The only mutation entry point is the shared verify+apply step.
    expect(source).toContain('verifyAndApplyRenewedGrant')
  })
})
