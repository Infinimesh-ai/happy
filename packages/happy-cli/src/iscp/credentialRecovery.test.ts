/**
 * Existing-device relay credential recovery (frozen contract: InfinimeshCloud
 * docs/10-design/12-managed-provisioning.md §11; OPS 2026-08-18 §8/§10):
 *
 *   - persist-before-send: key + wrap PRIVATE key + proof survive any crash;
 *   - unknown-outcome retry: same key + wrap key + proof verbatim, and the
 *     replayed ciphertext-only response still opens;
 *   - burned-nonce recovery: fresh proof for the SAME key + wrap key;
 *   - terminal reasons stop recovery (action-required) and a grant change
 *     (renewal) clears the stop — recovery_grant_expired routes to renewal
 *     FIRST, the order never flips;
 *   - success atomically persists tokens WITH the full expiry metadata;
 *   - end-to-end against the CloudFixture: recover → open → old state
 *     cleared → idempotent replay path;
 *   - no code path can ever enroll/replace/touch the device key.
 */

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import {
  CREDENTIAL_RECOVERY_WRAPPED_TYPE,
  X25519PublicKey,
  createNobleProvider,
  encodeTicketForTransport,
  fromBase64Url,
  iscpError,
  IscpErrorCodes,
  toBase64Url,
  utf8Encode,
  type CredentialRecovery,
  type DeviceProof,
} from '@slopus/iscp'

import { CloudFixture } from '@/iscp/testing/cloudFixture'

const homeDir = mkdtempSync(join(tmpdir(), 'happy-iscp-recover-'))
process.env.HAPPY_HOME_DIR = homeDir

const RELAY_ID = 'relay-cloud-test'
const TRUST_ROOT_ID = 'trust-cloud-test'
const DOMAIN_ID = 'dom_fixture'
const PHONE_DEVICE_ID = 'dev_phone_fixture'

const provider = createNobleProvider()

type Recovery = typeof import('@/iscp/credentialRecovery')
type Enrollment = typeof import('@/iscp/enrollment')

function cloudReason(status: number, reason: string): Error {
  return iscpError(IscpErrorCodes.AccessInvalid, `credential recovery failed with status ${status}: x (${reason})`, {
    details: { reason, httpStatus: String(status) },
  })
}

/** Mirror of the Cloud §11.4 sealer for the policy-core harness. */
function sealFor(wrapPublicKey: string, identity: { domainId: string; deviceId: string; thumbprint: string }, rotation: number): CredentialRecovery {
  const now = new Date()
  const pair = {
    access: {
      credential_id: `cred_a_${rotation}`, token: `rac_${rotation}`,
      domain_id: identity.domainId, device_id: identity.deviceId,
      issued_at: now.toISOString(), expires_at: new Date(now.getTime() + 900_000).toISOString(),
    },
    refresh: {
      credential_id: `cred_r_${rotation}`, token: `rrc_${rotation}`,
      domain_id: identity.domainId, device_id: identity.deviceId,
      issued_at: now.toISOString(), expires_at: new Date(now.getTime() + 86_400_000).toISOString(),
      rotation_counter: rotation,
    },
  }
  const clientPub = new X25519PublicKey(fromBase64Url(wrapPublicKey))
  const server = provider.generateSessionKeyPair()
  const secret = provider.sharedSecret(server.privateKey, clientPub)
  const transcript = utf8Encode(`iscp/v2/relay/credential-recovery\0${identity.domainId}\0${identity.deviceId}\0${identity.thumbprint}`)
  const info = new Uint8Array(transcript.length + 64)
  info.set(transcript, 0)
  info.set(clientPub.bytes, transcript.length)
  info.set(server.publicKey.bytes, transcript.length + 32)
  const key = provider.hkdfSha256(secret, new Uint8Array(0), info, 32)
  const nonce = provider.randomBytes(12)
  const strip = ({ token: _token, ...rest }: { token: string } & Record<string, unknown>) => rest
  return {
    data: { device_id: identity.deviceId, domain_id: identity.domainId },
    access: strip(pair.access),
    refresh: strip(pair.refresh),
    credentials_wrapped: {
      type: CREDENTIAL_RECOVERY_WRAPPED_TYPE,
      ciphersuite: 'ISCP_V2_X25519_HKDF_SHA256_CHACHA20POLY1305',
      recovery_public_key: wrapPublicKey,
      server_public_key: toBase64Url(server.publicKey.bytes),
      nonce: toBase64Url(nonce),
      ciphertext: toBase64Url(provider.seal(key, nonce, utf8Encode(JSON.stringify(pair)), transcript)),
    },
  } as CredentialRecovery
}

describe('credential recovery', () => {
  const fixture = new CloudFixture({ relayId: RELAY_ID, trustRootId: TRUST_ROOT_ID, domainId: DOMAIN_ID, phoneDeviceId: PHONE_DEVICE_ID })
  let recovery: Recovery
  let enrollment: Enrollment

  beforeAll(async () => {
    await fixture.start()
    // Dynamic imports so HAPPY_HOME_DIR (temp) is set before configuration loads.
    recovery = await import('@/iscp/credentialRecovery')
    enrollment = await import('@/iscp/enrollment')
  })

  afterAll(async () => {
    await fixture.stop()
    rmSync(homeDir, { recursive: true, force: true })
    delete process.env.HAPPY_HOME_DIR
  })

  describe('classification of the frozen §11 error reasons', () => {
    it('maps every action-required reason to terminal', () => {
      for (const reason of [
        'credential_recovery_disabled',
        'device_revoked',
        'recovery_identity_conflict',
        'recovery_grant_missing',
        'recovery_grant_revoked',
        'recovery_grant_expired',
      ]) {
        expect(recovery.classifyRecoveryFailure(cloudReason(403, reason))).toEqual({ kind: 'terminal', reason })
      }
    })
    it('maps proof rejections to the ladder escalation and the rest to transient/unknown', () => {
      expect(recovery.classifyRecoveryFailure(cloudReason(409, 'proof_replay_detected')))
        .toEqual({ kind: 'proof-stale', reason: 'proof_replay_detected' })
      expect(recovery.classifyRecoveryFailure(cloudReason(401, 'device_proof_invalid')))
        .toEqual({ kind: 'proof-stale', reason: 'device_proof_invalid' })
      expect(recovery.classifyRecoveryFailure(cloudReason(500, 'internal_error')))
        .toMatchObject({ kind: 'transient', reason: 'internal_error' })
      expect(recovery.classifyRecoveryFailure(new TypeError('fetch failed')))
        .toEqual({ kind: 'unknown', reason: 'fetch failed' })
    })
  })

  it('refreshCredentialTerminal reads the bundle metadata', () => {
    const bundle = (expiresAt: string) => ({
      refresh_credential: { token: 't', expires_at: expiresAt },
    }) as import('@/iscp/enrollment').IscpProfileBundle
    const now = Date.parse('2026-08-19T00:00:00Z')
    expect(recovery.refreshCredentialTerminal(bundle('2026-08-18T00:00:00Z'), now)).toBe(true)
    expect(recovery.refreshCredentialTerminal(bundle('2026-08-20T00:00:00Z'), now)).toBe(false)
    expect(recovery.refreshCredentialTerminal(bundle('not-a-date'), now)).toBe(false)
  })

  // -------------------------------------------------------------------------
  // Policy core (in-memory deps, real crypto)
  // -------------------------------------------------------------------------

  describe('runCredentialRecovery policy', () => {
    const t0 = Date.parse('2026-08-19T00:00:00Z')

    interface Harness {
      deps: import('@/iscp/credentialRecovery').CredentialRecoveryDeps
      state: () => import('@/iscp/credentialRecovery').CredentialRecoveryState | null
      sends: Array<{ idempotencyKey: string; wrapPublicKey: string; proof: DeviceProof }>
      applied: Array<Parameters<import('@/iscp/credentialRecovery').CredentialRecoveryDeps['applyCredentials']>[0]>
      setGrantId: (id: string) => void
      setForce: (force: boolean) => void
    }

    function harness(opts?: {
      send?: (call: { idempotencyKey: string; wrapPublicKey: string; proof: DeviceProof }) => Promise<CredentialRecovery>
    }): Harness {
      let stored: import('@/iscp/credentialRecovery').CredentialRecoveryState | null = null
      let keyCounter = 0
      let rotation = 2
      const sends: Harness['sends'] = []
      const applied: Harness['applied'] = []
      const identity = { domainId: DOMAIN_ID, deviceId: 'dev_recover_1', thumbprint: 'kid_recover_1' }
      const bundle = {
        device_identity: {
          domain_id: identity.domainId,
          device_id: identity.deviceId,
          public_key: { kid: identity.thumbprint },
        },
        trust_grant: { grant_id: 'grant_current_1' },
      } as import('@/iscp/enrollment').IscpProfileBundle
      const deps: import('@/iscp/credentialRecovery').CredentialRecoveryDeps = {
        profileId: 'policy-test',
        bundle,
        provider,
        send: async (call) => {
          sends.push(call)
          if (opts?.send) return await opts.send(call)
          rotation += 1
          return sealFor(call.wrapPublicKey, identity, rotation)
        },
        makeProof: (challenge) => ({ nonce: `nonce_${sends.length}_${Math.random()}`, challenge } as unknown as DeviceProof),
        newKey: () => `key_${++keyCounter}`,
        newWrapKey: () => {
          const pair = provider.generateSessionKeyPair()
          return { privateKey: pair.privateKey, publicKey: toBase64Url(pair.publicKey.bytes) }
        },
        applyCredentials: (credentials) => {
          applied.push(credentials)
        },
        readState: () => stored,
        writeState: (s) => {
          stored = s
        },
        now: () => t0,
        log: () => {},
      }
      return {
        deps,
        state: () => stored,
        sends,
        applied,
        setGrantId: (id) => {
          bundle.trust_grant = { ...bundle.trust_grant, grant_id: id }
        },
        setForce: (force) => {
          deps.force = force
        },
      }
    }

    it('recovers: opens the sealed pair and persists tokens with the FULL expiry metadata', async () => {
      const h = harness()
      const outcome = await recovery.runCredentialRecovery(h.deps)
      expect(outcome.result).toBe('recovered')
      expect(h.applied).toHaveLength(1)
      const applied = h.applied[0]!
      expect(applied.accessToken).toBe('rac_3')
      expect(applied.refreshToken).toBe('rrc_3')
      expect(applied.access.credential_id).toBe('cred_a_3')
      expect(applied.access.expires_at).toBeTruthy()
      expect(applied.access.issued_at).toBeTruthy()
      expect(applied.refresh.rotation_counter).toBe(3)
      const state = h.state()!
      expect(state.inflight).toBeUndefined()
      expect(state.last_result).toBe('recovered')
    })

    it('persists key + wrap private key + proof BEFORE the request leaves', async () => {
      let observedAtSendTime: import('@/iscp/credentialRecovery').CredentialRecoveryInflight | undefined
      const h = harness({
        send: async (call) => {
          observedAtSendTime = h.state()?.inflight
          return sealFor(call.wrapPublicKey, { domainId: DOMAIN_ID, deviceId: 'dev_recover_1', thumbprint: 'kid_recover_1' }, 3)
        },
      })
      await recovery.runCredentialRecovery(h.deps)
      expect(observedAtSendTime).toBeDefined()
      expect(observedAtSendTime!.idempotency_key).toBe(h.sends[0]!.idempotencyKey)
      expect(observedAtSendTime!.wrap_public).toBe(h.sends[0]!.wrapPublicKey)
      // The wrap PRIVATE key is on disk before the send — a replayed
      // ciphertext-only response stays openable after a crash.
      expect(fromBase64Url(observedAtSendTime!.wrap_private)).toHaveLength(32)
      expect(observedAtSendTime!.proof).toEqual(h.sends[0]!.proof)
    })

    it('unknown outcome keeps the record; the retry reuses key + wrap key + proof verbatim and opens the replay', async () => {
      let failFirst = true
      const h = harness({
        send: async (call) => {
          if (failFirst) {
            failFirst = false
            throw new TypeError('fetch failed')
          }
          return sealFor(call.wrapPublicKey, { domainId: DOMAIN_ID, deviceId: 'dev_recover_1', thumbprint: 'kid_recover_1' }, 3)
        },
      })
      expect((await recovery.runCredentialRecovery(h.deps)).result).toBe('unknown-kept')
      expect(h.state()?.inflight).toBeDefined()
      const outcome = await recovery.runCredentialRecovery(h.deps)
      expect(outcome.result).toBe('recovered')
      expect(h.sends).toHaveLength(2)
      expect(h.sends[1]).toEqual(h.sends[0])
      expect(h.state()?.inflight).toBeUndefined()
    })

    it('burned nonce after a crash: the verbatim retry escalates ONCE to a fresh proof for the SAME key + wrap key', async () => {
      // Sequence: transmission 1 dies (unknown outcome, nonce burned
      // server-side), the verbatim retry is rejected as a replay, and the
      // ladder remints the proof exactly once for the same logical recovery.
      let call = 0
      const h = harness({
        send: async (c) => {
          call += 1
          if (call === 1) throw new TypeError('socket hang up')
          if (call === 2) throw cloudReason(409, 'proof_replay_detected')
          return sealFor(c.wrapPublicKey, { domainId: DOMAIN_ID, deviceId: 'dev_recover_1', thumbprint: 'kid_recover_1' }, 3)
        },
      })
      expect((await recovery.runCredentialRecovery(h.deps)).result).toBe('unknown-kept')
      const outcome = await recovery.runCredentialRecovery(h.deps)
      expect(outcome.result).toBe('recovered')
      expect(h.sends).toHaveLength(3)
      expect(h.sends[1]!.proof).toEqual(h.sends[0]!.proof)
      expect(h.sends[2]!.idempotencyKey).toBe(h.sends[0]!.idempotencyKey)
      expect(h.sends[2]!.wrapPublicKey).toBe(h.sends[0]!.wrapPublicKey)
      expect(h.sends[2]!.proof).not.toEqual(h.sends[0]!.proof)
    })

    it('proof_replay_detected for a FRESH nonce is a surfaced anomaly, never a loop', async () => {
      let call = 0
      const h = harness({
        send: async () => {
          call += 1
          if (call === 1) throw new TypeError('socket hang up')
          throw cloudReason(409, 'proof_replay_detected')
        },
      })
      expect((await recovery.runCredentialRecovery(h.deps)).result).toBe('unknown-kept')
      const outcome = await recovery.runCredentialRecovery(h.deps)
      expect(outcome).toEqual({ result: 'action-required', reason: 'proof_replay_anomaly' })
      expect(h.sends).toHaveLength(3)
    })

    it('a FRESH first proof rejected is transient (clock skew / key mismatch), not an escalation', async () => {
      const h = harness({
        send: async () => {
          throw cloudReason(401, 'device_proof_invalid')
        },
      })
      expect((await recovery.runCredentialRecovery(h.deps)).result).toBe('transient')
      expect(h.sends).toHaveLength(1)
      expect(h.state()?.inflight).toBeUndefined()
    })

    it('terminal reasons stop recovery; a grant change (renewal) clears the stop', async () => {
      let calls = 0
      const h = harness({
        send: async (call) => {
          calls += 1
          if (calls === 1) throw cloudReason(410, 'recovery_grant_expired')
          return sealFor(call.wrapPublicKey, { domainId: DOMAIN_ID, deviceId: 'dev_recover_1', thumbprint: 'kid_recover_1' }, 3)
        },
      })
      expect(await recovery.runCredentialRecovery(h.deps)).toEqual({ result: 'action-required', reason: 'recovery_grant_expired' })
      expect(h.state()?.action_required).toMatchObject({ reason: 'recovery_grant_expired', grant_id: 'grant_current_1' })
      // Still stopped, zero additional wire calls.
      expect(await recovery.runCredentialRecovery(h.deps)).toEqual({ result: 'action-required', reason: 'recovery_grant_expired' })
      expect(h.sends).toHaveLength(1)
      // The grant was renewed (§9/§10 first, then recovery — the frozen order).
      h.setGrantId('grant_renewed_2')
      expect((await recovery.runCredentialRecovery(h.deps)).result).toBe('recovered')
    })

    it('--force clears a stop for the SAME grant (operator override)', async () => {
      let calls = 0
      const h = harness({
        send: async (call) => {
          calls += 1
          if (calls === 1) throw cloudReason(403, 'credential_recovery_disabled')
          return sealFor(call.wrapPublicKey, { domainId: DOMAIN_ID, deviceId: 'dev_recover_1', thumbprint: 'kid_recover_1' }, 3)
        },
      })
      expect((await recovery.runCredentialRecovery(h.deps)).result).toBe('action-required')
      h.setForce(true)
      expect((await recovery.runCredentialRecovery(h.deps)).result).toBe('recovered')
    })

    it('transient failures clear the in-flight record so the next attempt is a fresh logical recovery', async () => {
      let calls = 0
      const h = harness({
        send: async (call) => {
          calls += 1
          if (calls === 1) throw cloudReason(503, 'internal_error')
          return sealFor(call.wrapPublicKey, { domainId: DOMAIN_ID, deviceId: 'dev_recover_1', thumbprint: 'kid_recover_1' }, 3)
        },
      })
      expect((await recovery.runCredentialRecovery(h.deps)).result).toBe('transient')
      expect(h.state()?.inflight).toBeUndefined()
      expect((await recovery.runCredentialRecovery(h.deps)).result).toBe('recovered')
      expect(h.sends[1]!.idempotencyKey).not.toBe(h.sends[0]!.idempotencyKey)
    })

    it('a response for a different device identity never touches the profile and never loops', async () => {
      // A bad 201 would be replayed identically by the idempotency layer, so
      // it must terminate as a stable anomaly instead of an unknown-outcome
      // retry loop.
      const h = harness({
        send: async (call) => sealFor(call.wrapPublicKey, { domainId: DOMAIN_ID, deviceId: 'dev_SOMEONE_ELSE', thumbprint: 'kid_recover_1' }, 3),
      })
      const outcome = await recovery.runCredentialRecovery(h.deps)
      expect(outcome).toEqual({ result: 'action-required', reason: 'recovery_response_invalid' })
      expect(h.applied).toHaveLength(0)
      expect(h.state()?.action_required?.detail).toMatch(/different device identity/)
    })
  })

  // -------------------------------------------------------------------------
  // End to end against the CloudFixture (real enrollment, real wire)
  // -------------------------------------------------------------------------

  describe('recoverProfileCredentialsNow against the CloudFixture', () => {
    it('recovers an enrolled profile and persists the pair with metadata; state clears', async () => {
      const ticket = fixture.issueTicket()
      const { profileId, bundle } = await enrollment.enroll({
        relayUrl: fixture.baseUrl,
        trustUrl: fixture.baseUrl,
        relayId: RELAY_ID,
        trustRootId: TRUST_ROOT_ID,
        ticket: encodeTicketForTransport(ticket),
        profileId: 'recover-e2e',
        log: () => {},
      })
      const oldRefresh = bundle.refresh_credential.token

      const outcome = await recovery.recoverProfileCredentialsNow({
        profileId,
        provider,
        relayUrlOverride: fixture.baseUrl,
        log: () => {},
      })
      expect(outcome.result).toBe('recovered')
      expect(fixture.recoverCalls).toBe(1)

      const updated = enrollment.readProfileBundle(profileId)!
      expect(updated.refresh_credential.token).not.toBe(oldRefresh)
      expect(updated.refresh_credential.token.startsWith('rrc_recovered_')).toBe(true)
      expect(updated.refresh_credential.credential_id).toBeTruthy()
      expect(updated.refresh_credential.issued_at).toBeTruthy()
      expect(updated.refresh_credential.rotation_counter).toBeGreaterThan(2)
      expect(updated.access_credential.credential_id).toBeTruthy()
      // The device key and grant are untouched — recovery is never a re-enroll.
      expect(updated.device_identity).toEqual(bundle.device_identity)
      expect(updated.trust_grant.grant_id).toBe(bundle.trust_grant.grant_id)

      const state = recovery.readCredentialRecoveryState(profileId)!
      expect(state.inflight).toBeUndefined()
      expect(state.last_result).toBe('recovered')
    })

    it('a terminal grant gate stops recovery with the stable reason', async () => {
      const ticket = fixture.issueTicket()
      const { profileId } = await enrollment.enroll({
        relayUrl: fixture.baseUrl,
        trustUrl: fixture.baseUrl,
        relayId: RELAY_ID,
        trustRootId: TRUST_ROOT_ID,
        ticket: encodeTicketForTransport(ticket),
        profileId: 'recover-e2e-expired',
        log: () => {},
      })
      fixture.credentialRecovery = { enabled: true, grant: 'expired' }
      try {
        const outcome = await recovery.recoverProfileCredentialsNow({
          profileId,
          provider,
          relayUrlOverride: fixture.baseUrl,
          log: () => {},
        })
        expect(outcome).toEqual({ result: 'action-required', reason: 'recovery_grant_expired' })
      } finally {
        fixture.credentialRecovery = { enabled: true, grant: 'active' }
      }
    })
  })
})
