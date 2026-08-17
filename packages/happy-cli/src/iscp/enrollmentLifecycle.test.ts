/**
 * Persistent-identity state machine + grant renewal (OPS 2026-08-17 §4.1/§4.3):
 *
 *   - first enroll: exactly one key, one Cloud registration, generation 1;
 *   - healthy profile blocks re-enroll (ticket unconsumed, files untouched);
 *   - --replace: full backup of the old profile, new key, generation + 1;
 *   - corrupt profiles refuse by default with a reason, --replace recovers;
 *   - ticket replay (410): zero local side effects;
 *   - concurrent enrollments: profile lock lets exactly one through;
 *   - atomic persistence: leftover tmp dirs never corrupt the profile view;
 *   - renewProfileGrant: grant swap without key/device change, audience
 *     drift rejection, Cloud error mapping, byte-identical bundle on failure.
 */

import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import { createNobleProvider, encodeTicketForTransport } from '@slopus/iscp'

import { CloudFixture, type RenewalFixtureEntry } from '@/iscp/testing/cloudFixture'

const homeDir = mkdtempSync(join(tmpdir(), 'happy-iscp-lifecycle-'))
process.env.HAPPY_HOME_DIR = homeDir

const RELAY_ID = 'relay-cloud-test'
const TRUST_ROOT_ID = 'trust-cloud-test'
const DOMAIN_ID = 'dom_fixture'
const PHONE_DEVICE_ID = 'dev_phone_fixture'

const provider = createNobleProvider()

type Enrollment = typeof import('@/iscp/enrollment')

function readBytes(path: string): Buffer {
  return readFileSync(path)
}

function profileSnapshot(dir: string): { bundle: Buffer; key: Buffer } {
  return { bundle: readBytes(join(dir, 'bundle.json')), key: readBytes(join(dir, 'device.key')) }
}

describe('persistent identity state machine + renewal', () => {
  const fixture = new CloudFixture({ relayId: RELAY_ID, trustRootId: TRUST_ROOT_ID, domainId: DOMAIN_ID, phoneDeviceId: PHONE_DEVICE_ID })
  let enrollment: Enrollment

  beforeAll(async () => {
    await fixture.start()
    // Dynamic import so HAPPY_HOME_DIR (temp) is set before configuration loads.
    enrollment = await import('@/iscp/enrollment')
  })

  afterAll(async () => {
    await fixture.stop()
    rmSync(homeDir, { recursive: true, force: true })
    delete process.env.HAPPY_HOME_DIR
  })

  function enrollOpts(profileId: string, extra?: { replace?: boolean }) {
    const lines: string[] = []
    return {
      opts: {
        relayUrl: fixture.baseUrl,
        trustUrl: fixture.baseUrl,
        relayId: RELAY_ID,
        trustRootId: TRUST_ROOT_ID,
        ticket: encodeTicketForTransport(fixture.issueTicket()),
        profileId,
        log: (line: string) => lines.push(line),
        ...extra,
      },
      lines,
    }
  }

  it('first enroll registers exactly once and persists generation 1 with a single key', async () => {
    const registerCallsBefore = fixture.registerCalls
    const { opts } = enrollOpts('first')
    const { bundle, dir } = await enrollment.enroll(opts)
    expect(fixture.registerCalls).toBe(registerCallsBefore + 1)
    expect(bundle.generation).toBe(1)
    const entries = readdirSync(dir).sort()
    expect(entries).toEqual(['bundle.json', 'device.key'])
    expect(enrollment.inspectProfile(provider, 'first').state).toBe('healthy')
  })

  it('a healthy profile blocks re-enrollment: no registration, files byte-identical, guidance printed', async () => {
    const { opts } = enrollOpts('guarded')
    const { dir, bundle } = await enrollment.enroll(opts)
    const before = profileSnapshot(dir)
    const registerCallsBefore = fixture.registerCalls

    const again = enrollOpts('guarded')
    const error = await enrollment.enroll(again.opts).catch((e: unknown) => e as Error)
    expect(error).toBeInstanceOf(Error)
    expect((error as Error).message).toMatch(/already exists and is healthy/)
    expect((error as Error).message).toContain(bundle.device_identity.device_id)
    expect((error as Error).message).toContain(bundle.trust_grant.expires_at)
    expect((error as Error).message).toContain('happy iscp status')
    expect((error as Error).message).toContain('happy iscp renew')
    expect((error as Error).message).toContain('--replace')

    // The ticket was never consumed: zero registration calls hit the Cloud.
    expect(fixture.registerCalls).toBe(registerCallsBefore)
    const after = profileSnapshot(dir)
    expect(after.bundle.equals(before.bundle)).toBe(true)
    expect(after.key.equals(before.key)).toBe(true)
  })

  it('--replace backs up the old profile completely, generates a NEW key, and bumps the generation', async () => {
    const { opts } = enrollOpts('replaced')
    const { dir } = await enrollment.enroll(opts)
    const before = profileSnapshot(dir)

    const replace = enrollOpts('replaced', { replace: true })
    const { bundle: newBundle, backupDir } = await enrollment.enroll(replace.opts)
    expect(newBundle.generation).toBe(2)
    expect(backupDir).toBeDefined()
    expect(backupDir).toMatch(/replaced\.replaced-/)
    // Backup is the byte-identical old profile; the backup is never deleted.
    const backup = profileSnapshot(backupDir!)
    expect(backup.bundle.equals(before.bundle)).toBe(true)
    expect(backup.key.equals(before.key)).toBe(true)
    // New identity: new key material and a new device id.
    const after = profileSnapshot(dir)
    expect(after.key.equals(before.key)).toBe(false)
    const oldBundle = JSON.parse(before.bundle.toString('utf8')) as { device_identity: { device_id: string } }
    expect(newBundle.device_identity.device_id).not.toBe(oldBundle.device_identity.device_id)
    // Backups never show up as profiles.
    expect(enrollment.listProfiles()).not.toContain(`replaced.replaced-`)
    expect(enrollment.listProfiles().every((p) => !p.includes('.replaced-'))).toBe(true)
  })

  it('a corrupt profile (missing key) refuses by default with the reason; --replace recovers', async () => {
    const { opts } = enrollOpts('corrupt-key')
    const { dir } = await enrollment.enroll(opts)
    rmSync(join(dir, 'device.key'))

    const inspection = enrollment.inspectProfile(provider, 'corrupt-key')
    expect(inspection).toMatchObject({ state: 'corrupt', reason: expect.stringContaining('device.key is missing') })

    const retry = enrollOpts('corrupt-key')
    await expect(enrollment.enroll(retry.opts)).rejects.toThrowError(/corrupt.*device\.key is missing.*--replace/s)

    const replace = enrollOpts('corrupt-key', { replace: true })
    const { bundle } = await enrollment.enroll(replace.opts)
    expect(bundle.generation).toBe(2) // old bundle was readable: (1) + 1
    expect(enrollment.inspectProfile(provider, 'corrupt-key').state).toBe('healthy')
  })

  it('a corrupt profile (tampered JSON) refuses by default; --replace recovers', async () => {
    const { opts } = enrollOpts('corrupt-json')
    const { dir } = await enrollment.enroll(opts)
    writeFileSync(join(dir, 'bundle.json'), '{not json', { mode: 0o600 })

    const inspection = enrollment.inspectProfile(provider, 'corrupt-json')
    expect(inspection).toMatchObject({ state: 'corrupt', reason: expect.stringContaining('not valid JSON') })

    const retry = enrollOpts('corrupt-json')
    await expect(enrollment.enroll(retry.opts)).rejects.toThrowError(/corrupt.*not valid JSON.*--replace/s)

    const replace = enrollOpts('corrupt-json', { replace: true })
    const { bundle } = await enrollment.enroll(replace.opts)
    expect(enrollment.inspectProfile(provider, 'corrupt-json').state).toBe('healthy')
    expect(bundle.generation).toBeGreaterThanOrEqual(1)
  })

  it('a key/identity mismatch is corrupt (deviceFromStored gate)', async () => {
    const a = enrollOpts('mismatch-a')
    await enrollment.enroll(a.opts)
    const b = enrollOpts('mismatch-b')
    await enrollment.enroll(b.opts)
    // Swap A's key with B's key: bundle identity no longer matches the seed.
    const keyB = readFileSync(join(enrollment.iscpProfileDir('mismatch-b'), 'device.key'))
    writeFileSync(join(enrollment.iscpProfileDir('mismatch-a'), 'device.key'), keyB, { mode: 0o600 })
    const inspection = enrollment.inspectProfile(provider, 'mismatch-a')
    expect(inspection).toMatchObject({ state: 'corrupt', reason: expect.stringContaining('does not match') })
  })

  it('ticket replay (410) leaves zero local side effects: bundle intact, no tmp/backup dirs', async () => {
    const consumedTicket = fixture.issueTicket()
    const first = {
      relayUrl: fixture.baseUrl,
      trustUrl: fixture.baseUrl,
      relayId: RELAY_ID,
      trustRootId: TRUST_ROOT_ID,
      ticket: encodeTicketForTransport(consumedTicket),
      profileId: 'replay-victim',
      log: () => { },
    }
    const { dir } = await enrollment.enroll(first)
    const before = profileSnapshot(dir)

    // Replay the consumed ticket against the same profile with --replace: the
    // server rejects; the client must not delete/regenerate anything.
    const replay = { ...first, replace: true }
    await expect(enrollment.enroll(replay)).rejects.toThrowError(/ticket_consumed/)

    const after = profileSnapshot(dir)
    expect(after.bundle.equals(before.bundle)).toBe(true)
    expect(after.key.equals(before.key)).toBe(true)
    const leftovers = readdirSync(join(homeDir, 'iscp')).filter((e) => e.startsWith('replay-victim.'))
    expect(leftovers).toEqual([])
  })

  it('two concurrent enrollments for the same profile: one wins, one hits the lock, no mixed state', async () => {
    const registerCallsBefore = fixture.registerCalls
    const a = enrollOpts('concurrent')
    const b = enrollOpts('concurrent')
    const results = await Promise.allSettled([enrollment.enroll(a.opts), enrollment.enroll(b.opts)])
    const fulfilled = results.filter((r) => r.status === 'fulfilled')
    const rejected = results.filter((r): r is PromiseRejectedResult => r.status === 'rejected')
    expect(fulfilled).toHaveLength(1)
    expect(rejected).toHaveLength(1)
    expect(String(rejected[0]!.reason)).toMatch(/already in progress/)
    // Exactly one registration reached the Cloud; the profile is healthy.
    expect(fixture.registerCalls).toBe(registerCallsBefore + 1)
    expect(enrollment.inspectProfile(provider, 'concurrent').state).toBe('healthy')
    // The lock was released: a later guarded attempt fails on "healthy", not on the lock.
    await expect(enrollment.enroll(enrollOpts('concurrent').opts)).rejects.toThrowError(/already exists and is healthy/)
  })

  it('atomic persistence: a leftover tmp dir (crash before rename) never corrupts the profile view', async () => {
    const { opts } = enrollOpts('atomic')
    const { dir, bundle } = await enrollment.enroll(opts)
    // Simulate a crash between writing the temp dir and the final rename.
    const tmpDir = `${dir}.tmp-99999-deadbeef`
    mkdirSync(tmpDir, { recursive: true, mode: 0o700 })
    writeFileSync(join(tmpDir, 'bundle.json'), '{"partial": true}')
    writeFileSync(join(tmpDir, 'device.key'), '{"seed": "AAAA"}')

    // Restart view: the old profile is fully intact and the tmp dir is
    // invisible to every reader.
    expect(enrollment.listProfiles()).toContain('atomic')
    expect(enrollment.listProfiles().filter((p) => p.includes('.tmp-'))).toEqual([])
    const inspection = enrollment.inspectProfile(provider, 'atomic')
    expect(inspection.state).toBe('healthy')
    if (inspection.state === 'healthy') {
      expect(inspection.bundle.device_identity.device_id).toBe(bundle.device_identity.device_id)
    }
  })

  it('a stale lock (dead pid) is reclaimed; a live lock is respected', async () => {
    const locksDir = join(homeDir, 'iscp', '.locks')
    mkdirSync(locksDir, { recursive: true })
    // Dead pid → stale → reclaimed.
    writeFileSync(join(locksDir, 'stale-lock.lock'), '999999999')
    const release = enrollment.acquireProfileLock('stale-lock')
    release()
    // Live pid (our own) → refused.
    writeFileSync(join(locksDir, 'live-lock.lock'), String(process.pid))
    expect(() => enrollment.acquireProfileLock('live-lock')).toThrowError(/already in progress/)
    rmSync(join(locksDir, 'live-lock.lock'))
  })

  // -------------------------------------------------------------------------
  // Grant renewal
  // -------------------------------------------------------------------------

  it('renewGrant success: new grant + generation bump, key/device/audience unchanged', async () => {
    const { opts } = enrollOpts('renew-ok')
    const { dir, bundle: enrolled } = await enrollment.enroll(opts)
    const before = profileSnapshot(dir)
    fixture.renewals.set('ren_ok', { state: 'active', deviceId: enrolled.device_identity.device_id })

    const lines: string[] = []
    const { bundle: renewed } = await enrollment.renewProfileGrant({
      profileId: 'renew-ok',
      renewalId: 'ren_ok',
      log: (line) => lines.push(line),
    })

    expect(renewed.trust_grant.grant_id).not.toBe(enrolled.trust_grant.grant_id)
    expect(renewed.trust_grant.audience).toBe(enrolled.trust_grant.audience)
    expect(renewed.trust_grant.subject_device_id).toBe(enrolled.device_identity.device_id)
    expect(renewed.generation).toBe((enrolled.generation ?? 1) + 1)
    expect(renewed.device_identity).toEqual(enrolled.device_identity)
    expect(renewed.access_credential).toEqual(enrolled.access_credential)

    // The key file is byte-identical: renewal NEVER rewrites device.key.
    const after = profileSnapshot(dir)
    expect(after.key.equals(before.key)).toBe(true)
    expect(after.bundle.equals(before.bundle)).toBe(false)
    // The wire proof was bound to relay + renewal id.
    const proof = fixture.lastRenewBody?.identity_proof as { audience: string; challenge: string }
    expect(proof.audience).toBe(RELAY_ID)
    expect(proof.challenge).toBe('ren_ok')
    // No secrets in the log.
    expect(lines.join('\n')).not.toContain(enrolled.access_credential.token)
  })

  it('renewGrant rejects an audience drift and leaves the bundle byte-identical', async () => {
    const { opts } = enrollOpts('renew-drift')
    const { dir, bundle: enrolled } = await enrollment.enroll(opts)
    const before = profileSnapshot(dir)
    fixture.renewals.set('ren_drift', { state: 'active' })
    fixture.grantAudience = 'dev_other_phone' // Cloud tries to re-point the grant
    try {
      await expect(enrollment.renewProfileGrant({
        profileId: 'renew-drift',
        renewalId: 'ren_drift',
        log: () => { },
      })).rejects.toThrowError(/audience mismatch/)
    } finally {
      fixture.grantAudience = PHONE_DEVICE_ID
    }
    const after = profileSnapshot(dir)
    expect(after.bundle.equals(before.bundle)).toBe(true)
    expect(after.key.equals(before.key)).toBe(true)
    void enrolled
  })

  const renewalErrorCases: Array<{ renewalId: string; entry: RenewalFixtureEntry | undefined; expectError: RegExp }> = [
    { renewalId: 'ren_missing', entry: undefined, expectError: /renewal_not_found/ },
    { renewalId: 'ren_expired', entry: { state: 'expired' }, expectError: /renewal_expired/ },
    { renewalId: 'ren_used', entry: { state: 'consumed' }, expectError: /renewal_consumed/ },
    { renewalId: 'ren_wrong_dev', entry: { state: 'active', deviceId: 'dev_someone_else' }, expectError: /renewal_device_mismatch/ },
    { renewalId: 'ren_conflict', entry: { state: 'active', identityConflict: true }, expectError: /renewal_identity_conflict[\s\S]*--replace/ },
    { renewalId: 'ren_revoked', entry: { state: 'active', deviceRevoked: true }, expectError: /device_revoked/ },
  ]
  for (const { renewalId, entry, expectError } of renewalErrorCases) {
    it(`renewGrant maps ${renewalId} → ${expectError} and keeps the bundle byte-identical`, async () => {
      const profileId = `renew-err-${renewalId}`
      const { opts } = enrollOpts(profileId)
      const { dir } = await enrollment.enroll(opts)
      const before = profileSnapshot(dir)
      if (entry !== undefined) fixture.renewals.set(renewalId, entry)
      await expect(enrollment.renewProfileGrant({ profileId, renewalId, log: () => { } })).rejects.toThrowError(expectError)
      const after = profileSnapshot(dir)
      expect(after.bundle.equals(before.bundle)).toBe(true)
      expect(after.key.equals(before.key)).toBe(true)
    })
  }

  it('renewGrant refuses a corrupt profile and points at --replace', async () => {
    const { opts } = enrollOpts('renew-corrupt')
    const { dir } = await enrollment.enroll(opts)
    rmSync(join(dir, 'device.key'))
    await expect(enrollment.renewProfileGrant({
      profileId: 'renew-corrupt',
      renewalId: 'ren_whatever',
      log: () => { },
    })).rejects.toThrowError(/corrupt[\s\S]*--replace/)
  })

  it('renewGrant refuses an absent profile', async () => {
    await expect(enrollment.renewProfileGrant({
      profileId: 'never-enrolled',
      renewalId: 'ren_whatever',
      log: () => { },
    })).rejects.toThrowError(/not enrolled/)
  })
})
