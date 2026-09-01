/**
 * Managed enrollment against an in-process fixture implementing the
 * Infinimesh Cloud v2 signed-ticket contract (OPS 2026-08-16 §5.5,
 * InfinimeshCloud docs/10-design/12-managed-provisioning.md):
 *
 *   - wrapper / bare-ticket / JSON / file-path enrollment inputs;
 *   - client-side ticket verification before consumption;
 *   - official dev_ id remapping into the persisted bundle;
 *   - the grant verification gate (tampered/mismatched grants leave no
 *     files on disk);
 *   - ticket_consumed (410) reuse and Idempotency-Key replay.
 *
 * The persistent-identity state machine (healthy/corrupt/--replace, locks,
 * atomicity) is covered in enrollmentLifecycle.test.ts.
 */

import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import {
  createDevice,
  createNobleProvider,
  encodeEnrollmentWrapperForTransport,
  encodeTicketForTransport,
  rfc3339Seconds,
  signPairingTicket,
} from '@slopus/iscp'

import { CloudFixture, type GrantTamper } from '@/iscp/testing/cloudFixture'

const homeDir = mkdtempSync(join(tmpdir(), 'happy-iscp-enroll-'))
process.env.HAPPY_HOME_DIR = homeDir

const RELAY_ID = 'relay-cloud-test'
const TRUST_ROOT_ID = 'trust-cloud-test'
const DOMAIN_ID = 'dom_fixture'
const PHONE_DEVICE_ID = 'dev_phone_fixture'

const provider = createNobleProvider()

describe('managed enrollment (Cloud v2 signed-ticket contract)', () => {
  const fixture = new CloudFixture({ relayId: RELAY_ID, trustRootId: TRUST_ROOT_ID, domainId: DOMAIN_ID, phoneDeviceId: PHONE_DEVICE_ID })
  let enroll: typeof import('@/iscp/enrollment').enroll
  let parseEnrollmentInput: typeof import('@/iscp/enrollment').parseEnrollmentInput
  let iscpProfileDir: typeof import('@/iscp/enrollment').iscpProfileDir

  beforeAll(async () => {
    await fixture.start()
    // Dynamic import so HAPPY_HOME_DIR (temp) is set before configuration loads.
    const enrollment = await import('@/iscp/enrollment')
    enroll = enrollment.enroll
    parseEnrollmentInput = enrollment.parseEnrollmentInput
    iscpProfileDir = enrollment.iscpProfileDir
  })

  afterAll(async () => {
    await fixture.stop()
    rmSync(homeDir, { recursive: true, force: true })
    delete process.env.HAPPY_HOME_DIR
  })

  function enrollOpts(ticket: string, profileId: string, extra?: { domainId?: string }) {
    const lines: string[] = []
    return {
      opts: {
        relayUrl: fixture.baseUrl,
        trustUrl: fixture.baseUrl,
        relayId: RELAY_ID,
        trustRootId: TRUST_ROOT_ID,
        ticket,
        profileId,
        log: (line: string) => lines.push(line),
        ...extra,
      },
      lines,
    }
  }

  it('enrolls via the Console wrapper: official dev_ id, verified grant, 0600/0700 files', async () => {
    fixture.grantTamper = undefined
    const ticket = fixture.issueTicket()
    const wrapper = encodeEnrollmentWrapperForTransport({
      ticket,
      expectedAudiencePhoneId: PHONE_DEVICE_ID,
      displayName: 'Chiiz workstation',
    })
    const { opts, lines } = enrollOpts(wrapper, 'wrapper-ok')
    const { bundle, dir } = await enroll(opts)

    // The bundle carries the official identity, never the provisional one.
    expect(bundle.device_identity.device_id).toMatch(/^dev_official_/)
    expect(bundle.device_identity.domain_id).toBe(DOMAIN_ID)
    expect(bundle.domain_id).toBe(DOMAIN_ID)
    expect(bundle.trust_grant.subject_device_id).toBe(bundle.device_identity.device_id)
    expect(bundle.trust_grant.audience).toBe(PHONE_DEVICE_ID)
    expect(bundle.access_credential.token).toMatch(/^acc_/)
    expect(bundle.refresh_credential.token).toMatch(/^ref_/)
    expect(bundle.generation).toBe(1)

    // Wrapper display_name reached the Cloud; no legacy/shape fields did.
    expect(fixture.lastRegisterBody?.display_name).toBe('Chiiz workstation')
    expect(fixture.lastRegisterBody).not.toHaveProperty('device_type')
    expect(fixture.lastRegisterBody).not.toHaveProperty('device_role')
    expect(fixture.lastRegisterBody).not.toHaveProperty('max_uses')
    expect(fixture.lastRegisterBody).not.toHaveProperty('pairing_code')

    // 0700 dir, 0600 key + bundle.
    expect(statSync(dir).mode & 0o777).toBe(0o700)
    expect(statSync(join(dir, 'device.key')).mode & 0o777).toBe(0o600)
    expect(statSync(join(dir, 'bundle.json')).mode & 0o777).toBe(0o600)

    // Persisted identity matches what the log promised.
    const persisted = JSON.parse(readFileSync(join(dir, 'bundle.json'), 'utf8')) as typeof bundle
    expect(persisted.device_identity.device_id).toBe(bundle.device_identity.device_id)
    expect(lines.join('\n')).toContain(`audience matches expected phone ${PHONE_DEVICE_ID}`)
    // Never log ticket payloads or tokens.
    expect(lines.join('\n')).not.toContain(bundle.access_credential.token)
    expect(lines.join('\n')).not.toContain(wrapper)
  })

  it('enrolls via a bare ticket and prominently shows the grant audience for confirmation', async () => {
    fixture.grantTamper = undefined
    const ticket = fixture.issueTicket()
    const { opts, lines } = enrollOpts(encodeTicketForTransport(ticket), 'bare-ok')
    const { bundle } = await enroll(opts)
    expect(bundle.trust_grant.audience).toBe(PHONE_DEVICE_ID)
    const output = lines.join('\n')
    expect(output).toContain(`Grant audience (the phone allowed to control this machine): ${PHONE_DEVICE_ID}`)
  })

  it('takes the domain from the ticket and cross-checks an explicit --domain', async () => {
    fixture.grantTamper = undefined
    const ticket = fixture.issueTicket()
    const { opts } = enrollOpts(encodeTicketForTransport(ticket), 'domain-mismatch', { domainId: 'dom_other' })
    await expect(enroll(opts)).rejects.toThrowError(/domain dom_fixture, not dom_other/)
    expect(existsSync(iscpProfileDir('domain-mismatch'))).toBe(false)
  })

  it('rejects a ticket bound to a different relay/trust root before consuming it', async () => {
    const foreign = signPairingTicket(provider, fixture.trustSigner, {
      ticket_id: 'tick_foreign',
      domain_id: DOMAIN_ID,
      relay_id: 'relay-other',
      trust_root_id: TRUST_ROOT_ID,
      max_uses: 1,
      issued_at: rfc3339Seconds(new Date()),
      expires_at: rfc3339Seconds(new Date(Date.now() + 300_000)),
    })
    const { opts } = enrollOpts(encodeTicketForTransport(foreign), 'foreign-relay')
    await expect(enroll(opts)).rejects.toThrowError(/bound to relay relay-other/)
    expect(existsSync(iscpProfileDir('foreign-relay'))).toBe(false)
  })

  it('rejects a ticket not signed by an active trust root key (client-side verifyPairingTicket)', async () => {
    const rogue = createDevice(provider, { domainId: 'platform', deviceId: 'rogue-signer' })
    const forged = signPairingTicket(provider, rogue, {
      ticket_id: 'tick_forged',
      domain_id: DOMAIN_ID,
      relay_id: RELAY_ID,
      trust_root_id: TRUST_ROOT_ID,
      max_uses: 1,
      issued_at: rfc3339Seconds(new Date()),
      expires_at: rfc3339Seconds(new Date(Date.now() + 300_000)),
    })
    const { opts } = enrollOpts(encodeTicketForTransport(forged), 'forged-ticket')
    await expect(enroll(opts)).rejects.toThrowError(/not signed by an active trust root key/)
    expect(existsSync(iscpProfileDir('forged-ticket'))).toBe(false)
  })

  it('surfaces ticket_consumed (410) on reuse and leaves no files behind', async () => {
    fixture.grantTamper = undefined
    const ticket = fixture.issueTicket()
    const first = enrollOpts(encodeTicketForTransport(ticket), 'reuse-first')
    await enroll(first.opts)
    const second = enrollOpts(encodeTicketForTransport(ticket), 'reuse-second')
    await expect(enroll(second.opts)).rejects.toThrowError(/ticket_consumed/)
    expect(existsSync(iscpProfileDir('reuse-second'))).toBe(false)
  })

  const tamperCases: Array<{ tamper: GrantTamper; profile: string; expectError: RegExp }> = [
    { tamper: 'signature', profile: 'gate-signature', expectError: /signature verification failed/ },
    { tamper: 'subject', profile: 'gate-subject', expectError: /subject mismatch/ },
    { tamper: 'confirmation', profile: 'gate-confirmation', expectError: /confirmation mismatch/ },
    { tamper: 'expired', profile: 'gate-expired', expectError: /not currently valid/ },
  ]
  for (const { tamper, profile, expectError } of tamperCases) {
    it(`grant gate: rejects a grant with ${tamper} tampering and persists nothing`, async () => {
      fixture.grantTamper = tamper
      const ticket = fixture.issueTicket()
      const { opts } = enrollOpts(encodeTicketForTransport(ticket), profile)
      await expect(enroll(opts)).rejects.toThrowError(expectError)
      expect(existsSync(iscpProfileDir(profile))).toBe(false)
      fixture.grantTamper = undefined
    })
  }

  it('grant gate: rejects an audience that contradicts the wrapper expected phone', async () => {
    fixture.grantTamper = 'audience' // fixture issues dev_wrong_phone
    const ticket = fixture.issueTicket()
    const wrapper = encodeEnrollmentWrapperForTransport({ ticket, expectedAudiencePhoneId: PHONE_DEVICE_ID })
    const { opts } = enrollOpts(wrapper, 'gate-audience')
    await expect(enroll(opts)).rejects.toThrowError(/audience mismatch/)
    expect(existsSync(iscpProfileDir('gate-audience'))).toBe(false)
    fixture.grantTamper = undefined
  })

  it('parseEnrollmentInput handles wrapper strings, bare tickets, raw JSON, files, and garbage', () => {
    const ticket = fixture.issueTicket()

    const fromWrapper = parseEnrollmentInput(encodeEnrollmentWrapperForTransport({ ticket, expectedAudiencePhoneId: PHONE_DEVICE_ID, displayName: 'x' }))
    expect(fromWrapper.ticket).toEqual(ticket)
    expect(fromWrapper.expectedAudiencePhoneId).toBe(PHONE_DEVICE_ID)

    const fromBare = parseEnrollmentInput(encodeTicketForTransport(ticket))
    expect(fromBare.ticket).toEqual(ticket)
    expect(fromBare.expectedAudiencePhoneId).toBeUndefined()

    expect(parseEnrollmentInput(JSON.stringify(ticket)).ticket).toEqual(ticket)
    expect(parseEnrollmentInput(JSON.stringify({ version: 1, ticket, display_name: 'file' })).displayName).toBe('file')

    const ticketFile = join(homeDir, 'ticket.json')
    writeFileSync(ticketFile, JSON.stringify(ticket))
    expect(parseEnrollmentInput(ticketFile).ticket).toEqual(ticket)
    const wrapperFile = join(homeDir, 'wrapper.json')
    writeFileSync(wrapperFile, JSON.stringify({ version: 1, ticket, expected_audience_phone_id: 'dev_p2', display_name: 'JingSi issued' }))
    expect(parseEnrollmentInput(wrapperFile).expectedAudiencePhoneId).toBe('dev_p2')
    expect(parseEnrollmentInput(wrapperFile).fromWrapper).toBe(true)

    expect(() => parseEnrollmentInput('!!!not-a-ticket!!!')).toThrowError()
    expect(() => parseEnrollmentInput('{"not":"a ticket"}')).toThrowError()
  })

  it('rejects retired Cloud pair_… codes with the stable migration error, not an encoding error', () => {
    for (const input of ['pair_abc123', '  pair_abc123  ', 'pair_']) {
      let thrown: unknown
      try {
        parseEnrollmentInput(input)
      } catch (error) {
        thrown = error
      }
      expect(thrown).toBeInstanceOf(Error)
      expect((thrown as { code?: string }).code).toBe('legacy_pairing_code_unsupported')
      const message = (thrown as Error).message
      expect(message).toContain('legacy_pairing_code_unsupported')
      expect(message).toContain('iscp.pairing_ticket.v2')
      expect(message).not.toContain('invalid enrollment payload encoding')
      // The raw code must never be echoed back (no secrets/codes in output contract).
      expect(message).not.toContain('pair_abc123')
    }
  })
})
