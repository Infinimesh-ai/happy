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
 */

import { createServer, type Server } from 'node:http'
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
  signObject,
  signPairingTicket,
  verifyDeviceProof,
  verifyPairingTicket,
  SIGNED_DESCRIPTOR_TYPE,
  TRUST_GRANT_TYPE,
  type Device,
  type DeviceIdentity,
  type DeviceProof,
  type PairingTicket,
  type SignedDescriptor,
  type TrustGrant,
} from '@slopus/iscp'

const homeDir = mkdtempSync(join(tmpdir(), 'happy-iscp-enroll-'))
process.env.HAPPY_HOME_DIR = homeDir

const RELAY_ID = 'relay-cloud-test'
const TRUST_ROOT_ID = 'trust-cloud-test'
const DOMAIN_ID = 'dom_fixture'
const PHONE_DEVICE_ID = 'dev_phone_fixture'

const provider = createNobleProvider()

type GrantTamper = 'signature' | 'subject' | 'confirmation' | 'audience' | 'expired'

/** Minimal but faithful double of the Cloud's v2 signed-ticket endpoint. */
class CloudFixture {
  readonly relaySigner: Device
  readonly trustSigner: Device
  server!: Server
  baseUrl = ''
  grantTamper: GrantTamper | undefined
  /** Grant audience the fixture issues (the "phone" device). */
  grantAudience = PHONE_DEVICE_ID
  lastRegisterBody: Record<string, unknown> | undefined
  private readonly consumed = new Set<string>()
  private readonly nonces = new Set<string>()
  private readonly idempotency = new Map<string, { status: number; body: string }>()
  private deviceCounter = 0

  constructor() {
    this.relaySigner = createDevice(provider, { domainId: 'platform', deviceId: 'relay-signer' })
    this.trustSigner = createDevice(provider, { domainId: 'platform', deviceId: 'trust-signer' })
  }

  signedRelayDescriptor(): SignedDescriptor {
    const descriptor = {
      type: 'iscp.relay.descriptor.v2',
      relay_id: RELAY_ID,
      domain_id: 'platform',
      base_url: this.baseUrl,
      websocket_url: this.baseUrl.replace('http://', 'ws://'),
      signing_keys: [{
        kty: 'Ed25519' as const,
        use: 'descriptor-signature' as const,
        kid: this.relaySigner.identity.public_key.kid,
        public: this.relaySigner.identity.public_key.public,
      }],
      issued_at: rfc3339Seconds(new Date()),
      expires_at: rfc3339Seconds(new Date(Date.now() + 3600_000)),
    }
    return this.signDescriptor('iscp.relay.descriptor.v2', descriptor, this.relaySigner)
  }

  signedTrustDescriptor(): SignedDescriptor {
    const descriptor = {
      type: 'iscp.trust_root.descriptor.v2',
      trust_root_id: TRUST_ROOT_ID,
      domain_id: 'platform',
      base_url: this.baseUrl,
      keys: [{
        kty: 'Ed25519' as const,
        use: 'grant-signature' as const,
        kid: this.trustSigner.identity.public_key.kid,
        public: this.trustSigner.identity.public_key.public,
        state: 'active' as const,
      }],
      issued_at: rfc3339Seconds(new Date()),
      expires_at: rfc3339Seconds(new Date(Date.now() + 3600_000)),
    }
    return this.signDescriptor('iscp.trust_root.descriptor.v2', descriptor, this.trustSigner)
  }

  private signDescriptor(descriptorType: string, descriptor: object, signer: Device): SignedDescriptor {
    const unsigned = {
      type: SIGNED_DESCRIPTOR_TYPE,
      descriptor_type: descriptorType,
      descriptor,
      signed_by: signer.identity.device_id,
      signed_at: rfc3339Seconds(new Date()),
    }
    return signObject(provider, SIGNED_DESCRIPTOR_TYPE, unsigned, signer.privateKey, signer.identity.public_key.kid) as SignedDescriptor
  }

  issueTicket(overrides?: Partial<Pick<PairingTicket, 'ticket_id'>>): PairingTicket {
    const now = Date.now()
    return signPairingTicket(provider, this.trustSigner, {
      ticket_id: overrides?.ticket_id ?? `tick_${now}_${Math.floor(Math.random() * 1e6)}`,
      domain_id: DOMAIN_ID,
      relay_id: RELAY_ID,
      trust_root_id: TRUST_ROOT_ID,
      max_uses: 1,
      issued_at: rfc3339Seconds(new Date(now)),
      expires_at: rfc3339Seconds(new Date(now + 5 * 60_000)),
    })
  }

  private issueGrant(subjectDeviceId: string, confirmationThumbprint: string): TrustGrant {
    const now = Date.now()
    const tamper = this.grantTamper
    const unsigned = {
      type: TRUST_GRANT_TYPE,
      grant_id: `grant_${now}`,
      issuer: TRUST_ROOT_ID,
      subject_device_id: tamper === 'subject' ? 'dev_someone_else' : subjectDeviceId,
      audience: tamper === 'audience' ? 'dev_wrong_phone' : this.grantAudience,
      confirmation_thumbprint: tamper === 'confirmation' ? 'AAAAAAAAAAAAAAAA' : confirmationThumbprint,
      permissions: ['text'],
      relay_constraints: [RELAY_ID],
      not_before: rfc3339Seconds(new Date(now - 60_000)),
      expires_at: tamper === 'expired' ? rfc3339Seconds(new Date(now - 1_000)) : rfc3339Seconds(new Date(now + 3600_000)),
      revocation_epoch: 0,
    }
    const grant = signObject(provider, TRUST_GRANT_TYPE, unsigned, this.trustSigner.privateKey, this.trustSigner.identity.public_key.kid) as TrustGrant
    if (tamper === 'signature') {
      return { ...grant, permissions: ['text', 'injected'] }
    }
    return grant
  }

  async start(): Promise<void> {
    this.server = createServer((req, res) => {
      const chunks: Buffer[] = []
      req.on('data', (chunk: Buffer) => chunks.push(chunk))
      req.on('end', () => {
        const raw = Buffer.concat(chunks).toString('utf8')
        const { status, body } = this.route(req.method ?? 'GET', req.url ?? '/', raw, req.headers['idempotency-key'] as string | undefined)
        res.writeHead(status, { 'content-type': 'application/json' })
        res.end(body)
      })
    })
    await new Promise<void>((resolve) => this.server.listen(0, '127.0.0.1', resolve))
    const address = this.server.address()
    if (address === null || typeof address === 'string') throw new Error('fixture server failed to bind')
    this.baseUrl = `http://127.0.0.1:${address.port}`
  }

  async stop(): Promise<void> {
    await new Promise<void>((resolve, reject) => this.server.close((err) => (err ? reject(err) : resolve())))
  }

  private route(method: string, url: string, raw: string, idempotencyKey: string | undefined): { status: number; body: string } {
    if (method === 'GET' && url === '/.well-known/iscp/relay') {
      return { status: 200, body: JSON.stringify({ descriptor: this.signedRelayDescriptor() }) }
    }
    if (method === 'GET' && url === '/.well-known/iscp/trust-root') {
      return { status: 200, body: JSON.stringify({ descriptor: this.signedTrustDescriptor() }) }
    }
    if (method === 'POST' && url === '/v2/relay/devices/register-with-ticket') {
      if (idempotencyKey !== undefined) {
        const replay = this.idempotency.get(idempotencyKey)
        if (replay !== undefined) return replay
      }
      const result = this.register(raw)
      if (idempotencyKey !== undefined) this.idempotency.set(idempotencyKey, result)
      return result
    }
    return { status: 404, body: JSON.stringify(error('not_found', 'no route', 'no_route')) }
  }

  private register(raw: string): { status: number; body: string } {
    const body = JSON.parse(raw) as {
      ticket?: PairingTicket
      identity?: DeviceIdentity
      identity_proof?: DeviceProof
      device_type?: string
      device_role?: string
      display_name?: string
    }
    this.lastRegisterBody = body as Record<string, unknown>
    if (!body.ticket) {
      return { status: 400, body: JSON.stringify(error('invalid_request', 'ticket required', 'missing_ticket')) }
    }
    if (!body.identity || !body.identity_proof) {
      return { status: 400, body: JSON.stringify(error('invalid_request', 'identity and identity_proof are required', 'missing_identity_proof')) }
    }
    // Enrollee shape is fixed server-side; conflicting request shapes are rejected.
    if ((body.device_type !== undefined && body.device_type !== 'service_agent') || (body.device_role !== undefined && body.device_role !== 'member_device')) {
      return { status: 400, body: JSON.stringify(error('invalid_request', 'device type or role invalid', 'invalid_device_shape')) }
    }
    try {
      verifyPairingTicket(provider, body.ticket, this.trustSigner.identity.public_key.public)
    } catch {
      return { status: 403, body: JSON.stringify(error('forbidden', 'provisioning ticket invalid', 'ticket_invalid')) }
    }
    if (body.identity.domain_id !== body.ticket.domain_id) {
      return { status: 403, body: JSON.stringify(error('forbidden', 'identity domain does not match ticket', 'ticket_domain_mismatch')) }
    }
    try {
      verifyDeviceProof(provider, body.identity, body.identity_proof, { audience: RELAY_ID, challenge: body.ticket.ticket_id })
    } catch {
      return { status: 401, body: JSON.stringify(error('unauthorized', 'identity possession proof invalid', 'device_proof_invalid')) }
    }
    if (this.nonces.has(body.identity_proof.nonce)) {
      return { status: 409, body: JSON.stringify(error('conflict', 'device proof replay', 'proof_replay_detected')) }
    }
    this.nonces.add(body.identity_proof.nonce)
    if (this.consumed.has(body.ticket.ticket_id)) {
      return { status: 410, body: JSON.stringify(error('not_found', 'provisioning ticket consumed or expired', 'ticket_consumed')) }
    }
    this.consumed.add(body.ticket.ticket_id)

    const officialId = `dev_official_${++this.deviceCounter}`
    const expiresAt = rfc3339Seconds(new Date(Date.now() + 900_000))
    const refreshExpiresAt = rfc3339Seconds(new Date(Date.now() + 86_400_000))
    return {
      status: 201,
      body: JSON.stringify({
        data: {
          device_id: officialId,
          domain_id: body.ticket.domain_id,
          device_type: 'service_agent',
          device_role: 'member_device',
          display_name: body.display_name ?? '',
          public_key_thumbprint: body.identity.public_key.kid,
          trust_state: 'authorized',
        },
        access: { domain_id: body.ticket.domain_id, device_id: officialId, token: `acc_${officialId}`, expires_at: expiresAt },
        refresh: { domain_id: body.ticket.domain_id, device_id: officialId, token: `ref_${officialId}`, expires_at: refreshExpiresAt },
        grant: this.issueGrant(officialId, body.identity.public_key.kid),
      }),
    }
  }
}

function error(code: string, message: string, reason: string) {
  return { error: { code, message, reason, request_id: 'req_fixture', details: {} } }
}

describe('managed enrollment (Cloud v2 signed-ticket contract)', () => {
  const fixture = new CloudFixture()
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
})
