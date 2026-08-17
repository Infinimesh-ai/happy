/**
 * In-process HTTP double of the Infinimesh Cloud managed-provisioning
 * surface, shared by the enrollment/renewal/daemon-peer unit tests:
 *
 *   GET  /.well-known/iscp/relay             signed relay descriptor
 *   GET  /.well-known/iscp/trust-root        signed trust root descriptor
 *   POST /v2/relay/devices/register-with-ticket   v2 signed-ticket contract
 *   POST /v2/relay/devices/renew-grant            frozen renewal contract (OPS 2026-08-17 §4.3)
 *   GET  /v2/trust/devices/status            slice-20 frozen read contract
 *   GET  /v2/trust/grants/status             (InfinimeshCloud docs/30-delivery/
 *   GET  /v2/trust/revocations                20-trust-wire-contract.md)
 *
 * Faithful to the Cloud error envelope ({error:{code,message,reason,...}}),
 * Idempotency-Key replay, proof-nonce replay gating, and one-time consumption
 * of tickets and renewal ids.
 */

import { createServer, type Server } from 'node:http'

import {
  createDevice,
  createNobleProvider,
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

const provider = createNobleProvider()

export type GrantTamper = 'signature' | 'subject' | 'confirmation' | 'audience' | 'expired'

export interface CloudFixtureIds {
  relayId: string
  trustRootId: string
  domainId: string
  /** The default grant audience the fixture issues (the "phone" device). */
  phoneDeviceId: string
}

export interface RenewalFixtureEntry {
  state: 'active' | 'expired' | 'consumed'
  /** When set, the renewal is bound to this device id (mismatch → 403). */
  deviceId?: string
  identityConflict?: boolean
  deviceRevoked?: boolean
}

function error(code: string, message: string, reason: string) {
  return { error: { code, message, reason, request_id: 'req_fixture', details: {} } }
}

/** Minimal but faithful double of the Cloud's v2 signed-ticket + renewal endpoints. */
export class CloudFixture {
  readonly relaySigner: Device
  readonly trustSigner: Device
  server!: Server
  baseUrl = ''
  grantTamper: GrantTamper | undefined
  /** Grant audience the fixture issues (the "phone" device). */
  grantAudience: string
  lastRegisterBody: Record<string, unknown> | undefined
  lastRenewBody: Record<string, unknown> | undefined
  registerCalls = 0
  renewCalls = 0
  /** Renewal ids the Cloud knows about; configure per test. */
  readonly renewals = new Map<string, RenewalFixtureEntry>()
  /** Trust directory served by /v2/trust/devices/status; register() fills it. */
  readonly trustDevices = new Map<string, { identity: DeviceIdentity; status: string }>()
  /** Grants served by /v2/trust/grants/status; issueGrant() fills it. */
  readonly trustGrants = new Map<string, { grant: TrustGrant; status: 'active' | 'revoked' | 'expired' }>()
  /** Items served by /v2/trust/revocations (slice-20 shape); configure per test. */
  revocationItems: Array<Record<string, unknown>> = []
  private readonly consumed = new Set<string>()
  private readonly nonces = new Set<string>()
  private readonly idempotency = new Map<string, { status: number; body: string }>()
  private deviceCounter = 0

  constructor(readonly ids: CloudFixtureIds) {
    this.grantAudience = ids.phoneDeviceId
    this.relaySigner = createDevice(provider, { domainId: 'platform', deviceId: 'relay-signer' })
    this.trustSigner = createDevice(provider, { domainId: 'platform', deviceId: 'trust-signer' })
  }

  signedRelayDescriptor(): SignedDescriptor {
    const descriptor = {
      type: 'iscp.relay.descriptor.v2',
      relay_id: this.ids.relayId,
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
      trust_root_id: this.ids.trustRootId,
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
      domain_id: this.ids.domainId,
      relay_id: this.ids.relayId,
      trust_root_id: this.ids.trustRootId,
      max_uses: 1,
      issued_at: rfc3339Seconds(new Date(now)),
      expires_at: rfc3339Seconds(new Date(now + 5 * 60_000)),
    })
  }

  issueGrant(subjectDeviceId: string, confirmationThumbprint: string): TrustGrant {
    const now = Date.now()
    const tamper = this.grantTamper
    const unsigned = {
      type: TRUST_GRANT_TYPE,
      grant_id: `grant_${now}_${Math.floor(Math.random() * 1e6)}`,
      issuer: this.ids.trustRootId,
      subject_device_id: tamper === 'subject' ? 'dev_someone_else' : subjectDeviceId,
      audience: tamper === 'audience' ? 'dev_wrong_phone' : this.grantAudience,
      confirmation_thumbprint: tamper === 'confirmation' ? 'AAAAAAAAAAAAAAAA' : confirmationThumbprint,
      permissions: ['text'],
      relay_constraints: [this.ids.relayId],
      not_before: rfc3339Seconds(new Date(now - 60_000)),
      expires_at: tamper === 'expired' ? rfc3339Seconds(new Date(now - 1_000)) : rfc3339Seconds(new Date(now + 3600_000)),
      revocation_epoch: 0,
    }
    const grant = signObject(provider, TRUST_GRANT_TYPE, unsigned, this.trustSigner.privateKey, this.trustSigner.identity.public_key.kid) as TrustGrant
    if (tamper === 'signature') {
      return { ...grant, permissions: ['text', 'injected'] }
    }
    this.trustGrants.set(grant.grant_id, { grant, status: 'active' })
    return grant
  }

  /** Make a device (e.g. the audience phone) resolvable via /v2/trust/devices/status. */
  addTrustDevice(identity: DeviceIdentity, status = 'trusted'): void {
    this.trustDevices.set(identity.device_id, { identity, status })
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
    const parsed = new URL(url, 'http://fixture')
    if (method === 'GET' && parsed.pathname === '/v2/trust/devices/status') {
      return this.trustDeviceStatus(parsed.searchParams)
    }
    if (method === 'GET' && parsed.pathname === '/v2/trust/grants/status') {
      return this.trustGrantStatus(parsed.searchParams)
    }
    if (method === 'GET' && parsed.pathname === '/v2/trust/revocations') {
      if ((parsed.searchParams.get('domain_id') ?? '') === '') {
        return { status: 400, body: JSON.stringify(error('invalid_request', 'domain_id is required', 'missing_query')) }
      }
      return { status: 200, body: JSON.stringify({ items: this.revocationItems }) }
    }
    if (method === 'POST' && (url === '/v2/relay/devices/register-with-ticket' || url === '/v2/relay/devices/renew-grant')) {
      if (idempotencyKey !== undefined) {
        const replay = this.idempotency.get(idempotencyKey)
        if (replay !== undefined) return replay
      }
      const result = url === '/v2/relay/devices/register-with-ticket' ? this.register(raw) : this.renew(raw)
      if (idempotencyKey !== undefined) this.idempotency.set(idempotencyKey, result)
      return result
    }
    return { status: 404, body: JSON.stringify(error('not_found', 'no route', 'no_route')) }
  }

  /** Slice-20 frozen shape: flat record + canonical nested identity. */
  private trustDeviceStatus(params: URLSearchParams): { status: number; body: string } {
    const domainId = params.get('domain_id') ?? ''
    const deviceId = params.get('device_id') ?? ''
    if (domainId === '' || deviceId === '') {
      return { status: 400, body: JSON.stringify(error('invalid_request', 'domain_id and device_id are required', 'missing_query')) }
    }
    const entry = this.trustDevices.get(deviceId)
    if (entry === undefined || entry.identity.domain_id !== domainId) {
      return { status: 404, body: JSON.stringify(error('not_found', 'device not found', 'device_not_found')) }
    }
    return {
      status: 200,
      body: JSON.stringify({
        identity: entry.identity,
        domain_id: entry.identity.domain_id,
        device_id: entry.identity.device_id,
        status: entry.status,
        public_key: entry.identity.public_key,
        device_record_version: 1,
        revocation_epoch: entry.status === 'revoked' ? 1 : 0,
      }),
    }
  }

  /** Slice-20 frozen shape: {grant, status} envelope, optional domain scoping. */
  private trustGrantStatus(params: URLSearchParams): { status: number; body: string } {
    const grantId = params.get('grant_id') ?? ''
    if (grantId === '') {
      return { status: 400, body: JSON.stringify(error('invalid_request', 'grant_id is required', 'missing_query')) }
    }
    const entry = this.trustGrants.get(grantId)
    const domainId = params.get('domain_id')
    if (entry === undefined || (domainId !== null && domainId !== this.ids.domainId)) {
      return { status: 404, body: JSON.stringify(error('not_found', 'grant not found', 'grant_not_found')) }
    }
    return { status: 200, body: JSON.stringify({ grant: entry.grant, status: entry.status }) }
  }

  private register(raw: string): { status: number; body: string } {
    this.registerCalls += 1
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
      verifyDeviceProof(provider, body.identity, body.identity_proof, { audience: this.ids.relayId, challenge: body.ticket.ticket_id })
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
    // Cloud re-homes the submitted key under the official device id; the
    // trust directory serves that identity, not the enrollee-side one.
    this.trustDevices.set(officialId, {
      identity: {
        type: 'iscp.device.identity.v2',
        domain_id: body.ticket.domain_id,
        device_id: officialId,
        public_key: body.identity.public_key,
        created_at: rfc3339Seconds(new Date()),
      },
      status: 'trusted',
    })
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

  private renew(raw: string): { status: number; body: string } {
    this.renewCalls += 1
    const body = JSON.parse(raw) as {
      renewal_id?: string
      identity?: DeviceIdentity
      identity_proof?: DeviceProof
    }
    this.lastRenewBody = body as Record<string, unknown>
    if (!body.renewal_id || !body.identity || !body.identity_proof) {
      return { status: 400, body: JSON.stringify(error('invalid_request', 'renewal_id, identity and identity_proof are required', 'missing_renewal_fields')) }
    }
    try {
      verifyDeviceProof(provider, body.identity, body.identity_proof, { audience: this.ids.relayId, challenge: body.renewal_id })
    } catch {
      return { status: 401, body: JSON.stringify(error('unauthorized', 'identity possession proof invalid', 'device_proof_invalid')) }
    }
    if (this.nonces.has(body.identity_proof.nonce)) {
      return { status: 409, body: JSON.stringify(error('conflict', 'device proof replay', 'proof_replay_detected')) }
    }
    this.nonces.add(body.identity_proof.nonce)
    const entry = this.renewals.get(body.renewal_id)
    if (entry === undefined) {
      return { status: 404, body: JSON.stringify(error('not_found', 'renewal id unknown', 'renewal_not_found')) }
    }
    if (entry.state === 'expired') {
      return { status: 410, body: JSON.stringify(error('gone', 'renewal id expired', 'renewal_expired')) }
    }
    if (entry.state === 'consumed') {
      return { status: 410, body: JSON.stringify(error('gone', 'renewal id already used', 'renewal_consumed')) }
    }
    if (entry.deviceRevoked === true) {
      return { status: 403, body: JSON.stringify(error('forbidden', 'device revoked', 'device_revoked')) }
    }
    if (entry.deviceId !== undefined && entry.deviceId !== body.identity.device_id) {
      return { status: 403, body: JSON.stringify(error('forbidden', 'renewal issued for a different device', 'renewal_device_mismatch')) }
    }
    if (entry.identityConflict === true) {
      return { status: 409, body: JSON.stringify(error('conflict', 'conflicting identity registered for this device', 'renewal_identity_conflict')) }
    }
    entry.state = 'consumed'
    return {
      status: 201,
      body: JSON.stringify({
        data: { device_id: body.identity.device_id, domain_id: body.identity.domain_id },
        grant: this.issueGrant(body.identity.device_id, body.identity.public_key.kid),
      }),
    }
  }
}
