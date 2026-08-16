/**
 * ISCP enrollment for happy-cli (Phase 2 slice of the dual-stack plan).
 *
 * Enrolls this machine as an ISCP device against a relay + trust root and
 * persists the resulting profile under ~/.happy/iscp/<profileId>/:
 *
 *   device.key    0600  Ed25519 identity seed (never leaves this machine)
 *   bundle.json   0600  descriptors, pins, credentials, trust grant
 *
 * Layout is namespaced per profile so ISCP state never touches legacy
 * ~/.happy files, and legacy logout never touches ISCP state
 * (docs/network-dual-stack/inventory.md isolation contract).
 *
 * Against the reference services (local-lab) the CLI can play the operator
 * and self-authorize; against a gated trust root it polls for authorization
 * and expects the operator to compare the printed device confirmation code
 * out of band before approving.
 */

import { chmodSync, mkdirSync, writeFileSync, readFileSync, readdirSync, statSync, existsSync } from 'node:fs'
import { join } from 'node:path'

import {
  createDevice,
  createNobleProvider,
  decodeEnrollmentFromTransport,
  descriptorPin,
  deviceFromStored,
  Ed25519PrivateKey,
  enrollmentPayloadFromObject,
  fromBase64Url,
  grantSigningKey,
  identityThumbprint,
  IscpError,
  RelayHttpClient,
  toBase64Url,
  TrustRootClient,
  utf8Encode,
  verifyGrant,
  verifyPairingTicket,
  verifyRelayDescriptor,
  verifyTrustRootDescriptor,
  type CryptoProvider,
  type Device,
  type DeviceIdentity,
  type EnrollmentTransportPayload,
  type SignedDescriptor,
  type TrustGrant,
  type TrustRootDescriptor,
} from '@slopus/iscp'

import { configuration } from '@/configuration'

/** Everything a Phase 3 transport needs to come online as this device. */
export interface IscpProfileBundle {
  version: 1
  profile_id: string
  domain_id: string
  relay_id: string
  trust_root_id: string
  relay_descriptor: SignedDescriptor
  relay_pin: string
  trust_root_descriptor: SignedDescriptor
  trust_root_pin: string
  device_identity: DeviceIdentity
  access_credential: { token: string; expires_at: string }
  refresh_credential: { token: string; expires_at: string }
  trust_grant: TrustGrant
  enrolled_at: string
}

export interface EnrollOptions {
  relayUrl: string
  trustUrl: string
  relayId: string
  trustRootId: string
  /**
   * ISCP domain id. Optional in ticket mode (the signed ticket carries the
   * authoritative domain_id); required for the local-lab bind-self flow.
   */
  domainId?: string
  /**
   * Enrollment payload: base64url wrapper or bare ticket (QR/deep-link/copy
   * string from Console/JingSi), raw JSON, or a path to a JSON file.
   */
  ticket?: string
  deviceId?: string
  profileId?: string
  /** Display name registered with the Cloud (ticket mode only). */
  displayName?: string
  /** Print progress lines (device confirmation code etc.). Never prints secrets. */
  log: (line: string) => void
}

export function iscpProfileDir(profileId: string): string {
  return join(configuration.happyHomeDir, 'iscp', profileId)
}

export function readProfileBundle(profileId: string): IscpProfileBundle | null {
  const file = join(iscpProfileDir(profileId), 'bundle.json')
  if (!existsSync(file)) return null
  return JSON.parse(readFileSync(file, 'utf8')) as IscpProfileBundle
}

export function readProfileDevice(provider: CryptoProvider, profileId: string): Device | null {
  const bundle = readProfileBundle(profileId)
  const keyFile = join(iscpProfileDir(profileId), 'device.key')
  if (!bundle || !existsSync(keyFile)) return null
  const stored = JSON.parse(readFileSync(keyFile, 'utf8')) as { seed: string }
  return deviceFromStored(provider, bundle.device_identity, new Ed25519PrivateKey(fromBase64Url(stored.seed)))
}

export function listProfiles(): string[] {
  const root = join(configuration.happyHomeDir, 'iscp')
  if (!existsSync(root)) return []
  return readdirSync(root).filter((entry: string) => {
    try {
      return statSync(join(root, entry)).isDirectory() && existsSync(join(root, entry, 'bundle.json'))
    } catch {
      return false
    }
  })
}

/**
 * Parse an enrollment input: a path to a JSON file, raw JSON, or the
 * base64url transport string — each either a bare signed ticket or the
 * Console/JingSi `iscp_enrollment_wrapper`.
 */
export function parseEnrollmentInput(input: string): EnrollmentTransportPayload {
  if (existsSync(input)) {
    return enrollmentPayloadFromObject(JSON.parse(readFileSync(input, 'utf8')))
  }
  if (input.trimStart().startsWith('{')) {
    return enrollmentPayloadFromObject(JSON.parse(input))
  }
  return decodeEnrollmentFromTransport(input)
}

/**
 * Client-side ticket validation before consumption: bound to the discovered
 * relay/trust root, signed by an active trust root key, inside its window.
 */
function verifyTicketAgainstDescriptors(
  provider: CryptoProvider,
  payload: EnrollmentTransportPayload,
  opts: { relayId: string; trustRootId: string; relayDescriptorRelayId: string; trustDescriptor: TrustRootDescriptor },
): void {
  const ticket = payload.ticket
  if (ticket.relay_id !== opts.relayId || ticket.relay_id !== opts.relayDescriptorRelayId) {
    throw new Error(`pairing ticket is bound to relay ${ticket.relay_id}, but this enrollment targets ${opts.relayId} (descriptor: ${opts.relayDescriptorRelayId})`)
  }
  if (ticket.trust_root_id !== opts.trustRootId || ticket.trust_root_id !== opts.trustDescriptor.trust_root_id) {
    throw new Error(`pairing ticket is bound to trust root ${ticket.trust_root_id}, but this enrollment targets ${opts.trustRootId} (descriptor: ${opts.trustDescriptor.trust_root_id})`)
  }
  const signingKey = opts.trustDescriptor.keys.find((k) => k.kid === ticket.signature.kid && k.state !== 'revoked' && k.state !== 'next')
  if (!signingKey) {
    throw new Error('pairing ticket is not signed by an active trust root key')
  }
  verifyPairingTicket(provider, ticket, signingKey.public)
}

/**
 * Six-digit device confirmation code derived from the identity thumbprint.
 * The operator authorizing this device compares it out of band (same shape
 * as the Local Secure Channel OOB code, but bound to the long-term identity
 * instead of an ephemeral channel).
 */
export function deviceConfirmationCode(provider: CryptoProvider, identity: DeviceIdentity): string {
  const digest = provider.sha256(utf8Encode(`iscp/happy/device-confirmation\0${identity.public_key.kid}`))
  const view = new DataView(digest.buffer, digest.byteOffset, digest.byteLength)
  return (view.getUint32(0) % 1_000_000).toString().padStart(6, '0')
}

function persistProfile(profileId: string, device: Device, bundle: IscpProfileBundle): string {
  const dir = iscpProfileDir(profileId)
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  chmodSync(dir, 0o700)
  const keyFile = join(dir, 'device.key')
  writeFileSync(keyFile, JSON.stringify({ warning: 'ISCP device identity seed; never share', seed: toBase64Url(device.privateKey.bytes) }, null, 2), { mode: 0o600 })
  chmodSync(keyFile, 0o600)
  const bundleFile = join(dir, 'bundle.json')
  writeFileSync(bundleFile, JSON.stringify(bundle, null, 2), { mode: 0o600 })
  chmodSync(bundleFile, 0o600)
  return dir
}

/** Persist rotated relay credentials back into the profile bundle (0600). */
export function updateProfileCredentials(profileId: string, credentials: { accessToken: string; refreshToken: string }): void {
  const bundle = readProfileBundle(profileId)
  if (!bundle) return
  bundle.access_credential = { ...bundle.access_credential, token: credentials.accessToken }
  bundle.refresh_credential = { ...bundle.refresh_credential, token: credentials.refreshToken }
  const file = join(iscpProfileDir(profileId), 'bundle.json')
  writeFileSync(file, JSON.stringify(bundle, null, 2), { mode: 0o600 })
  chmodSync(file, 0o600)
}

export async function enroll(opts: EnrollOptions): Promise<{ profileId: string; dir: string; bundle: IscpProfileBundle }> {
  const provider = createNobleProvider()
  const { log } = opts

  // 0. Resolve the enrollment payload; the signed ticket carries the
  //    authoritative domain_id (--domain stays optional in ticket mode).
  const payload = opts.ticket !== undefined ? parseEnrollmentInput(opts.ticket) : undefined
  if (payload !== undefined && opts.domainId !== undefined && payload.ticket.domain_id !== opts.domainId) {
    throw new Error(`pairing ticket is for domain ${payload.ticket.domain_id}, not ${opts.domainId}`)
  }
  const domainId = payload?.ticket.domain_id ?? opts.domainId
  if (domainId === undefined) {
    throw new Error('a domain id is required when enrolling without a pairing ticket (--domain)')
  }

  // 1. Discover and verify both services; record pins.
  const relayHttp = new RelayHttpClient({ baseUrl: opts.relayUrl, relayId: opts.relayId, provider })
  const trustRoot = new TrustRootClient({ baseUrl: opts.trustUrl, trustRootId: opts.trustRootId, provider })
  const { descriptor: signedRelay } = await relayHttp.fetchSignedDescriptor()
  const relayDescriptor = verifyRelayDescriptor(provider, signedRelay)
  const signedTrust = await trustRoot.fetchSignedDescriptor()
  const trustDescriptor = verifyTrustRootDescriptor(provider, signedTrust)
  log(`Relay:      ${relayDescriptor.relay_id} (${relayDescriptor.base_url})`)
  log(`Trust root: ${trustDescriptor.trust_root_id} (${trustDescriptor.base_url})`)

  // 1b. Ticket mode: verify the ticket client-side BEFORE consuming it —
  //     signature against an active trust root key, validity window, and
  //     binding to exactly this relay/trust root pair.
  if (payload !== undefined) {
    verifyTicketAgainstDescriptors(provider, payload, {
      relayId: opts.relayId,
      trustRootId: opts.trustRootId,
      relayDescriptorRelayId: relayDescriptor.relay_id,
      trustDescriptor,
    })
    log(`Ticket:     ${payload.ticket.ticket_id} verified (domain ${payload.ticket.domain_id}, expires ${payload.ticket.expires_at})`)
  }

  // 2. Generate the device identity locally. The seed is written only to
  //    device.key (0600) at the end; it never travels. In ticket mode the
  //    device id is provisional — the Cloud assigns the official dev_ id.
  const deviceId = opts.deviceId ?? `happy-cli-${toBase64Url(provider.randomBytes(9))}`
  let device = createDevice(provider, { domainId, deviceId })
  const thumbprint = identityThumbprint(provider, device.identity)
  log(`Device id:  ${deviceId}${payload !== undefined ? ' (provisional; the Cloud assigns the official id)' : ''}`)
  log(`Thumbprint: ${thumbprint}`)
  log('')
  log(`  Device confirmation code: ${deviceConfirmationCode(provider, device.identity)}`)
  log('  Compare this code out of band before the operator authorizes the device.')
  log('')

  let credentials: { access: { token?: string; expires_at: string }; refresh: { token?: string; expires_at: string } }
  let grant: TrustGrant

  if (payload !== undefined) {
    // 3. Managed provisioning (Infinimesh Cloud v2 signed-ticket contract):
    //    one call registers the device, issues relay credentials, and returns
    //    the pre-authorized Trust Grant. No trust self-authorization here.
    const registration = await relayHttp.registerWithSignedTicket(device, payload.ticket, {
      displayName: payload.displayName ?? opts.displayName,
      metadata: { product_kind: 'happy', runtime_kind: 'happy-cli' },
    })
    log(`Relay access granted via pairing ticket ${payload.ticket.ticket_id}`)
    log(`Official device id: ${registration.data.device_id} (domain ${registration.data.domain_id})`)

    // Rebuild the identity around the official ids before anything persists;
    // deviceFromStored re-validates that the key pair matches.
    const officialIdentity: DeviceIdentity = {
      ...device.identity,
      domain_id: registration.data.domain_id,
      device_id: registration.data.device_id,
    }
    device = deviceFromStored(provider, officialIdentity, device.privateKey)

    // 4. Verify the returned grant before it ever touches disk: signed by an
    //    active trust root key, subject = our official id, confirmation = our
    //    key thumbprint, constrained to this relay, inside its window.
    grant = registration.grant
    verifyGrant(provider, grant, grantSigningKey(trustDescriptor, grant.signature.kid), {
      audience: payload.expectedAudiencePhoneId ?? grant.audience,
      subjectDeviceId: device.identity.device_id,
      confirmationThumbprint: device.identity.public_key.kid,
      permission: grant.permissions[0] ?? 'text',
      relayId: opts.relayId,
    })
    if (payload.expectedAudiencePhoneId !== undefined) {
      log(`Trust grant verified; audience matches expected phone ${payload.expectedAudiencePhoneId}`)
    } else {
      log('Trust grant verified.')
      log('')
      log(`  >>> Grant audience (the phone allowed to control this machine): ${grant.audience}`)
      log('  >>> Confirm this device id on the phone before using the profile.')
      log('')
    }
    credentials = { access: registration.access, refresh: registration.refresh }
  } else {
    // 3. Local-lab dev flow: bind-self, then trust self-authorization (the
    //    reference services leave the operator endpoint open).
    credentials = await relayHttp.bindSelf(device)
    log('Relay access granted via bind-self (no ticket; local-lab dev flow)')

    await trustRoot.submitDevice(device)
    log('Device submitted to trust root')
    try {
      const authorized = await trustRoot.authorizeDevice({
        deviceId,
        audience: domainId,
        permissions: ['text'],
        relayId: opts.relayId,
        ttlSeconds: 3600,
      })
      grant = authorized.grant
      log('Device authorized (local-lab self-authorization)')
    } catch (error) {
      if (!(error instanceof IscpError && error.code === 'ISCPACCESS001')) throw error
      log('Trust root requires an operator. Waiting for authorization...')
      await trustRoot.waitForAuthorization(deviceId, { intervalMs: 2000, timeoutMs: 10 * 60 * 1000 })
      // Reference trust roots expose no device-facing grant fetch; the
      // operator must deliver the grant (Provisioning Bundle path, Phase 3+).
      throw new Error('device authorized, but this trust root delivers grants only via a provisioning bundle; re-run with a bundle once issued')
    }
  }

  // 5. Persist the profile bundle (only after every verification passed —
  //    a failed enrollment leaves no partial files behind).
  const profileId = opts.profileId ?? `${device.identity.domain_id}-${opts.relayId}`
  const bundle: IscpProfileBundle = {
    version: 1,
    profile_id: profileId,
    domain_id: device.identity.domain_id,
    relay_id: opts.relayId,
    trust_root_id: opts.trustRootId,
    relay_descriptor: signedRelay,
    relay_pin: descriptorPin(provider, signedRelay),
    trust_root_descriptor: signedTrust,
    trust_root_pin: descriptorPin(provider, signedTrust),
    device_identity: device.identity,
    access_credential: { token: credentials.access.token as string, expires_at: credentials.access.expires_at },
    refresh_credential: { token: credentials.refresh.token as string, expires_at: credentials.refresh.expires_at },
    trust_grant: grant,
    enrolled_at: new Date().toISOString(),
  }
  const dir = persistProfile(profileId, device, bundle)
  log('')
  log(`Enrolled. Profile stored at ${dir}`)
  log(`Grant ${grant.grant_id} (permissions: ${grant.permissions.join(', ')}) expires ${grant.expires_at}`)
  return { profileId, dir, bundle }
}
