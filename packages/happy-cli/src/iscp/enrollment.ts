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
 * Identity persistence invariants (OPS 2026-08-17 §4.1):
 * - One install + domain + relay pair owns exactly one active managed
 *   profile with one long-lived device key. A healthy profile is NEVER
 *   silently replaced: enrollment refuses before consuming the ticket
 *   unless --replace is passed explicitly.
 * - --replace keeps the old profile directory as a
 *   `<dir>.replaced-<ISO timestamp>` backup (never auto-deleted).
 * - Every profile write is atomic (temp file/dir + rename) and guarded by a
 *   per-profile lock file, so a crash at any point leaves either the old or
 *   the new profile fully intact — never a mixed state.
 *
 * Against the reference services (local-lab) the CLI can play the operator
 * and self-authorize; against a gated trust root it polls for authorization
 * and expects the operator to compare the printed device confirmation code
 * out of band before approving.
 */

import { chmodSync, mkdirSync, writeFileSync, readFileSync, readdirSync, statSync, existsSync, linkSync, unlinkSync, renameSync, rmSync } from 'node:fs'
import { randomBytes } from 'node:crypto'
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
import { daemonPost } from '@/daemon/controlClient'

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
  /**
   * Identity/grant generation counter. Bumped on every --replace enrollment
   * and every grant renewal. Absent on pre-generation production bundles,
   * which read as generation 1.
   */
  generation?: number
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
  /**
   * Explicitly replace an existing (healthy or corrupt) profile: the old
   * directory is kept as a `.replaced-<ISO>` backup and a NEW device key is
   * generated. Without this flag, enrollment refuses to touch an existing
   * profile and the ticket is never consumed.
   */
  replace?: boolean
  /** Print progress lines (device confirmation code etc.). Never prints secrets. */
  log: (line: string) => void
}

export function iscpProfileDir(profileId: string): string {
  return join(configuration.happyHomeDir, 'iscp', profileId)
}

/** Read a profile bundle; null when absent OR unreadable (corrupt JSON). */
export function readProfileBundle(profileId: string): IscpProfileBundle | null {
  const file = join(iscpProfileDir(profileId), 'bundle.json')
  if (!existsSync(file)) return null
  try {
    return JSON.parse(readFileSync(file, 'utf8')) as IscpProfileBundle
  } catch {
    return null
  }
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
    // Skip lock bookkeeping, in-flight atomic writes, and --replace backups.
    if (entry === '.locks' || entry.includes('.tmp-') || entry.includes('.replaced-')) return false
    try {
      return statSync(join(root, entry)).isDirectory() && existsSync(join(root, entry, 'bundle.json'))
    } catch {
      return false
    }
  })
}

// ---------------------------------------------------------------------------
// Profile inspection (persistent-identity state machine)
// ---------------------------------------------------------------------------

export type ProfileInspection =
  | { state: 'absent' }
  | { state: 'healthy'; bundle: IscpProfileBundle; device: Device }
  | { state: 'corrupt'; reason: string }

/**
 * Classify the on-disk state of a profile. `corrupt` covers every partial or
 * inconsistent state: a missing bundle or key, unparseable JSON, or a key
 * that does not match the recorded device identity.
 */
export function inspectProfile(provider: CryptoProvider, profileId: string): ProfileInspection {
  const dir = iscpProfileDir(profileId)
  const bundleFile = join(dir, 'bundle.json')
  const keyFile = join(dir, 'device.key')
  if (!existsSync(dir)) return { state: 'absent' }
  const hasBundle = existsSync(bundleFile)
  const hasKey = existsSync(keyFile)
  if (!hasBundle && !hasKey) {
    return { state: 'corrupt', reason: 'profile directory exists but contains neither bundle.json nor device.key' }
  }
  if (!hasBundle) return { state: 'corrupt', reason: 'bundle.json is missing (device.key is present without it)' }
  if (!hasKey) return { state: 'corrupt', reason: 'device.key is missing (bundle.json is present without it)' }

  let bundle: IscpProfileBundle
  try {
    bundle = JSON.parse(readFileSync(bundleFile, 'utf8')) as IscpProfileBundle
  } catch {
    return { state: 'corrupt', reason: 'bundle.json is not valid JSON' }
  }
  if (typeof bundle !== 'object' || bundle === null || bundle.device_identity === undefined || bundle.trust_grant === undefined) {
    return { state: 'corrupt', reason: 'bundle.json is missing required fields (device_identity/trust_grant)' }
  }

  let seed: Uint8Array
  try {
    const stored = JSON.parse(readFileSync(keyFile, 'utf8')) as { seed?: unknown }
    if (typeof stored.seed !== 'string') throw new Error('missing seed')
    seed = fromBase64Url(stored.seed)
  } catch {
    return { state: 'corrupt', reason: 'device.key is unreadable or has no seed' }
  }
  try {
    const device = deviceFromStored(provider, bundle.device_identity, new Ed25519PrivateKey(seed))
    return { state: 'healthy', bundle, device }
  } catch {
    return { state: 'corrupt', reason: 'device.key does not match the device identity recorded in bundle.json' }
  }
}

// ---------------------------------------------------------------------------
// Per-profile mutation lock
// ---------------------------------------------------------------------------

function profileLockFile(profileId: string): string {
  return join(configuration.happyHomeDir, 'iscp', '.locks', `${profileId}.lock`)
}

/**
 * Acquire the per-profile mutation lock (~/.happy/iscp/.locks/<id>.lock).
 * Creation is atomic INCLUDING the pid payload (hard-link O_EXCL pattern,
 * same as acquireDaemonLock in persistence.ts): the lock file never exists
 * empty, so a lock whose pid is dead is unambiguously stale and reclaimed
 * exactly once. Returns the release function.
 */
export function acquireProfileLock(profileId: string): () => void {
  const lockFile = profileLockFile(profileId)
  mkdirSync(join(configuration.happyHomeDir, 'iscp', '.locks'), { recursive: true, mode: 0o700 })
  const tryAcquire = (): (() => void) | null => {
    const tempPath = `${lockFile}.${process.pid}.tmp`
    try {
      writeFileSync(tempPath, String(process.pid), { mode: 0o600 })
      linkSync(tempPath, lockFile)
      return () => {
        try {
          unlinkSync(lockFile)
        } catch {
          /* already released */
        }
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'EEXIST') return null
      throw error
    } finally {
      try {
        unlinkSync(tempPath)
      } catch {
        /* temp never created */
      }
    }
  }

  const first = tryAcquire()
  if (first) return first

  // Lock exists — stale (dead pid / unreadable) locks are reclaimed once.
  let holderPid: number | undefined
  try {
    const parsed = Number(readFileSync(lockFile, 'utf8').trim())
    if (Number.isSafeInteger(parsed) && parsed > 0) holderPid = parsed
  } catch {
    /* raced with a release; treated as stale below */
  }
  let holderAlive = false
  if (holderPid !== undefined) {
    try {
      process.kill(holderPid, 0)
      holderAlive = true
    } catch {
      /* dead */
    }
  }
  if (holderAlive) {
    throw new Error(`another ISCP enrollment/renewal for profile "${profileId}" is already in progress (pid ${holderPid}); wait for it to finish and retry`)
  }
  try {
    unlinkSync(lockFile)
  } catch {
    /* raced */
  }
  const second = tryAcquire()
  if (second) return second
  throw new Error(`another ISCP enrollment/renewal for profile "${profileId}" grabbed the lock; retry in a moment`)
}

export async function withProfileLock<T>(profileId: string, fn: () => Promise<T>): Promise<T> {
  const release = acquireProfileLock(profileId)
  try {
    return await fn()
  } finally {
    release()
  }
}

// ---------------------------------------------------------------------------
// Enrollment input parsing + client-side ticket verification
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Atomic persistence
// ---------------------------------------------------------------------------

function writeProfileFiles(dir: string, device: Device, bundle: IscpProfileBundle): void {
  const keyFile = join(dir, 'device.key')
  writeFileSync(keyFile, JSON.stringify({ warning: 'ISCP device identity seed; never share', seed: toBase64Url(device.privateKey.bytes) }, null, 2), { mode: 0o600 })
  chmodSync(keyFile, 0o600)
  const bundleFile = join(dir, 'bundle.json')
  writeFileSync(bundleFile, JSON.stringify(bundle, null, 2), { mode: 0o600 })
  chmodSync(bundleFile, 0o600)
}

/**
 * Atomically persist a full profile: everything is written into a sibling
 * temp directory and renamed into place. When the target already exists
 * (--replace) the old directory is first renamed to a
 * `<dir>.replaced-<ISO timestamp>` backup — a crash between the two renames
 * leaves the old profile fully intact under the backup name.
 */
function persistProfile(profileId: string, device: Device, bundle: IscpProfileBundle): { dir: string; backupDir?: string } {
  const dir = iscpProfileDir(profileId)
  mkdirSync(join(configuration.happyHomeDir, 'iscp'), { recursive: true, mode: 0o700 })
  const tmpDir = `${dir}.tmp-${process.pid}-${randomBytes(6).toString('hex')}`
  mkdirSync(tmpDir, { mode: 0o700 })
  chmodSync(tmpDir, 0o700)
  try {
    writeProfileFiles(tmpDir, device, bundle)
    let backupDir: string | undefined
    if (existsSync(dir)) {
      backupDir = `${dir}.replaced-${new Date().toISOString()}`
      renameSync(dir, backupDir)
    }
    renameSync(tmpDir, dir)
    return { dir, backupDir }
  } catch (error) {
    try {
      rmSync(tmpDir, { recursive: true, force: true })
    } catch {
      /* best effort */
    }
    throw error
  }
}

/** Atomically replace bundle.json (temp file + rename, 0600). */
function writeBundleAtomic(profileId: string, bundle: IscpProfileBundle): void {
  const file = join(iscpProfileDir(profileId), 'bundle.json')
  const tempPath = `${file}.tmp-${process.pid}-${randomBytes(6).toString('hex')}`
  writeFileSync(tempPath, JSON.stringify(bundle, null, 2), { mode: 0o600 })
  chmodSync(tempPath, 0o600)
  renameSync(tempPath, file)
}

/** Persist rotated relay credentials back into the profile bundle (0600, locked, atomic). */
export function updateProfileCredentials(profileId: string, credentials: { accessToken: string; refreshToken: string }): void {
  const release = acquireProfileLock(profileId)
  try {
    const bundle = readProfileBundle(profileId)
    if (!bundle) return
    bundle.access_credential = { ...bundle.access_credential, token: credentials.accessToken }
    bundle.refresh_credential = { ...bundle.refresh_credential, token: credentials.refreshToken }
    writeBundleAtomic(profileId, bundle)
  } finally {
    release()
  }
}

/** Best-effort: ask a running daemon to hot-reload its ISCP peers. Never fatal. */
async function notifyDaemonReload(log: (line: string) => void): Promise<void> {
  try {
    const result = (await daemonPost('/iscp/reload')) as { error?: string; profiles?: string[] }
    if (result?.error !== undefined) {
      log(`Daemon not reloaded (${result.error}); restart the happy daemon to apply the change.`)
    } else {
      log('Daemon reloaded its ISCP profiles.')
    }
  } catch {
    log('Daemon not reloaded; restart the happy daemon to apply the change.')
  }
}

function bestEffortPreviousGeneration(profileId: string): number {
  try {
    const raw = JSON.parse(readFileSync(join(iscpProfileDir(profileId), 'bundle.json'), 'utf8')) as { generation?: unknown }
    return typeof raw.generation === 'number' ? raw.generation : 1
  } catch {
    return 0
  }
}

// ---------------------------------------------------------------------------
// Enrollment
// ---------------------------------------------------------------------------

export async function enroll(opts: EnrollOptions): Promise<{ profileId: string; dir: string; bundle: IscpProfileBundle; backupDir?: string }> {
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

  // 0b. Persistent-identity gate — BEFORE any network traffic, so a refused
  //     enrollment never consumes the ticket and never registers a device.
  const targetProfileId = opts.profileId ?? `${domainId}-${opts.relayId}`
  return withProfileLock(targetProfileId, async () => {
    const inspection = inspectProfile(provider, targetProfileId)
    if (inspection.state === 'healthy' && opts.replace !== true) {
      const existing = inspection.bundle
      throw new Error([
        `ISCP profile "${targetProfileId}" already exists and is healthy — enrollment refused so the ticket stays unconsumed and this machine keeps its device identity.`,
        `  device:        ${existing.device_identity.device_id}`,
        `  thumbprint:    ${identityThumbprint(provider, existing.device_identity)}`,
        `  grant expires: ${existing.trust_grant.expires_at}`,
        'Next steps:',
        `  happy iscp status ${targetProfileId} --check   # inspect the existing profile`,
        '  happy iscp renew <renewal-id>                # if the grant is expiring or expired',
        '  happy iscp enroll --replace ...              # explicitly replace the device identity (old profile kept as a backup)',
      ].join('\n'))
    }
    if (inspection.state === 'corrupt' && opts.replace !== true) {
      throw new Error(`ISCP profile "${targetProfileId}" is corrupt: ${inspection.reason}. Re-run with --replace to explicitly replace it (the old profile directory is kept as a backup).`)
    }
    const previousGeneration = inspection.state === 'healthy'
      ? (inspection.bundle.generation ?? 1)
      : inspection.state === 'corrupt'
        ? bestEffortPreviousGeneration(targetProfileId)
        : 0
    const generation = previousGeneration + 1

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
    log(`Device id:  ${deviceId}${payload !== undefined ? ' (provisional; the Cloud assigns the official id)' : ''}`)
    log(`Thumbprint: ${identityThumbprint(provider, device.identity)}`)
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
    const bundle: IscpProfileBundle = {
      version: 1,
      profile_id: targetProfileId,
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
      generation,
    }
    const { dir, backupDir } = persistProfile(targetProfileId, device, bundle)
    log('')
    log(`Enrolled. Profile stored at ${dir}`)
    if (backupDir !== undefined) {
      log(`Previous profile kept as a backup at ${backupDir} (not auto-deleted)`)
    }
    log(`  device:      ${device.identity.device_id}`)
    log(`  thumbprint:  ${identityThumbprint(provider, device.identity)}`)
    log(`  generation:  ${generation}`)
    log(`  grant:       ${grant.grant_id} (permissions: ${grant.permissions.join(', ')})`)
    log(`  audience:    ${grant.audience}`)
    log(`  expires:     ${grant.expires_at}`)
    log(`Next: happy iscp status ${targetProfileId} --check`)
    await notifyDaemonReload(log)
    return { profileId: targetProfileId, dir, bundle, backupDir }
  })
}

// ---------------------------------------------------------------------------
// Grant renewal (frozen contract, OPS 2026-08-17 §4.3)
// ---------------------------------------------------------------------------

export interface RenewOptions {
  profileId: string
  renewalId: string
  /** Override the relay base URL (defaults to the enrolled relay descriptor). */
  relayUrl?: string
  /** Override the trust root base URL (defaults to the enrolled trust descriptor). */
  trustUrl?: string
  relayId?: string
  trustRootId?: string
  log: (line: string) => void
}

const RENEWAL_REASON_HINTS: Record<string, string> = {
  renewal_not_found: 'the renewal id is unknown — check the id issued by the Console/JingSi',
  renewal_expired: 'the renewal id has expired — request a fresh one from the Console/JingSi',
  renewal_consumed: 'the renewal id was already used — request a fresh one from the Console/JingSi',
  renewal_device_mismatch: 'this renewal id was issued for a different device',
  renewal_identity_conflict: 'the Cloud holds a conflicting identity for this device; if this machine was re-provisioned, run "happy iscp enroll --replace" with a fresh enrollment ticket',
  device_revoked: 'this device has been revoked by the Cloud; renewal is not possible',
  device_proof_invalid: 'the device possession proof was rejected — the local key may not match the Cloud registration',
  proof_replay_detected: 'the possession proof was replayed — retry to generate a fresh proof',
}

/**
 * Renew the trust grant of a healthy profile in place. The device key and
 * identity NEVER change here — only `trust_grant` (and the generation
 * counter) are updated, atomically. Any failure leaves the old bundle
 * byte-for-byte intact.
 */
export async function renewProfileGrant(opts: RenewOptions): Promise<{ profileId: string; bundle: IscpProfileBundle }> {
  const provider = createNobleProvider()
  const { log } = opts
  return withProfileLock(opts.profileId, async () => {
    const inspection = inspectProfile(provider, opts.profileId)
    if (inspection.state === 'absent') {
      throw new Error(`ISCP profile "${opts.profileId}" is not enrolled; run: happy iscp enroll`)
    }
    if (inspection.state === 'corrupt') {
      throw new Error(`ISCP profile "${opts.profileId}" is corrupt: ${inspection.reason}. Renewal needs a healthy profile; use "happy iscp enroll --replace" with a fresh enrollment ticket instead.`)
    }
    const { bundle, device } = inspection
    const relayId = opts.relayId ?? bundle.relay_id
    const trustRootId = opts.trustRootId ?? bundle.trust_root_id
    const enrolledRelay = verifyRelayDescriptor(provider, bundle.relay_descriptor, { now: new Date(bundle.enrolled_at) })
    const relayHttp = new RelayHttpClient({ baseUrl: opts.relayUrl ?? enrolledRelay.base_url, relayId, provider })

    // Prefer a fresh trust descriptor (the grant may be signed by a rotated
    // key); fall back to the enrolled descriptor when the trust root is
    // unreachable.
    const enrolledTrust = verifyTrustRootDescriptor(provider, bundle.trust_root_descriptor, { now: new Date(bundle.enrolled_at) })
    let trustDescriptor: TrustRootDescriptor = enrolledTrust
    try {
      const trustClient = new TrustRootClient({ baseUrl: opts.trustUrl ?? enrolledTrust.base_url, trustRootId, provider })
      trustDescriptor = verifyTrustRootDescriptor(provider, await trustClient.fetchSignedDescriptor())
    } catch {
      log('Trust root unreachable for a fresh descriptor; verifying against the enrolled descriptor.')
    }

    log(`Renewing grant for device ${device.identity.device_id} (profile ${opts.profileId})`)
    let renewal
    try {
      renewal = await relayHttp.renewGrant(device, opts.renewalId)
    } catch (error) {
      if (error instanceof IscpError && typeof error.details?.reason === 'string') {
        const hint = RENEWAL_REASON_HINTS[error.details.reason]
        if (hint !== undefined) {
          throw new Error(`grant renewal failed (${error.details.reason}): ${hint}`, { cause: error })
        }
      }
      throw error
    }
    if (renewal.data.device_id !== device.identity.device_id || renewal.data.domain_id !== device.identity.domain_id) {
      throw new Error('grant renewal returned a different device identity; refusing to touch the local profile')
    }

    // Verify the new grant before it touches disk. The audience MUST equal
    // the enrolled grant's audience — an audience drift is rejected outright.
    const grant = renewal.grant
    verifyGrant(provider, grant, grantSigningKey(trustDescriptor, grant.signature.kid), {
      audience: bundle.trust_grant.audience,
      subjectDeviceId: device.identity.device_id,
      confirmationThumbprint: device.identity.public_key.kid,
      permission: grant.permissions[0] ?? 'text',
      relayId,
    })

    const updated: IscpProfileBundle = {
      ...bundle,
      trust_grant: grant,
      generation: (bundle.generation ?? 1) + 1,
    }
    writeBundleAtomic(opts.profileId, updated)
    log('')
    log(`Grant renewed for profile "${opts.profileId}".`)
    log(`  grant:      ${grant.grant_id} (permissions: ${grant.permissions.join(', ')})`)
    log(`  audience:   ${grant.audience}`)
    log(`  expires:    ${grant.expires_at}`)
    log(`  generation: ${updated.generation}`)
    await notifyDaemonReload(log)
    return { profileId: opts.profileId, bundle: updated }
  })
}
