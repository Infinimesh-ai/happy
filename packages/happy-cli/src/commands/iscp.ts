/**
 * `happy iscp` — ISCP device enrollment, grant renewal and profile
 * inspection (dual-stack Phase 2 slice; the ISCP transport itself lands in
 * Phase 3).
 *
 * Managed enrollment against Infinimesh Cloud consumes the v2 signed-ticket
 * contract (OPS 2026-08-16 §5.5): `--cloud` presets the production endpoints
 * and the positional argument accepts the Console/JingSi enrollment wrapper.
 * Grant renewal consumes the frozen renew-grant contract (OPS 2026-08-17
 * §4.3): the device key never changes, only the trust grant is re-issued.
 */

import chalk from 'chalk'

import { createNobleProvider, identityThumbprint, TrustRootClient, verifyTrustRootDescriptor } from '@slopus/iscp'

import { daemonGet } from '@/daemon/controlClient'
import {
  deviceConfirmationCode,
  enroll,
  inspectProfile,
  iscpProfileDir,
  listProfiles,
  parseEnrollmentInput,
  readProfileBundle,
  renewProfileGrant,
} from '@/iscp/enrollment'
import { autoRenewalStatusView, readAutoRenewalState } from '@/iscp/autoRenewal'
import type { ProfilePeerStatus } from '@/iscp/sessionInitiator'

const CLOUD_DEFAULTS = {
  baseUrl: () => process.env.ISCP_CLOUD_BASE_URL ?? 'https://iscp.infinimesh.cloud',
  relayId: () => process.env.ISCP_CLOUD_RELAY_ID ?? 'relay-prod-cn-east-1',
  trustRootId: () => process.env.ISCP_CLOUD_TRUST_ID ?? 'trust-root-cn-east-1',
  profile: () => process.env.ISCP_CLOUD_PROFILE ?? 'cloud-prod',
}

function printHelp(): void {
  console.log(`
${chalk.bold('happy iscp')} - ISCP device enrollment (dual-stack)

${chalk.bold('Usage:')}
  happy iscp enroll <ticket-or-wrapper> [options]   Enroll this machine as an ISCP device
  happy iscp renew <renewal-id> [options]           Renew the trust grant (device key unchanged)
  happy iscp status [profile] [--check]             Show enrolled ISCP profiles
  happy iscp help                                   Show this help

${chalk.bold('Arguments:')}
  ticket-or-wrapper     Enrollment payload: the base64url string from the
                        Console/JingSi QR code, deep link
                        (happy://iscp-enroll?payload=<wrapper>), or copy
                        button — either the enrollment wrapper or a bare
                        signed pairing ticket — a raw JSON string, or a path
                        to a JSON file. Omit for the local-lab bind-self dev
                        flow.
  renewal-id            One-time renewal id issued by the Console/JingSi for
                        this device.

${chalk.bold('Options (enroll):')}
  --cloud               Infinimesh Cloud preset: base URL, relay id, trust
                        root id and profile from ISCP_CLOUD_BASE_URL /
                        ISCP_CLOUD_RELAY_ID / ISCP_CLOUD_TRUST_ID /
                        ISCP_CLOUD_PROFILE (defaults:
                        https://iscp.infinimesh.cloud, relay-prod-cn-east-1,
                        trust-root-cn-east-1, cloud-prod).
                        A Console/JingSi wrapper payload implies this preset
                        automatically; the flag is an explicit alias.
  --replace             Explicitly replace an existing profile: a NEW device
                        key is generated and the old profile directory is
                        kept as a .replaced-<timestamp> backup. Without this
                        flag, enrolling over an existing profile is refused
                        and the ticket is NOT consumed.
  --relay-url <url>     Relay base URL           (default http://localhost:18080)
  --trust-url <url>     Trust root base URL      (default http://localhost:18081)
  --relay-id <id>       Relay id                 (default relay-local)
  --trust-root-id <id>  Trust root id            (default trust-local)
  --domain <id>         ISCP domain id. With a ticket the domain comes from
                        the ticket; only pass this to cross-check it.
                        (default local, bind-self mode only)
  --device-id <id>      Device id                (default generated happy-cli-<rand>;
                        ticket mode: provisional, the Cloud assigns dev_...)
  --display-name <name> Display name registered with the Cloud (ticket mode)
  --profile <id>        Profile id               (default <domain>-<relay-id>,
                        or cloud-prod with --cloud)

${chalk.bold('Options (renew):')}
  --profile <id>        Profile to renew         (default cloud-prod, or
                        ISCP_CLOUD_PROFILE)
  --relay-url <url>     Override the relay base URL (default: from the
                        enrolled relay descriptor)
  --trust-url <url>     Override the trust root base URL (default: from the
                        enrolled trust root descriptor)
  --relay-id <id>       Override the relay id    (default: enrolled relay id)
  --trust-root-id <id>  Override the trust root id (default: enrolled id)

${chalk.bold('Options (status):')}
  --check               Six-layer live check: ① local profile integrity
                        ② key thumbprint ③ Cloud device record ④ grant
                        online status ⑤ relay transport ⑥ E2E session —
                        layers ⑤/⑥ come from the running daemon and degrade
                        to "daemon not running". Never fatal.

${chalk.bold('Notes:')}
  - The device identity key is generated locally and stored only in
    ~/.happy/iscp/<profile>/device.key (0600). It never leaves this machine.
  - One machine keeps ONE device identity per profile: enrolling again over
    a healthy profile is refused (and the ticket left unconsumed) unless
    --replace is passed. Grant expiry needs "happy iscp renew", not a new
    enrollment.
  - During enrollment a 6-digit device confirmation code is printed; the
    operator authorizing the device should compare it out of band.
  - Managed enrollment verifies the signed ticket and the returned Trust
    Grant before anything is written to disk. Ticket payloads are never
    printed; neither are tokens or keys.
  - With background auto-renewal enabled (from JingSi/Console), the happy
    daemon renews the trust grant automatically inside the renewal window
    (min(24h, grantTTL/5)). "happy iscp status" shows that layer separately
    from grant validity and from relay credential health; "happy iscp renew"
    stays available as the manual/diagnostic fallback.
  - The local-lab defaults match the reference harness:
      docker compose -f environments/iscp/docker-compose.yaml up --build -d
`)
}

function takeOption(args: string[], name: string): string | undefined {
  const index = args.indexOf(name)
  if (index < 0) return undefined
  const value = args[index + 1]
  if (value === undefined || value.startsWith('--')) {
    throw new Error(`${name} requires a value`)
  }
  args.splice(index, 2)
  return value
}

function takeFlag(args: string[], name: string): boolean {
  const index = args.indexOf(name)
  if (index < 0) return false
  args.splice(index, 1)
  return true
}

async function handleEnroll(args: string[]): Promise<void> {
  const cloudFlag = takeFlag(args, '--cloud')
  const replace = takeFlag(args, '--replace')
  const relayUrlOption = takeOption(args, '--relay-url')
  const trustUrlOption = takeOption(args, '--trust-url')
  const relayIdOption = takeOption(args, '--relay-id')
  const trustRootIdOption = takeOption(args, '--trust-root-id')
  const domainOption = takeOption(args, '--domain')
  const deviceId = takeOption(args, '--device-id')
  const displayName = takeOption(args, '--display-name')
  const profileOption = takeOption(args, '--profile')
  const unknown = args.find((a) => a.startsWith('--'))
  if (unknown !== undefined) {
    throw new Error(`unknown option ${unknown} (see: happy iscp help)`)
  }
  const ticket = args[0]
  if (cloudFlag && ticket === undefined) {
    throw new Error('--cloud requires an enrollment ticket/wrapper (issued by the Console or JingSi)')
  }

  // A Console/JingSi wrapper implies the managed Cloud preset — their UIs
  // print plain `happy iscp enroll <wrapper>` with no endpoint flags.
  // Explicit options always win; parse failures surface inside enroll().
  let wrapperInput = false
  if (!cloudFlag && ticket !== undefined) {
    try {
      wrapperInput = parseEnrollmentInput(ticket).fromWrapper === true
    } catch {
      wrapperInput = false
    }
  }
  const cloud = cloudFlag || wrapperInput

  const relayUrl = relayUrlOption ?? (cloud ? CLOUD_DEFAULTS.baseUrl() : 'http://localhost:18080')
  const trustUrl = trustUrlOption ?? (cloud ? CLOUD_DEFAULTS.baseUrl() : 'http://localhost:18081')
  const relayId = relayIdOption ?? (cloud ? CLOUD_DEFAULTS.relayId() : 'relay-local')
  const trustRootId = trustRootIdOption ?? (cloud ? CLOUD_DEFAULTS.trustRootId() : 'trust-local')
  const profileId = profileOption ?? (cloud ? CLOUD_DEFAULTS.profile() : undefined)
  // Without a ticket the domain is required (bind-self); with a ticket it is
  // taken from the signed ticket and --domain only cross-checks.
  const domainId = domainOption ?? (ticket === undefined ? 'local' : undefined)

  const { profileId: enrolledProfile } = await enroll({
    relayUrl,
    trustUrl,
    relayId,
    trustRootId,
    domainId,
    ticket,
    deviceId,
    profileId,
    displayName,
    replace,
    log: (line) => console.log(line),
  })
  console.log('')
  console.log(chalk.green(`✓ ISCP profile "${enrolledProfile}" is ready`))
}

async function handleRenew(args: string[]): Promise<void> {
  const relayUrl = takeOption(args, '--relay-url')
  const trustUrl = takeOption(args, '--trust-url')
  const relayId = takeOption(args, '--relay-id')
  const trustRootId = takeOption(args, '--trust-root-id')
  const profileOption = takeOption(args, '--profile')
  const unknown = args.find((a) => a.startsWith('--'))
  if (unknown !== undefined) {
    throw new Error(`unknown option ${unknown} (see: happy iscp help)`)
  }
  const renewalId = args[0]
  if (renewalId === undefined) {
    throw new Error('renew requires a renewal id: happy iscp renew <renewal-id> [--profile <id>]')
  }
  const profileId = profileOption ?? CLOUD_DEFAULTS.profile()

  const { profileId: renewedProfile } = await renewProfileGrant({
    profileId,
    renewalId,
    relayUrl,
    trustUrl,
    relayId,
    trustRootId,
    log: (line) => console.log(line),
  })
  console.log('')
  console.log(chalk.green(`✓ Trust grant renewed for profile "${renewedProfile}"`))
}

async function handleStatus(args: string[]): Promise<void> {
  const check = takeFlag(args, '--check')
  const provider = createNobleProvider()
  const filter = args[0]
  const profiles = filter !== undefined ? [filter] : listProfiles()
  if (profiles.length === 0) {
    console.log('No ISCP profiles enrolled. Run: happy iscp enroll')
    return
  }
  // Layers 5/6 come from the daemon; fetched once for all profiles.
  const peerStatuses = check ? await fetchDaemonPeerStatuses() : undefined
  for (const profileId of profiles) {
    const bundle = readProfileBundle(profileId)
    if (!bundle) {
      console.log(`${chalk.yellow('!')} ${profileId}: missing or corrupt bundle at ${iscpProfileDir(profileId)}`)
      if (check) {
        const inspection = inspectProfile(provider, profileId)
        console.log(`  [1] local profile:  ${inspection.state === 'corrupt' ? chalk.red(`corrupt — ${inspection.reason}`) : inspection.state}`)
        console.log(`      recover with: happy iscp enroll --replace ... (old directory is kept as a backup)`)
      }
      continue
    }
    const grant = bundle.trust_grant
    console.log(`${chalk.bold(profileId)}  (${iscpProfileDir(profileId)})`)
    console.log(`  domain/relay/trust: ${bundle.domain_id} / ${bundle.relay_id} / ${bundle.trust_root_id}`)
    console.log(`  device:             ${bundle.device_identity.device_id}`)
    console.log(`  thumbprint:         ${identityThumbprint(provider, bundle.device_identity)}`)
    console.log(`  confirmation code:  ${deviceConfirmationCode(provider, bundle.device_identity)}`)
    console.log(`  generation:         ${bundle.generation ?? 1}`)
    console.log(`  grant:              ${grant.grant_id} (expires ${grant.expires_at})`)
    console.log(`  grant audience:     ${grant.audience} ${chalk.dim('(the phone allowed to control this machine)')}`)
    console.log(`  grant permissions:  ${grant.permissions.join(', ')}`)
    if (grant.relay_constraints !== undefined && grant.relay_constraints.length > 0) {
      console.log(`  relay constraints:  ${grant.relay_constraints.join(', ')}`)
    }
    console.log(`  access expires:     ${bundle.access_credential.expires_at}`)
    console.log(`  refresh expires:    ${bundle.refresh_credential.expires_at}`)
    console.log(`  enrolled at:        ${bundle.enrolled_at}`)
    // Two DISTINCT lifecycle layers (OPS §8.3): the short-lived grant
    // validity above, and the background auto-renewal machinery below. Relay
    // access/refresh credential issues are a third, independent lifecycle —
    // never collapse these into one message.
    printAutoRenewalStatus(profileId, bundle)
    if (check) {
      await printCheckLayers(provider, profileId, bundle, peerStatuses)
    }
  }
}

const AUTO_RENEWAL_ACTION_HINTS: Record<string, string> = {
  renewal_authorization_not_found: 'auto-renewal is not enabled for this device — enable it from JingSi/Console',
  renewal_authorization_revoked: 'auto-renewal was switched off — re-enable it from JingSi/Console if desired',
  renewal_authorization_expired: 'the auto-renewal authorization reached its absolute expiry — re-authorize from JingSi/Console',
  renewal_identity_conflict: 'the Cloud holds a DIFFERENT key for this device (replace-required); this needs an explicit decision, never an automatic re-enrollment',
  device_revoked: 'this device has been revoked by the Cloud',
  grant_audience_not_active: 'the paired phone is no longer active/trusted — re-pair from JingSi/Console',
  require_mfa: 'the Cloud demands a step-up — re-authorize from JingSi/Console',
  auto_renewal_disabled: 'background auto-renewal is disabled server-side (kill switch); manual renewal still works',
  proof_replay_anomaly: 'contract anomaly during an idempotent retry — collect daemon logs and renew manually',
}

/**
 * The background auto-renewal layer, read from the scheduler's on-disk state
 * (works with the daemon down). Deliberately printed as its own block so
 * grant validity, auto-renewal health, and relay credential health never
 * fold into one message.
 */
function printAutoRenewalStatus(profileId: string, bundle: NonNullable<ReturnType<typeof readProfileBundle>>): void {
  const view = autoRenewalStatusView(bundle, readAutoRenewalState(profileId), Date.now())
  const display = view.display
  switch (display.kind) {
    case 'action-required': {
      const hint = AUTO_RENEWAL_ACTION_HINTS[display.reason]
      console.log(`  auto-renewal:       ${chalk.red(`ACTION REQUIRED — ${display.reason}`)} (since ${display.at})`)
      if (hint !== undefined) console.log(`                      ${hint}`)
      console.log(`                      manual fallback: happy iscp renew <renewal-id>`)
      break
    }
    case 'retrying-unknown-outcome':
      console.log(`  auto-renewal:       ${chalk.yellow('retrying an unresolved attempt')} (started ${display.startedAt}${display.nextAttemptAt !== undefined ? `, next retry ${display.nextAttemptAt}` : ''}; same idempotency key)`)
      break
    case 'scheduled':
      console.log(`  auto-renewal:       ${chalk.green('scheduled')} — next attempt ${display.nextAttemptAt}`)
      break
    case 'waiting':
      console.log(`  auto-renewal:       waiting — renewal window opens ${display.windowOpensAt}`)
      break
  }
  if (view.lastSuccessAt !== undefined) {
    console.log(`                      last renewed: ${view.lastSuccessAt}`)
  }
  if (view.lastResult !== undefined && view.lastResult !== 'renewed') {
    console.log(`                      last attempt result: ${view.lastResult}${view.lastAttemptAt !== undefined ? ` (at ${view.lastAttemptAt})` : ''}`)
  }
}

/**
 * `--check`: the six diagnostic layers (OPS 2026-08-17 §4.1). Every layer is
 * best-effort and never fatal — offline layers degrade to warnings.
 */
async function printCheckLayers(
  provider: ReturnType<typeof createNobleProvider>,
  profileId: string,
  bundle: NonNullable<ReturnType<typeof readProfileBundle>>,
  peerStatuses: ProfilePeerStatus[] | undefined,
): Promise<void> {
  // ① Local profile integrity.
  try {
    const inspection = inspectProfile(provider, profileId)
    if (inspection.state === 'healthy') {
      console.log(`  [1] local profile:  ${chalk.green('healthy')} (bundle + key present, key matches identity)`)
    } else if (inspection.state === 'corrupt') {
      console.log(`  [1] local profile:  ${chalk.red(`corrupt — ${inspection.reason}`)}`)
    } else {
      console.log(`  [1] local profile:  ${chalk.yellow('absent')}`)
    }
  } catch (error) {
    console.log(`  [1] local profile:  ${chalk.yellow('unavailable')} (${error instanceof Error ? error.message : String(error)})`)
  }

  // ② Key thumbprint (local, always available once the bundle loads).
  console.log(`  [2] key thumbprint: ${identityThumbprint(provider, bundle.device_identity)}`)

  // ③ Cloud device record: existence + the Cloud-side key matches ours.
  try {
    const trustDescriptor = verifyTrustRootDescriptor(provider, bundle.trust_root_descriptor)
    const trustRoot = new TrustRootClient({ baseUrl: trustDescriptor.base_url, trustRootId: bundle.trust_root_id, domainId: bundle.domain_id, provider })
    const record = await trustRoot.deviceStatus(bundle.device_identity.device_id)
    if (record.identity.public_key.kid === bundle.device_identity.public_key.kid) {
      console.log(`  [3] cloud device:   ${chalk.green('registered')} (status ${record.status}, key matches)`)
    } else {
      console.log(`  [3] cloud device:   ${chalk.red('identity mismatch')} — the Cloud holds a DIFFERENT key for ${bundle.device_identity.device_id} (a later enrollment replaced this device; re-enroll here with --replace or revoke the other machine)`)
    }
  } catch (error) {
    console.log(`  [3] cloud device:   ${chalk.yellow('unavailable')} (${error instanceof Error ? error.message : String(error)})`)
  }

  // ④ Grant online status.
  await printOnlineGrantStatus(provider, bundle)

  // ⑤ Relay transport + ⑥ E2E session — from the running daemon.
  if (peerStatuses === undefined) {
    console.log(`  [5] relay transport: ${chalk.yellow('daemon not running')}`)
    console.log(`  [6] session:         ${chalk.yellow('daemon not running')}`)
    return
  }
  const peer = peerStatuses.find((p) => p.profileId === profileId)
  if (peer === undefined) {
    console.log(`  [5] relay transport: ${chalk.yellow('profile not loaded by the daemon')} (run: happy daemon restart, or POST /iscp/reload)`)
    console.log(`  [6] session:         ${chalk.yellow('profile not loaded by the daemon')}`)
    return
  }
  const transportColor = peer.connectionState === 'READY' ? chalk.green : chalk.yellow
  console.log(`  [5] relay transport: ${transportColor(peer.connectionState)}`)
  const sessionLine = peer.sessionDetail !== undefined ? `${peer.session} (${peer.sessionDetail})` : peer.session
  const sessionColor = peer.session === 'ready' ? chalk.green : peer.session === 'connecting' ? chalk.yellow : chalk.red
  console.log(`  [6] session:         ${sessionColor(sessionLine)} ${chalk.dim(`(peer ${peer.peerDeviceId})`)}`)
  if (peer.session === 'authorization_expired') {
    console.log(`      the grant has expired — run: happy iscp renew <renewal-id>`)
  }
}

/** Fetch /iscp/peer-status from the daemon; undefined when it is not running. */
async function fetchDaemonPeerStatuses(): Promise<ProfilePeerStatus[] | undefined> {
  try {
    const result = (await daemonGet('/iscp/peer-status')) as { error?: string; profiles?: ProfilePeerStatus[] }
    if (result?.error !== undefined || !Array.isArray(result?.profiles)) return undefined
    return result.profiles
  } catch {
    return undefined
  }
}

/** `--check` layer ④: query the trust root for live grant/revocation state; never fatal. */
async function printOnlineGrantStatus(
  provider: ReturnType<typeof createNobleProvider>,
  bundle: NonNullable<ReturnType<typeof readProfileBundle>>,
): Promise<void> {
  try {
    const trustDescriptor = verifyTrustRootDescriptor(provider, bundle.trust_root_descriptor)
    const trustRoot = new TrustRootClient({
      baseUrl: trustDescriptor.base_url,
      trustRootId: bundle.trust_root_id,
      domainId: bundle.domain_id,
      provider,
    })
    const [liveGrant, revocations] = await Promise.all([
      trustRoot.grantStatus(bundle.trust_grant.grant_id),
      trustRoot.revocations(),
    ])
    const deviceEpoch = revocations[bundle.device_identity.device_id]
    const revoked = deviceEpoch !== undefined && liveGrant.revocation_epoch < deviceEpoch
    const expired = Date.now() >= new Date(liveGrant.expires_at).getTime()
    if (revoked) {
      console.log(`  [4] online grant:   ${chalk.red('REVOKED')} (device revocation epoch ${deviceEpoch} > grant epoch ${liveGrant.revocation_epoch})`)
    } else if (expired) {
      console.log(`  [4] online grant:   ${chalk.yellow('EXPIRED')} (grant expired ${liveGrant.expires_at}; run: happy iscp renew <renewal-id>)`)
    } else {
      console.log(`  [4] online grant:   ${chalk.green('active')} (grant epoch ${liveGrant.revocation_epoch}, expires ${liveGrant.expires_at})`)
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    console.log(`  [4] online grant:   ${chalk.yellow('unavailable')} (${message})`)
  }
}

export async function handleIscpCommand(args: string[]): Promise<void> {
  const subcommand = args[0]
  switch (subcommand) {
    case 'enroll':
      await handleEnroll(args.slice(1))
      return
    case 'renew':
      await handleRenew(args.slice(1))
      return
    case 'status':
      await handleStatus(args.slice(1))
      return
    case 'help':
    case '--help':
    case undefined:
      printHelp()
      return
    default:
      throw new Error(`unknown iscp subcommand "${subcommand}" (see: happy iscp help)`)
  }
}
