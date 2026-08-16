/**
 * `happy iscp` — ISCP device enrollment and profile inspection (dual-stack
 * Phase 2 slice; the ISCP transport itself lands in Phase 3).
 *
 * Managed enrollment against Infinimesh Cloud consumes the v2 signed-ticket
 * contract (OPS 2026-08-16 §5.5): `--cloud` presets the production endpoints
 * and the positional argument accepts the Console/JingSi enrollment wrapper.
 */

import chalk from 'chalk'

import { createNobleProvider, identityThumbprint, TrustRootClient, verifyTrustRootDescriptor } from '@slopus/iscp'

import { deviceConfirmationCode, enroll, iscpProfileDir, listProfiles, parseEnrollmentInput, readProfileBundle } from '@/iscp/enrollment'

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

${chalk.bold('Options (enroll):')}
  --cloud               Infinimesh Cloud preset: base URL, relay id, trust
                        root id and profile from ISCP_CLOUD_BASE_URL /
                        ISCP_CLOUD_RELAY_ID / ISCP_CLOUD_TRUST_ID /
                        ISCP_CLOUD_PROFILE (defaults:
                        https://iscp.infinimesh.cloud, relay-prod-cn-east-1,
                        trust-root-cn-east-1, cloud-prod).
                        A Console/JingSi wrapper payload implies this preset
                        automatically; the flag is an explicit alias.
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

${chalk.bold('Options (status):')}
  --check               Also query the trust root online for the grant's
                        revocation status (degrades to a warning offline).

${chalk.bold('Notes:')}
  - The device identity key is generated locally and stored only in
    ~/.happy/iscp/<profile>/device.key (0600). It never leaves this machine.
  - During enrollment a 6-digit device confirmation code is printed; the
    operator authorizing the device should compare it out of band.
  - Managed enrollment verifies the signed ticket and the returned Trust
    Grant before anything is written to disk. Ticket payloads are never
    printed; neither are tokens or keys.
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
    log: (line) => console.log(line),
  })
  console.log('')
  console.log(chalk.green(`✓ ISCP profile "${enrolledProfile}" is ready`))
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
  for (const profileId of profiles) {
    const bundle = readProfileBundle(profileId)
    if (!bundle) {
      console.log(`${chalk.yellow('!')} ${profileId}: missing or corrupt bundle at ${iscpProfileDir(profileId)}`)
      continue
    }
    const grant = bundle.trust_grant
    console.log(`${chalk.bold(profileId)}  (${iscpProfileDir(profileId)})`)
    console.log(`  domain/relay/trust: ${bundle.domain_id} / ${bundle.relay_id} / ${bundle.trust_root_id}`)
    console.log(`  device:             ${bundle.device_identity.device_id}`)
    console.log(`  thumbprint:         ${identityThumbprint(provider, bundle.device_identity)}`)
    console.log(`  confirmation code:  ${deviceConfirmationCode(provider, bundle.device_identity)}`)
    console.log(`  grant:              ${grant.grant_id} (expires ${grant.expires_at})`)
    console.log(`  grant audience:     ${grant.audience} ${chalk.dim('(the phone allowed to control this machine)')}`)
    console.log(`  grant permissions:  ${grant.permissions.join(', ')}`)
    if (grant.relay_constraints !== undefined && grant.relay_constraints.length > 0) {
      console.log(`  relay constraints:  ${grant.relay_constraints.join(', ')}`)
    }
    console.log(`  access expires:     ${bundle.access_credential.expires_at}`)
    console.log(`  refresh expires:    ${bundle.refresh_credential.expires_at}`)
    console.log(`  enrolled at:        ${bundle.enrolled_at}`)
    if (check) {
      await printOnlineGrantStatus(provider, bundle)
    }
  }
}

/** `--check`: query the trust root for live grant/revocation state; never fatal. */
async function printOnlineGrantStatus(
  provider: ReturnType<typeof createNobleProvider>,
  bundle: NonNullable<ReturnType<typeof readProfileBundle>>,
): Promise<void> {
  try {
    const trustDescriptor = verifyTrustRootDescriptor(provider, bundle.trust_root_descriptor)
    const trustRoot = new TrustRootClient({
      baseUrl: trustDescriptor.base_url,
      trustRootId: bundle.trust_root_id,
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
      console.log(`  online status:      ${chalk.red('REVOKED')} (device revocation epoch ${deviceEpoch} > grant epoch ${liveGrant.revocation_epoch})`)
    } else if (expired) {
      console.log(`  online status:      ${chalk.yellow('EXPIRED')} (grant expired ${liveGrant.expires_at})`)
    } else {
      console.log(`  online status:      ${chalk.green('active')} (grant epoch ${liveGrant.revocation_epoch}, expires ${liveGrant.expires_at})`)
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    console.log(`  online status:      ${chalk.yellow('unavailable')} (${message})`)
  }
}

export async function handleIscpCommand(args: string[]): Promise<void> {
  const subcommand = args[0]
  switch (subcommand) {
    case 'enroll':
      await handleEnroll(args.slice(1))
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
