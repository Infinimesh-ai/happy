/**
 * Network startup decision for Happy entrypoints (OPS 2026-08-26 §3.1/§4.1):
 * Legacy and ISCP are parallel network identities, not a base + plugin.
 *
 * A healthy ISCP profile alone must be sufficient to run the daemon and to
 * start Claude/Codex sessions; the ISCP path must never read, create, or
 * interactively demand legacy Happy Server credentials. Conversely the legacy
 * branch is preserved verbatim: whenever `~/.happy/access.key` exists the
 * existing auth/machine setup runs exactly as before (dual-stack when an ISCP
 * profile is also resolved).
 *
 * Zero credentials of either kind lands in mode-selection/enrollment guidance
 * — it must NOT silently fall into the interactive legacy QR login.
 *
 * The decide* functions are pure so every branch is pinnable by tests; the
 * resolve* wrappers do the IO (credentials file, settings, env, auth prompt).
 */

import { randomUUID } from 'node:crypto'

import { readCredentials, updateSettings, type Credentials } from '@/persistence'
import { authAndSetupMachineIfNeeded } from '@/ui/auth'
import { logger } from '@/ui/logger'
import {
  resolveIscpProfile,
  type IscpProfileProbe,
  type IscpProfileResolution,
} from '@/iscp/profileEnv'
import { listProfiles, inspectProfile } from '@/iscp/enrollment'
import { createNobleProvider } from '@slopus/iscp'

export type SessionNetwork =
  | { mode: 'legacy'; credentials: Credentials; machineId: string }
  | { mode: 'iscp-only'; profileId: string; machineId: string }

export type SessionNetworkDecision =
  | { kind: 'legacy' }
  | { kind: 'dual'; profileId: string }
  | { kind: 'iscp-only'; profileId: string }
  | { kind: 'legacy-login' }
  | { kind: 'choose' }
  | { kind: 'error'; message: string }

/**
 * Map an ISCP profile resolution plus legacy-credential presence to a startup
 * mode. `explicitLegacyOptOut` is HAPPY_NETWORK_PROFILE='' — the user's
 * explicit "run legacy" choice, which counts as mode selection and therefore
 * may proceed into the interactive legacy login when no credentials exist.
 */
export function decideSessionNetwork(opts: {
  resolution: IscpProfileResolution
  hasLegacyCredentials: boolean
  explicitLegacyOptOut: boolean
}): SessionNetworkDecision {
  const { resolution, hasLegacyCredentials, explicitLegacyOptOut } = opts
  if (resolution.mode === 'iscp') {
    return hasLegacyCredentials
      ? { kind: 'dual', profileId: resolution.profileId }
      : { kind: 'iscp-only', profileId: resolution.profileId }
  }
  if (hasLegacyCredentials) {
    return { kind: 'legacy' }
  }
  if (resolution.warning !== undefined) {
    // Profiles are enrolled but none is healthy, and there is no legacy
    // account to fall back to. Jumping into the legacy QR login here would
    // silently turn an ISCP host into a legacy one — fail with repair
    // guidance instead.
    return {
      kind: 'error',
      message:
        `${resolution.warning}\n` +
        `No legacy Happy account is configured on this machine either. ` +
        `Repair the ISCP profile (happy iscp status <profile> --check), re-enroll ` +
        `(happy iscp enroll <invitation>), or run 'happy auth login' if you want a legacy account.`,
    }
  }
  return explicitLegacyOptOut ? { kind: 'legacy-login' } : { kind: 'choose' }
}

export const ZERO_CREDENTIAL_GUIDANCE =
  `No Happy credentials found on this machine — neither an ISCP profile nor a legacy account.\n` +
  `Choose how this machine should join a network:\n` +
  `  - ISCP (recommended for managed devices): ask your Cloud Console / JingSi admin for an\n` +
  `    enrollment invitation and run: happy iscp enroll <invitation>\n` +
  `  - Legacy Happy account: run 'happy auth login' (QR / browser login).`

function defaultProbe(): IscpProfileProbe {
  const provider = createNobleProvider()
  return {
    list: listProfiles,
    inspect: (profileId) => inspectProfile(provider, profileId),
  }
}

async function ensureMachineIdWithoutAuth(): Promise<string> {
  const settings = await updateSettings(async (s) => (
    s.machineId ? s : { ...s, machineId: randomUUID() }
  ))
  return settings.machineId!
}

/**
 * Interactive zero-credential mode chooser. Injectable for tests; the default
 * lazily loads the Ink selector so headless paths never touch it.
 */
async function chooseNetworkModeInteractively(): Promise<'legacy' | 'iscp' | null> {
  const [{ render }, React, { NetworkModeSelector }] = await Promise.all([
    import('ink'),
    import('react'),
    import('@/ui/ink/NetworkModeSelector'),
  ])
  return new Promise((resolve) => {
    let resolved = false
    const finish = (choice: 'legacy' | 'iscp' | null) => {
      if (resolved) return
      resolved = true
      app.unmount()
      resolve(choice)
    }
    const app = render(React.createElement(NetworkModeSelector, {
      onSelect: finish,
      onCancel: () => finish(null),
    }), { exitOnCtrlC: false, patchConsole: false })
  })
}

export interface SessionNetworkIo {
  readCredentials: () => Promise<Credentials | null>
  runLegacyAuth: () => Promise<{ credentials: Credentials; machineId: string }>
  ensureMachineId: () => Promise<string>
  chooseMode: () => Promise<'legacy' | 'iscp' | null>
  isInteractive: () => boolean
  probe?: IscpProfileProbe
}

const defaultIo: SessionNetworkIo = {
  readCredentials,
  runLegacyAuth: authAndSetupMachineIfNeeded,
  ensureMachineId: ensureMachineIdWithoutAuth,
  chooseMode: chooseNetworkModeInteractively,
  isInteractive: () => process.stdout.isTTY === true && process.stdin.isTTY === true,
}

/**
 * Resolve how a session command ('happy', 'happy codex') should run, applying
 * the ISCP profile to process.env for the dual/iscp-only branches. Throws on
 * fail-fast conditions; the command entrypoint prints the error and exits.
 */
export async function resolveSessionNetwork(
  command: string,
  startedBy?: string,
  io: SessionNetworkIo = defaultIo,
): Promise<SessionNetwork> {
  const envValue = process.env.HAPPY_NETWORK_PROFILE
  const resolution = resolveIscpProfile({ startedBy, envValue, command, probe: io.probe })
  const credentials = await io.readCredentials()
  const decision = decideSessionNetwork({
    resolution,
    hasLegacyCredentials: credentials !== null,
    explicitLegacyOptOut: envValue === '',
  })

  switch (decision.kind) {
    case 'legacy': {
      if (resolution.mode === 'legacy' && resolution.warning) {
        console.error(resolution.warning)
      }
      const auth = await io.runLegacyAuth()
      return { mode: 'legacy', ...auth }
    }
    case 'dual': {
      process.env.HAPPY_NETWORK_PROFILE = decision.profileId
      if (resolution.mode === 'iscp' && resolution.announcement) {
        console.log(resolution.announcement)
      }
      const auth = await io.runLegacyAuth()
      return { mode: 'legacy', ...auth }
    }
    case 'iscp-only': {
      process.env.HAPPY_NETWORK_PROFILE = decision.profileId
      if (resolution.mode === 'iscp' && resolution.announcement) {
        console.log(resolution.announcement)
      }
      console.log(`Running ISCP-only: profile '${decision.profileId}', no legacy Happy account on this machine.`)
      const machineId = await io.ensureMachineId()
      logger.debug(`[NETWORK] ISCP-only session network resolved (profile ${decision.profileId})`)
      return { mode: 'iscp-only', profileId: decision.profileId, machineId }
    }
    case 'legacy-login': {
      // HAPPY_NETWORK_PROFILE='' — the user explicitly chose legacy mode, so
      // the interactive login is an answer to their choice, not a default.
      const auth = await io.runLegacyAuth()
      return { mode: 'legacy', ...auth }
    }
    case 'choose': {
      if (!io.isInteractive()) {
        throw new Error(ZERO_CREDENTIAL_GUIDANCE)
      }
      const choice = await io.chooseMode()
      if (choice === 'legacy') {
        const auth = await io.runLegacyAuth()
        return { mode: 'legacy', ...auth }
      }
      if (choice === 'iscp') {
        console.log('')
        console.log(ZERO_CREDENTIAL_GUIDANCE)
        process.exit(0)
      }
      throw new Error('Cancelled. ' + ZERO_CREDENTIAL_GUIDANCE)
    }
    case 'error':
      throw new Error(decision.message)
  }
}

/**
 * Guard for agents that only support the legacy network (gemini, acp,
 * openclaw, agy). On an ISCP-only host (profiles enrolled, no legacy
 * account) they must report "unsupported" instead of dropping the user into
 * the interactive legacy QR login. With zero credentials of either kind the
 * legacy login remains the agent's only possible path, so it may proceed.
 */
export async function ensureLegacyOnlyAgentUsable(agent: string): Promise<void> {
  const credentials = await readCredentials()
  if (credentials !== null) return
  if (listProfiles().length === 0) return
  throw new Error(
    `'${agent}' only supports the legacy Happy network, and this machine runs ISCP-only ` +
    `(no legacy account). Use 'happy' (Claude) or 'happy codex', which support ISCP — ` +
    `or run 'happy auth login' to add a legacy account for this agent.`,
  )
}

// ---------------------------------------------------------------------------
// Daemon
// ---------------------------------------------------------------------------

export type DaemonNetwork =
  | { mode: 'legacy'; credentials: Credentials; machineId: string }
  | { mode: 'iscp-only'; machineId: string; profiles: string[] }

export type DaemonNetworkDecision =
  | { kind: 'legacy' }
  | { kind: 'iscp-only'; profiles: string[] }
  | { kind: 'error'; message: string }

/**
 * Daemon startup decision. Legacy credentials on disk → the existing legacy
 * boot path, verbatim (ISCP peers still come up additively, as today). No
 * legacy credentials + at least one healthy profile → ISCP-only daemon.
 * The daemon is headless, so every other combination is a hard error with
 * guidance, never an interactive login.
 */
export function decideDaemonNetwork(opts: {
  hasLegacyCredentials: boolean
  profiles: string[]
  healthyProfiles: string[]
}): DaemonNetworkDecision {
  if (opts.hasLegacyCredentials) {
    return { kind: 'legacy' }
  }
  if (opts.healthyProfiles.length > 0) {
    return { kind: 'iscp-only', profiles: opts.healthyProfiles }
  }
  if (opts.profiles.length > 0) {
    return {
      kind: 'error',
      message:
        `ISCP profiles are enrolled (${opts.profiles.join(', ')}) but none is healthy, and no legacy ` +
        `Happy account exists. The daemon cannot start. Repair with 'happy iscp status <profile> --check' ` +
        `or re-enroll with 'happy iscp enroll <invitation>'.`,
    }
  }
  return { kind: 'error', message: ZERO_CREDENTIAL_GUIDANCE }
}

export async function resolveDaemonNetwork(io?: {
  readCredentials?: () => Promise<Credentials | null>
  runLegacyAuth?: () => Promise<{ credentials: Credentials; machineId: string }>
  ensureMachineId?: () => Promise<string>
  probe?: IscpProfileProbe
}): Promise<DaemonNetwork> {
  const readCreds = io?.readCredentials ?? readCredentials
  const runAuth = io?.runLegacyAuth ?? authAndSetupMachineIfNeeded
  const ensureId = io?.ensureMachineId ?? ensureMachineIdWithoutAuth
  const probe = io?.probe ?? defaultProbe()

  const credentials = await readCreds()
  const profiles = probe.list()
  const healthyProfiles = profiles.filter((profileId) => probe.inspect(profileId).state === 'healthy')
  const decision = decideDaemonNetwork({
    hasLegacyCredentials: credentials !== null,
    profiles,
    healthyProfiles,
  })

  switch (decision.kind) {
    case 'legacy': {
      const auth = await runAuth()
      return { mode: 'legacy', ...auth }
    }
    case 'iscp-only': {
      const machineId = await ensureId()
      logger.debug(`[NETWORK] ISCP-only daemon network resolved (profiles: ${decision.profiles.join(', ')})`)
      return { mode: 'iscp-only', machineId, profiles: decision.profiles }
    }
    case 'error':
      throw new Error(decision.message)
  }
}
