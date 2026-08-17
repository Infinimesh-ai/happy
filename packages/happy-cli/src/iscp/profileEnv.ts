/**
 * HAPPY_NETWORK_PROFILE resolution for terminal-launched agent sessions.
 *
 * A session started without the env var silently runs pure-legacy: it shows
 * up in daemon session lists but has no ISCP RPC bridge, so a phone can list
 * it yet never reach it (OPS 2026-08-17 session recovery incident, P0-C).
 * Resolve the profile BEFORE spawning instead of guessing later:
 * - daemon-spawned sessions are exempt (the daemon injects the profile);
 * - env set (non-empty): must name a healthy enrolled profile, else fail fast;
 * - env set to '': explicit legacy opt-out, honored silently;
 * - env unset, no profiles enrolled: legacy, silent;
 * - env unset, exactly one healthy profile: safe to auto-select (announced);
 * - env unset, several healthy profiles: fail fast — never guess identities;
 * - env unset, profiles enrolled but none healthy: loud warning, then legacy.
 */

import { createNobleProvider } from '@slopus/iscp'

import { inspectProfile, listProfiles, type ProfileInspection } from '@/iscp/enrollment'

export type IscpProfileResolution =
  | { mode: 'legacy'; warning?: string }
  | { mode: 'iscp'; profileId: string; announcement?: string }

export interface IscpProfileProbe {
  list: () => string[]
  inspect: (profileId: string) => ProfileInspection
}

function defaultProbe(): IscpProfileProbe {
  const provider = createNobleProvider()
  return {
    list: listProfiles,
    inspect: (profileId) => inspectProfile(provider, profileId),
  }
}

/** Throws on fail-fast conditions; the CLI entry prints the error and exits. */
export function resolveIscpProfile(opts: {
  startedBy?: string
  envValue: string | undefined
  command: string
  probe?: IscpProfileProbe
}): IscpProfileResolution {
  if (opts.startedBy === 'daemon') {
    // The daemon decided the mode when it spawned us; never second-guess it.
    return opts.envValue !== undefined && opts.envValue !== ''
      ? { mode: 'iscp', profileId: opts.envValue }
      : { mode: 'legacy' }
  }
  const probe = opts.probe ?? defaultProbe()

  if (opts.envValue === '') {
    return { mode: 'legacy' }
  }
  if (opts.envValue !== undefined) {
    const inspection = probe.inspect(opts.envValue)
    if (inspection.state !== 'healthy') {
      const reason = inspection.state === 'absent' ? 'no such enrolled profile' : inspection.reason
      throw new Error(
        `HAPPY_NETWORK_PROFILE=${opts.envValue} is not usable (${reason}). ` +
        `Fix the profile (happy iscp status ${opts.envValue} --check) or set HAPPY_NETWORK_PROFILE='' to run without ISCP.`,
      )
    }
    return { mode: 'iscp', profileId: opts.envValue }
  }

  const profiles = probe.list()
  if (profiles.length === 0) {
    return { mode: 'legacy' }
  }
  const healthy = profiles.filter((profileId) => probe.inspect(profileId).state === 'healthy')
  if (healthy.length === 1) {
    return {
      mode: 'iscp',
      profileId: healthy[0],
      announcement: `Using ISCP profile '${healthy[0]}' (the only healthy enrolled profile). Set HAPPY_NETWORK_PROFILE to override, or '' to opt out.`,
    }
  }
  if (healthy.length === 0) {
    return {
      mode: 'legacy',
      warning:
        `ISCP profiles are enrolled (${profiles.join(', ')}) but none is healthy; ` +
        `this session will run WITHOUT an ISCP bridge and will not be reachable from the app. ` +
        `Run 'happy iscp status <profile> --check' to repair.`,
    }
  }
  throw new Error(
    `Several healthy ISCP profiles are enrolled (${healthy.join(', ')}) and HAPPY_NETWORK_PROFILE is not set — ` +
    `refusing to guess which identity '${opts.command}' should use. ` +
    `Run HAPPY_NETWORK_PROFILE=<profile> ${opts.command}, or HAPPY_NETWORK_PROFILE='' ${opts.command} for legacy mode.`,
  )
}

/**
 * Apply the resolution to process.env before the session spawns. Throws on
 * fail-fast conditions (propagates to the command's error handler).
 */
export function ensureIscpProfileEnv(command: string, startedBy?: string, probe?: IscpProfileProbe): void {
  const resolution = resolveIscpProfile({
    startedBy,
    envValue: process.env.HAPPY_NETWORK_PROFILE,
    command,
    probe,
  })
  if (resolution.mode === 'iscp') {
    process.env.HAPPY_NETWORK_PROFILE = resolution.profileId
    if (resolution.announcement) console.log(resolution.announcement)
  } else if (resolution.warning) {
    console.error(resolution.warning)
  }
}
