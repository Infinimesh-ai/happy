/**
 * Pins the network startup decision matrix (OPS 2026-08-26 §3.1/§4.1.4):
 * multi-profile, single-profile, explicit legacy opt-out, corrupt profile,
 * and zero-credential branches — for sessions and for the daemon. The
 * decision layer is pure; resolveSessionNetwork is exercised with injected IO
 * so no interactive login or real enrollment is needed.
 */

import { afterEach, beforeEach, describe, expect, it } from 'vitest'

import {
  decideDaemonNetwork,
  decideSessionNetwork,
  resolveSessionNetwork,
  ZERO_CREDENTIAL_GUIDANCE,
  type SessionNetworkIo,
} from '@/iscp/networkStartup'
import type { IscpProfileProbe } from '@/iscp/profileEnv'
import type { Credentials } from '@/persistence'

const LEGACY_CREDENTIALS: Credentials = {
  token: 'token',
  encryption: { type: 'legacy', secret: new Uint8Array(32) },
}

function probeOf(profiles: Record<string, 'healthy' | 'corrupt'>): IscpProfileProbe {
  return {
    list: () => Object.keys(profiles),
    inspect: (profileId) => {
      const state = profiles[profileId]
      if (state === undefined) return { state: 'absent' } as const
      if (state === 'healthy') return { state: 'healthy' } as any
      return { state: 'corrupt', reason: 'bundle unreadable' } as any
    },
  }
}

describe('decideSessionNetwork', () => {
  it('resolved profile + legacy credentials → dual-stack (legacy auth path preserved)', () => {
    expect(decideSessionNetwork({
      resolution: { mode: 'iscp', profileId: 'p1' },
      hasLegacyCredentials: true,
      explicitLegacyOptOut: false,
    })).toEqual({ kind: 'dual', profileId: 'p1' })
  })

  it('resolved profile without legacy credentials → ISCP-only, never legacy auth', () => {
    expect(decideSessionNetwork({
      resolution: { mode: 'iscp', profileId: 'p1' },
      hasLegacyCredentials: false,
      explicitLegacyOptOut: false,
    })).toEqual({ kind: 'iscp-only', profileId: 'p1' })
  })

  it('no profile + legacy credentials → legacy, silent', () => {
    expect(decideSessionNetwork({
      resolution: { mode: 'legacy' },
      hasLegacyCredentials: true,
      explicitLegacyOptOut: false,
    })).toEqual({ kind: 'legacy' })
  })

  it('unhealthy profiles + legacy credentials → legacy with the existing warning path', () => {
    expect(decideSessionNetwork({
      resolution: { mode: 'legacy', warning: 'none healthy' },
      hasLegacyCredentials: true,
      explicitLegacyOptOut: false,
    })).toEqual({ kind: 'legacy' })
  })

  it('unhealthy profiles without legacy credentials → hard error with repair guidance, no login', () => {
    const decision = decideSessionNetwork({
      resolution: { mode: 'legacy', warning: 'profiles enrolled but none is healthy' },
      hasLegacyCredentials: false,
      explicitLegacyOptOut: false,
    })
    expect(decision.kind).toBe('error')
    if (decision.kind === 'error') {
      expect(decision.message).toContain('none is healthy')
      expect(decision.message).toContain('happy iscp status')
    }
  })

  it("explicit HAPPY_NETWORK_PROFILE='' without credentials → legacy login is an explicit choice", () => {
    expect(decideSessionNetwork({
      resolution: { mode: 'legacy' },
      hasLegacyCredentials: false,
      explicitLegacyOptOut: true,
    })).toEqual({ kind: 'legacy-login' })
  })

  it('zero credentials of either kind → mode-selection guidance, never a default login', () => {
    expect(decideSessionNetwork({
      resolution: { mode: 'legacy' },
      hasLegacyCredentials: false,
      explicitLegacyOptOut: false,
    })).toEqual({ kind: 'choose' })
  })
})

describe('resolveSessionNetwork', () => {
  const savedProfileEnv = process.env.HAPPY_NETWORK_PROFILE
  beforeEach(() => { delete process.env.HAPPY_NETWORK_PROFILE })
  afterEach(() => {
    if (savedProfileEnv === undefined) delete process.env.HAPPY_NETWORK_PROFILE
    else process.env.HAPPY_NETWORK_PROFILE = savedProfileEnv
  })

  function io(overrides: Partial<SessionNetworkIo>): SessionNetworkIo {
    return {
      readCredentials: async () => null,
      runLegacyAuth: async () => { throw new Error('legacy auth must not run') },
      ensureMachineId: async () => 'machine-1',
      chooseMode: async () => { throw new Error('chooser must not open') },
      isInteractive: () => false,
      ...overrides,
    }
  }

  it('single healthy profile, no credentials → ISCP-only with env applied and machineId minted', async () => {
    const network = await resolveSessionNetwork('happy', undefined, io({
      probe: probeOf({ solo: 'healthy' }),
    }))
    expect(network).toEqual({ mode: 'iscp-only', profileId: 'solo', machineId: 'machine-1' })
    expect(process.env.HAPPY_NETWORK_PROFILE).toBe('solo')
  })

  it('single healthy profile with legacy credentials → dual-stack: env applied AND legacy auth runs', async () => {
    const network = await resolveSessionNetwork('happy', undefined, io({
      probe: probeOf({ solo: 'healthy' }),
      readCredentials: async () => LEGACY_CREDENTIALS,
      runLegacyAuth: async () => ({ credentials: LEGACY_CREDENTIALS, machineId: 'machine-2' }),
    }))
    expect(network.mode).toBe('legacy')
    expect(process.env.HAPPY_NETWORK_PROFILE).toBe('solo')
  })

  it('several healthy profiles, unspecified → fail fast, regardless of credentials', async () => {
    await expect(resolveSessionNetwork('happy', undefined, io({
      probe: probeOf({ a: 'healthy', b: 'healthy' }),
    }))).rejects.toThrow(/Several healthy ISCP profiles/)
  })

  it('explicit corrupt profile → fail fast with repair hint', async () => {
    process.env.HAPPY_NETWORK_PROFILE = 'broken'
    await expect(resolveSessionNetwork('happy', undefined, io({
      probe: probeOf({ broken: 'corrupt' }),
    }))).rejects.toThrow(/not usable/)
  })

  it('corrupt profiles only, no credentials → repair guidance error, no interactive login', async () => {
    await expect(resolveSessionNetwork('happy', undefined, io({
      probe: probeOf({ broken: 'corrupt' }),
    }))).rejects.toThrow(/none is healthy/)
  })

  it('zero credentials, non-interactive → guidance error naming both enrollment and legacy login', async () => {
    await expect(resolveSessionNetwork('happy', undefined, io({
      probe: probeOf({}),
    }))).rejects.toThrow(ZERO_CREDENTIAL_GUIDANCE.slice(0, 40))
  })

  it('zero credentials, interactive, user picks legacy → legacy login runs', async () => {
    const network = await resolveSessionNetwork('happy', undefined, io({
      probe: probeOf({}),
      isInteractive: () => true,
      chooseMode: async () => 'legacy',
      runLegacyAuth: async () => ({ credentials: LEGACY_CREDENTIALS, machineId: 'machine-3' }),
    }))
    expect(network).toEqual({ mode: 'legacy', credentials: LEGACY_CREDENTIALS, machineId: 'machine-3' })
  })

  it('daemon-spawned session inherits the daemon-injected profile without probing', async () => {
    process.env.HAPPY_NETWORK_PROFILE = 'injected'
    const network = await resolveSessionNetwork('happy', 'daemon', io({
      probe: probeOf({}), // would report the profile absent if consulted
    }))
    expect(network).toEqual({ mode: 'iscp-only', profileId: 'injected', machineId: 'machine-1' })
  })
})

describe('decideDaemonNetwork', () => {
  it('legacy credentials → legacy boot, verbatim, even with healthy profiles', () => {
    expect(decideDaemonNetwork({
      hasLegacyCredentials: true,
      profiles: ['p1'],
      healthyProfiles: ['p1'],
    })).toEqual({ kind: 'legacy' })
  })

  it('healthy profile without legacy credentials → ISCP-only boot', () => {
    expect(decideDaemonNetwork({
      hasLegacyCredentials: false,
      profiles: ['p1', 'p2'],
      healthyProfiles: ['p1'],
    })).toEqual({ kind: 'iscp-only', profiles: ['p1'] })
  })

  it('corrupt profiles only, no credentials → hard error with repair guidance', () => {
    const decision = decideDaemonNetwork({
      hasLegacyCredentials: false,
      profiles: ['broken'],
      healthyProfiles: [],
    })
    expect(decision.kind).toBe('error')
    if (decision.kind === 'error') {
      expect(decision.message).toContain('none is healthy')
    }
  })

  it('zero credentials → hard error with the shared guidance (daemon never prompts)', () => {
    const decision = decideDaemonNetwork({
      hasLegacyCredentials: false,
      profiles: [],
      healthyProfiles: [],
    })
    expect(decision.kind).toBe('error')
    if (decision.kind === 'error') {
      expect(decision.message).toBe(ZERO_CREDENTIAL_GUIDANCE)
    }
  })
})
