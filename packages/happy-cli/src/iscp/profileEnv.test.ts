import { describe, expect, it } from 'vitest'

import { resolveIscpProfile, type IscpProfileProbe } from './profileEnv'
import type { ProfileInspection } from './enrollment'

const probe = (profiles: Record<string, ProfileInspection['state']>): IscpProfileProbe => ({
  list: () => Object.keys(profiles),
  inspect: (profileId) => {
    const state = profiles[profileId] ?? 'absent'
    if (state === 'healthy') return { state: 'healthy', bundle: {} as never, device: {} as never }
    if (state === 'absent') return { state: 'absent' }
    return { state: 'corrupt', reason: 'device.key is missing' }
  },
})

describe('resolveIscpProfile', () => {
  it('never second-guesses daemon-spawned sessions', () => {
    expect(resolveIscpProfile({ startedBy: 'daemon', envValue: 'cloud-prod', command: 'happy codex' }))
      .toEqual({ mode: 'iscp', profileId: 'cloud-prod' })
    expect(resolveIscpProfile({ startedBy: 'daemon', envValue: undefined, command: 'happy codex' }))
      .toEqual({ mode: 'legacy' })
  })

  it('honors an explicit empty value as a legacy opt-out', () => {
    expect(resolveIscpProfile({ envValue: '', command: 'happy codex', probe: probe({ 'cloud-prod': 'healthy' }) }))
      .toEqual({ mode: 'legacy' })
  })

  it('fails fast when the named profile is absent or corrupt', () => {
    expect(() => resolveIscpProfile({ envValue: 'ghost', command: 'happy codex', probe: probe({}) }))
      .toThrowError(/no such enrolled profile/)
    expect(() => resolveIscpProfile({ envValue: 'bad', command: 'happy codex', probe: probe({ bad: 'corrupt' }) }))
      .toThrowError(/device\.key is missing/)
  })

  it('runs legacy silently when nothing is enrolled', () => {
    expect(resolveIscpProfile({ envValue: undefined, command: 'happy codex', probe: probe({}) }))
      .toEqual({ mode: 'legacy' })
  })

  it('auto-selects the single healthy profile with an announcement', () => {
    const resolution = resolveIscpProfile({
      envValue: undefined,
      command: 'happy codex',
      probe: probe({ 'cloud-prod': 'healthy', broken: 'corrupt' }),
    })
    expect(resolution).toMatchObject({ mode: 'iscp', profileId: 'cloud-prod' })
    expect((resolution as { announcement?: string }).announcement).toContain('cloud-prod')
  })

  it('warns loudly (but proceeds legacy) when profiles exist yet none is healthy', () => {
    const resolution = resolveIscpProfile({ envValue: undefined, command: 'happy codex', probe: probe({ broken: 'corrupt' }) })
    expect(resolution.mode).toBe('legacy')
    expect((resolution as { warning?: string }).warning).toContain('WITHOUT an ISCP bridge')
  })

  it('refuses to guess between several healthy profiles', () => {
    expect(() => resolveIscpProfile({
      envValue: undefined,
      command: 'happy codex',
      probe: probe({ 'cloud-prod': 'healthy', 'cloud-staging': 'healthy' }),
    })).toThrowError(/refusing to guess/)
  })
})
