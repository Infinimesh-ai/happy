/**
 * Session initiator loop (OPS 2026-08-17 §4.2) against a fake peer:
 * ready on success, closeSession + backoff on timeout, authorization_expired
 * on grant expiry (local and remote), fatal classification, stop()
 * cancellation, and the 5→10→20→30→60s capped backoff schedule.
 */

import { describe, expect, it } from 'vitest'

import { IscpErrorCodes, iscpError } from '@slopus/iscp'

import {
  classifySessionFailure,
  startSessionInitiator,
  SESSION_BACKOFF_SCHEDULE_MS,
  type ProfileSessionState,
  type SessionInitiatorDeps,
} from '@/iscp/sessionInitiator'

const PEER = 'dev_phone_1'
const FUTURE = new Date(Date.now() + 3600_000)

interface Harness {
  states: Array<{ state: ProfileSessionState; detail?: string }>
  closes: string[]
  sleeps: number[]
  logs: string[]
  deps: SessionInitiatorDeps
}

function harness(openSession: SessionInitiatorDeps['openSession'], overrides?: Partial<SessionInitiatorDeps>): Harness {
  const h: Harness = { states: [], closes: [], sleeps: [], logs: [], deps: undefined as unknown as SessionInitiatorDeps }
  h.deps = {
    peerDeviceId: PEER,
    openSession,
    closeSession: (id) => h.closes.push(id),
    grantExpiresAt: () => FUTURE,
    onState: (state, detail) => h.states.push({ state, ...(detail !== undefined ? { detail } : {}) }),
    log: (line) => h.logs.push(line),
    jitterRatio: 0,
    sleep: async (ms) => {
      h.sleeps.push(ms)
    },
    ...overrides,
  }
  return h
}

function timeoutError() {
  return iscpError(IscpErrorCodes.SessionInvalid, 'timed out waiting for peer session', { retryable: true })
}

describe('classifySessionFailure', () => {
  it('classifies per the frozen matrix', () => {
    expect(classifySessionFailure(timeoutError())).toEqual({ kind: 'retry', resetSession: true })
    expect(classifySessionFailure(iscpError(IscpErrorCodes.AccessInvalid, 'relay throttled', { retryable: true }))).toEqual({ kind: 'retry', resetSession: false })
    expect(classifySessionFailure(new TypeError('fetch failed'))).toEqual({ kind: 'retry', resetSession: false })
    expect(classifySessionFailure(iscpError(IscpErrorCodes.TrustInvalid, 'device has been revoked'))).toEqual({ kind: 'fatal', category: 'revoked' })
    expect(classifySessionFailure(iscpError(IscpErrorCodes.TrustInvalid, 'trust grant is not currently valid'))).toEqual({ kind: 'fatal', category: 'grant_expired' })
    expect(classifySessionFailure(iscpError(IscpErrorCodes.AccessInvalid, 'device status failed with status 404'))).toEqual({ kind: 'fatal', category: 'identity_unavailable' })
    // Only the device-status context reads as identity trouble: the same
    // wire failure from any other call is a transport problem.
    expect(classifySessionFailure(iscpError(IscpErrorCodes.AccessInvalid, 'device status failed with status 500'))).toEqual({ kind: 'fatal', category: 'identity_unavailable' })
    expect(classifySessionFailure(iscpError(IscpErrorCodes.AccessInvalid, 'envelope submit failed with status 404'))).toEqual({ kind: 'fatal', category: 'transport_failed' })
    expect(classifySessionFailure(iscpError(IscpErrorCodes.AccessInvalid, 'access credential invalid'))).toEqual({ kind: 'fatal', category: 'transport_failed' })
    expect(classifySessionFailure(iscpError(IscpErrorCodes.EnvelopeInvalid, 'malformed envelope'))).toEqual({ kind: 'fatal', category: 'protocol_error' })
  })
})

describe('startSessionInitiator', () => {
  it('success: connecting → ready, loop ends, no retries', async () => {
    const calls: string[] = []
    const h = harness(async (id) => {
      calls.push(id)
      return { manifest: true }
    })
    const loop = startSessionInitiator(h.deps)
    await loop.done
    expect(calls).toEqual([PEER])
    expect(h.states).toEqual([{ state: 'connecting' }, { state: 'ready' }])
    expect(h.sleeps).toEqual([])
    expect(h.closes).toEqual([])
  })

  it('timeout: closeSession BEFORE the backoff retry, then succeeds', async () => {
    let attempt = 0
    const order: string[] = []
    const h = harness(async () => {
      attempt += 1
      order.push(`open-${attempt}`)
      if (attempt === 1) throw timeoutError()
      return {}
    })
    h.deps.closeSession = (id) => {
      h.closes.push(id)
      order.push('close')
    }
    const loop = startSessionInitiator(h.deps)
    await loop.done
    expect(order).toEqual(['open-1', 'close', 'open-2'])
    expect(h.closes).toEqual([PEER])
    expect(h.sleeps).toEqual([SESSION_BACKOFF_SCHEDULE_MS[0]])
    expect(h.states.at(-1)).toEqual({ state: 'ready' })
  })

  it('retryable failures back off 5→10→20→30→60s and cap at 60s', async () => {
    let attempt = 0
    const h = harness(async () => {
      attempt += 1
      if (attempt <= 7) throw iscpError(IscpErrorCodes.EnvelopeInvalid, 'relay unavailable', { retryable: true })
      return {}
    })
    const loop = startSessionInitiator(h.deps)
    await loop.done
    expect(h.sleeps).toEqual([5_000, 10_000, 20_000, 30_000, 60_000, 60_000, 60_000])
    expect(h.states.at(-1)).toEqual({ state: 'ready' })
    expect(h.closes).toEqual([]) // non-session retryables do not reset the session
  })

  it('applies ±20% jitter by default', async () => {
    let attempt = 0
    const h = harness(async () => {
      attempt += 1
      if (attempt <= 20) throw iscpError(IscpErrorCodes.EnvelopeInvalid, 'unavailable', { retryable: true })
      return {}
    }, { jitterRatio: undefined }) // undefined → the 0.2 default applies
    const loop = startSessionInitiator(h.deps)
    await loop.done
    for (const [i, ms] of h.sleeps.entries()) {
      const base = SESSION_BACKOFF_SCHEDULE_MS[Math.min(i, SESSION_BACKOFF_SCHEDULE_MS.length - 1)]!
      expect(ms).toBeGreaterThanOrEqual(base * 0.8 - 1)
      expect(ms).toBeLessThanOrEqual(base * 1.2 + 1)
    }
  })

  it('locally expired grant: authorization_expired without any openSession call, renew hint logged', async () => {
    const calls: string[] = []
    const h = harness(async (id) => {
      calls.push(id)
      return {}
    }, { grantExpiresAt: () => new Date(Date.now() - 1000) })
    const loop = startSessionInitiator(h.deps)
    await loop.done
    expect(calls).toEqual([])
    expect(h.states).toEqual([{ state: 'authorization_expired', detail: 'grant_expired' }])
    expect(h.logs.join('\n')).toContain('happy iscp renew')
    expect(h.sleeps).toEqual([]) // no tight reconnect attempts on an invalid grant
  })

  it('remotely rejected expired grant: authorization_expired, loop ends', async () => {
    const h = harness(async () => {
      throw iscpError(IscpErrorCodes.TrustInvalid, 'trust grant is not currently valid')
    })
    const loop = startSessionInitiator(h.deps)
    await loop.done
    expect(h.states.at(-1)).toEqual({ state: 'authorization_expired', detail: 'grant_expired' })
    expect(h.logs.join('\n')).toContain('happy iscp renew')
    expect(h.sleeps).toEqual([])
  })

  it('non-retryable failure: failed(<category>), loop ends, no initial-enrollment fallback', async () => {
    let calls = 0
    const h = harness(async () => {
      calls += 1
      throw iscpError(IscpErrorCodes.TrustInvalid, 'device has been revoked')
    })
    const loop = startSessionInitiator(h.deps)
    await loop.done
    expect(calls).toBe(1)
    expect(h.states.at(-1)).toEqual({ state: 'failed', detail: 'revoked' })
    expect(h.logs.join('\n')).toContain('revoked')
    expect(h.logs.join('\n')).not.toContain('enroll') // never suggests re-enrollment automatically
  })

  it('stop() cancels a pending attempt: no further retries once the promise settles', async () => {
    let calls = 0
    let rejectPending: ((error: unknown) => void) | undefined
    const h = harness(() => {
      calls += 1
      return new Promise((_resolve, reject) => {
        rejectPending = reject
      })
    })
    const loop = startSessionInitiator(h.deps)
    await new Promise((resolve) => setTimeout(resolve, 10))
    expect(calls).toBe(1)
    loop.stop()
    // The daemon pairs stop() with closeSession(), which rejects the waiter.
    rejectPending!(timeoutError())
    await loop.done
    expect(calls).toBe(1)
    expect(h.closes).toEqual([]) // aborted before the retry path ran closeSession
  })

  it('stop() during backoff cancels before the next attempt', async () => {
    let calls = 0
    let loopHandle: ReturnType<typeof startSessionInitiator> | undefined
    const h = harness(async () => {
      calls += 1
      throw iscpError(IscpErrorCodes.EnvelopeInvalid, 'unavailable', { retryable: true })
    })
    h.deps.sleep = async (ms) => {
      h.sleeps.push(ms)
      loopHandle!.stop() // abort mid-backoff
    }
    loopHandle = startSessionInitiator(h.deps)
    await loopHandle.done
    expect(calls).toBe(1)
    expect(h.sleeps).toHaveLength(1)
  })
})
