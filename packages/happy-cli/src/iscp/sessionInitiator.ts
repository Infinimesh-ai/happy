/**
 * Daemon-side ISCP session initiator (OPS 2026-08-17 §4.2): after the relay
 * peer starts, the daemon PROACTIVELY opens the E2E session towards the
 * grant audience (the phone) instead of waiting as a passive responder.
 *
 * State machine per profile:
 *   connecting → ready                      openSession resolved (manifests exchanged)
 *   connecting → authorization_expired      grant expired locally/remotely → `happy iscp renew`
 *   connecting → failed(<category>)         non-retryable failure; loop ends
 *
 * Retryable failures back off 5s → 10s → 20s → 30s → 60s (capped) with ±20%
 * jitter. An openSession timeout additionally calls closeSession first —
 * the SDK does not re-send the Hello for a lingering stale session, so the
 * entry must be dropped for the retry to make progress.
 *
 * This module is deliberately dependency-injected and free of heavy imports
 * so the loop is unit-testable with a fake peer.
 */

import { IscpError, IscpErrorCodes } from '@slopus/iscp'

export type ProfileSessionState = 'connecting' | 'ready' | 'authorization_expired' | 'failed'

/** Diagnostic snapshot of one profile's peer, served via GET /iscp/peer-status. */
export interface ProfilePeerStatus {
  profileId: string
  deviceId: string
  generation: number
  /** Relay WS transport state (CONNECTING/READY/CLOSED/...). */
  connectionState: string
  session: ProfileSessionState
  /** Failure category or extra detail (transport_failed / grant_expired / revoked / identity_unavailable / protocol_error). */
  sessionDetail?: string
  /** The grant audience this daemon dials (the phone device id). */
  peerDeviceId: string
}

export type SessionFailureCategory = 'transport_failed' | 'grant_expired' | 'revoked' | 'identity_unavailable' | 'protocol_error'

export type SessionFailureAction =
  | { kind: 'retry'; resetSession: boolean }
  | { kind: 'fatal'; category: SessionFailureCategory }

/**
 * Classify an openSession failure:
 * - retryable ISCP errors retry with backoff; a retryable session error
 *   (ISCPSESSION001 — the openSession timeout) additionally resets the
 *   half-open session first;
 * - non-ISCP errors (fetch/socket-level) are transient transport problems;
 * - non-retryable errors terminate the loop with a category.
 */
export function classifySessionFailure(error: unknown): SessionFailureAction {
  if (error instanceof IscpError) {
    if (error.retryable) {
      return { kind: 'retry', resetSession: error.code === IscpErrorCodes.SessionInvalid }
    }
    const message = error.message.toLowerCase()
    if (message.includes('revoked')) return { kind: 'fatal', category: 'revoked' }
    if (error.code === IscpErrorCodes.TrustInvalid && (message.includes('expired') || message.includes('not currently valid'))) {
      return { kind: 'fatal', category: 'grant_expired' }
    }
    if (error.code === IscpErrorCodes.AccessInvalid && (message.includes('status 404') || message.includes('not found') || message.includes('device status'))) {
      return { kind: 'fatal', category: 'identity_unavailable' }
    }
    if (error.code === IscpErrorCodes.AccessInvalid) return { kind: 'fatal', category: 'transport_failed' }
    return { kind: 'fatal', category: 'protocol_error' }
  }
  return { kind: 'retry', resetSession: false }
}

export const SESSION_BACKOFF_SCHEDULE_MS = [5_000, 10_000, 20_000, 30_000, 60_000]

export interface SessionInitiatorDeps {
  /** The grant audience — the phone allowed to control this machine. */
  peerDeviceId: string
  openSession: (peerDeviceId: string, opts: { timeoutMs: number }) => Promise<unknown>
  closeSession: (peerDeviceId: string) => void
  /** The trust grant expiry; checked locally at the start of every attempt. */
  grantExpiresAt: () => Date
  onState: (session: ProfileSessionState, detail?: string) => void
  /** Diagnostics only — MUST never receive secrets. */
  log: (line: string) => void
  /** Per-attempt openSession timeout (default 60s). */
  timeoutMs?: number
  backoffScheduleMs?: number[]
  /** Jitter ratio applied to each delay (default 0.2 = ±20%; tests pass 0). */
  jitterRatio?: number
  now?: () => number
  /** Cancellable delay; the default resolves early when the signal aborts. */
  sleep?: (ms: number, signal: AbortSignal) => Promise<void>
}

function defaultSleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise<void>((resolve) => {
    if (signal.aborted) {
      resolve()
      return
    }
    const onAbort = () => {
      clearTimeout(timer)
      resolve()
    }
    const timer = setTimeout(() => {
      signal.removeEventListener('abort', onAbort)
      resolve()
    }, ms)
    signal.addEventListener('abort', onAbort, { once: true })
  })
}

export interface SessionInitiatorHandle {
  /** Cancel the loop. Callers should also closeSession() so a pending openSession settles. */
  stop: () => void
  /** Resolves when the loop has fully terminated. Never rejects. */
  done: Promise<void>
}

export function startSessionInitiator(deps: SessionInitiatorDeps): SessionInitiatorHandle {
  const controller = new AbortController()
  const signal = controller.signal
  const schedule = deps.backoffScheduleMs ?? SESSION_BACKOFF_SCHEDULE_MS
  const jitterRatio = deps.jitterRatio ?? 0.2
  const now = deps.now ?? (() => Date.now())
  const sleep = deps.sleep ?? defaultSleep
  const timeoutMs = deps.timeoutMs ?? 60_000

  const done = (async () => {
    let attempt = 0
    while (!signal.aborted) {
      if (deps.grantExpiresAt().getTime() <= now()) {
        deps.onState('authorization_expired', 'grant_expired')
        deps.log(`trust grant for peer ${deps.peerDeviceId} has expired; run: happy iscp renew <renewal-id>`)
        return
      }
      deps.onState('connecting')
      try {
        await deps.openSession(deps.peerDeviceId, { timeoutMs })
        if (signal.aborted) return
        deps.onState('ready')
        deps.log(`session ready with peer ${deps.peerDeviceId} (manifests exchanged)`)
        return
      } catch (error) {
        if (signal.aborted) return
        const action = classifySessionFailure(error)
        if (action.kind === 'fatal') {
          if (action.category === 'grant_expired') {
            deps.onState('authorization_expired', action.category)
            deps.log(`trust grant for peer ${deps.peerDeviceId} is no longer valid; run: happy iscp renew <renewal-id>`)
          } else {
            deps.onState('failed', action.category)
            deps.log(`session with peer ${deps.peerDeviceId} failed permanently (${action.category})`)
          }
          return
        }
        if (action.resetSession) {
          // Timeout: drop the half-open session so the retry re-sends Hello.
          deps.closeSession(deps.peerDeviceId)
        }
        const base = schedule[Math.min(attempt, schedule.length - 1)]!
        const jitter = base * jitterRatio
        const delay = Math.max(0, Math.round(base + (Math.random() * 2 - 1) * jitter))
        attempt += 1
        await sleep(delay, signal)
      }
    }
  })().catch(() => {
    /* the loop never throws; belt and braces */
  })

  return { stop: () => controller.abort(), done }
}
