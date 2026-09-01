/**
 * Daemon-side ISCP session initiator (OPS 2026-08-17 §4.2): after the relay
 * peer starts, the daemon PROACTIVELY opens the E2E session towards the
 * grant audience (the phone) instead of waiting as a passive responder.
 *
 * State machine per profile:
 *   connecting → ready                      openSession resolved (manifests exchanged)
 *   ready → peer_stale → reopening          authenticated/controlled reopen fired
 *   reopening → ready                        fresh Session id/transcript and manifests exchanged
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

export type ProfileSessionState = 'connecting' | 'ready' | 'peer_stale' | 'reopening' | 'authorization_expired' | 'failed'

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
  /** Current verified Session metadata. No transcript material is exposed. */
  sessionId?: string
  sessionRole?: 'initiator' | 'responder'
  sessionAttempt: number
  sessionReopenCount: number
  sessionReopenCoalesceCount: number
  helloAttemptCount: number
  helloSupersededCount: number
  helloCoalescedCount: number
  pendingCount: number
  sessionLastVerifiedAt?: number
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
    // identity_unavailable is scoped to the peer-identity lookup: the trust
    // client's parseError prefixes every deviceStatus failure with the stable
    // 'device status' context. A 404 from any OTHER call (e.g. a relay route)
    // must not read as an unresolvable peer — that misclassification hid the
    // slice-20 trust contract fix behind a relay-side 404.
    if (error.code === IscpErrorCodes.AccessInvalid && message.includes('device status')) {
      return { kind: 'fatal', category: 'identity_unavailable' }
    }
    if (error.code === IscpErrorCodes.AccessInvalid) return { kind: 'fatal', category: 'transport_failed' }
    return { kind: 'fatal', category: 'protocol_error' }
  }
  return { kind: 'retry', resetSession: false }
}

export const SESSION_BACKOFF_SCHEDULE_MS = [5_000, 10_000, 20_000, 30_000, 60_000]
export interface SessionRuntimeStatus {
  sessionId: string
  role: 'initiator' | 'responder'
  lastAuthenticatedAt?: number
}

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
  /** Keep the supervisor alive after ready so controlled reopen can wake it. */
  superviseReopen?: boolean
  /**
   * Optional authenticated-idle policy for non-managed deployments. Managed
   * Happy profiles deliberately omit it: an idle/offline phone must not
   * cause an unbounded queue of Hellos.
   */
  livenessWindowMs?: number
  /** Metadata-only activity source from IscpPeer. */
  sessionStatus?: () => SessionRuntimeStatus | undefined
  /** Clear generation-scoped consumers immediately before closing the old Session. */
  onBeforeReopen?: (cause: string, previous: SessionRuntimeStatus | undefined) => void
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
  /**
   * Ask a ready Session to re-open. Concurrent requests coalesce; returns
   * false while an initial connection/reopen is already in progress.
   */
  requestReopen: (cause?: string) => boolean
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
  let phase: ProfileSessionState = 'connecting'
  let reopenRequested: { cause: string; resolve: () => void } | undefined
  let reopenWakePending = false

  const waitForReopen = async (windowMs?: number): Promise<string | undefined> => {
    while (!signal.aborted) {
      const lastVerifiedAt = deps.sessionStatus?.()?.lastAuthenticatedAt ?? now()
      const remaining = windowMs === undefined
        ? undefined
        : Math.max(0, lastVerifiedAt + windowMs - now())
      let timerElapsed = false
      const controlled = new Promise<void>((resolve) => {
        reopenRequested = { cause: reopenRequested?.cause ?? 'controlled_reopen', resolve }
      })
      if (remaining === undefined) {
        await controlled
      } else {
        await Promise.race([
          sleep(remaining, signal).then(() => { timerElapsed = true }),
          controlled,
        ])
      }
      if (signal.aborted) return undefined
      if ((!timerElapsed || remaining === undefined) && reopenRequested !== undefined) {
        const cause = reopenRequested.cause
        reopenRequested = undefined
        reopenWakePending = false
        return cause
      }
      reopenRequested = undefined
      reopenWakePending = false
      if (windowMs === undefined) continue
      const latestVerifiedAt = deps.sessionStatus?.()?.lastAuthenticatedAt ?? lastVerifiedAt
      if (latestVerifiedAt + windowMs <= now()) return 'liveness_window_elapsed'
      // Authenticated activity arrived while the timer was running. Keep the
      // same Session and wait only for the new remainder.
    }
    return undefined
  }

  const done = (async () => {
    let attempt = 0
    let hasBeenReady = false
    while (!signal.aborted) {
      if (deps.grantExpiresAt().getTime() <= now()) {
        deps.onState('authorization_expired', 'grant_expired')
        deps.log(`trust grant for peer ${deps.peerDeviceId} has expired; run: happy iscp renew <renewal-id>`)
        return
      }
      phase = hasBeenReady ? 'reopening' : 'connecting'
      deps.onState(phase)
      try {
        await deps.openSession(deps.peerDeviceId, { timeoutMs })
        if (signal.aborted) return
        phase = 'ready'
        deps.onState('ready')
        deps.log(`session ready with peer ${deps.peerDeviceId} (manifests exchanged)`)
        attempt = 0
        if (deps.superviseReopen !== true && deps.livenessWindowMs === undefined) return
        const cause = await waitForReopen(deps.livenessWindowMs)
        if (signal.aborted || cause === undefined) return
        const previous = deps.sessionStatus?.()
        phase = 'peer_stale'
        deps.onState('peer_stale', cause)
        deps.onBeforeReopen?.(cause, previous)
        deps.closeSession(deps.peerDeviceId)
        hasBeenReady = true
        continue
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

  return {
    stop: () => {
      controller.abort()
      reopenRequested?.resolve()
      reopenRequested = undefined
      reopenWakePending = false
    },
    requestReopen: (cause = 'controlled_reopen') => {
      if (signal.aborted || phase !== 'ready' || reopenRequested === undefined || reopenWakePending) return false
      reopenWakePending = true
      reopenRequested.cause = cause
      reopenRequested.resolve()
      return true
    },
    done,
  }
}
