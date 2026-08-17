/**
 * Daemon-side ISCP service state: one DaemonEventLog per enrolled profile
 * plus a subscription fan-out for real-time wire events. Workstream 2 layers
 * the ISCP peer + wire responder on top of this; workstream 1 only ingests.
 */

import { EventEmitter } from 'node:events'
import { join } from 'node:path'

import { iscpProfileDir } from '@/iscp/enrollment'
import { DaemonEventLog, type EventLogAppendResult, type EventLogRecord } from '@/iscp/eventLog'

export interface IngestedSessionEvent {
  localId?: string
  body: unknown
}

export interface SessionEventNotification {
  profileId: string
  sessionId: string
  record: EventLogRecord
  epoch: string
  /** True when this append was a localId dedupe (no new record written). */
  deduped: boolean
}

export interface SessionLifecycleNotification {
  profileId: string
  sessionId: string
  change: 'added' | 'changed'
  reason: 'session_created' | 'agent_reachable' | 'agent_unreachable'
}

export class DaemonIscpService {
  /** Injectable for tests; defaults to the enrolled profile directory. */
  constructor(private readonly profileDirFor: (profileId: string) => string = iscpProfileDir) {}

  private readonly logs = new Map<string, DaemonEventLog>()
  /**
   * Emits 'session-event' with SessionEventNotification and
   * 'session-lifecycle' with SessionLifecycleNotification for live subscribers.
   */
  readonly events = new EventEmitter()
  /** sessionId → localhost RPC port of the running ISCP session process. */
  private readonly sessionRpcPorts = new Map<string, { profileId: string; port: number }>()

  /**
   * Sessions re-register on a heartbeat, so an unchanged registration is the
   * steady state; only changes are worth logging or pushing to peers.
   * Returns true when the registration is new or the port moved.
   */
  registerSessionRpcPort(profileId: string, sessionId: string, port: number): boolean {
    const existing = this.sessionRpcPorts.get(sessionId)
    if (existing?.profileId === profileId && existing.port === port) return false
    this.sessionRpcPorts.set(sessionId, { profileId, port })
    this.events.emit('session-lifecycle', {
      profileId,
      sessionId,
      change: 'changed',
      reason: 'agent_reachable',
    } satisfies SessionLifecycleNotification)
    return true
  }

  /** Drop a registration when the session process exits (agent unreachable). */
  unregisterSessionRpcPort(sessionId: string): void {
    const existing = this.sessionRpcPorts.get(sessionId)
    if (!existing) return
    this.sessionRpcPorts.delete(sessionId)
    this.events.emit('session-lifecycle', {
      profileId: existing.profileId,
      sessionId,
      change: 'changed',
      reason: 'agent_unreachable',
    } satisfies SessionLifecycleNotification)
  }

  /** The port is scoped to the owning profile: no cross-profile resolution. */
  sessionRpcPort(profileId: string, sessionId: string): number | null {
    const entry = this.sessionRpcPorts.get(sessionId)
    if (!entry || entry.profileId !== profileId) return null
    return entry.port
  }

  /**
   * Sessions whose agent RPC bridge is currently registered for a profile.
   * After a daemon restart the agent processes are NOT children of the new
   * daemon, but their lifetime heartbeat re-registers here within one
   * interval — a live registration is the daemon's proof of a reachable
   * agent, so liveness views must union this with the child-process table.
   */
  sessionIdsWithRpcPort(profileId: string): string[] {
    const ids: string[] = []
    for (const [sessionId, entry] of this.sessionRpcPorts) {
      if (entry.profileId === profileId) ids.push(sessionId)
    }
    return ids
  }

  /** All registered agent RPC bridges (for the daemon control /list view). */
  listRegisteredRpcSessions(): Array<{ sessionId: string; profileId: string; port: number }> {
    return [...this.sessionRpcPorts.entries()].map(([sessionId, entry]) => ({
      sessionId,
      profileId: entry.profileId,
      port: entry.port,
    }))
  }

  log(profileId: string): DaemonEventLog {
    if (profileId === '' || profileId.includes('/') || profileId.includes('\\') || profileId === '.' || profileId === '..') {
      throw new Error(`invalid ISCP profile id: ${JSON.stringify(profileId)}`)
    }
    let log = this.logs.get(profileId)
    if (!log) {
      log = new DaemonEventLog(join(this.profileDirFor(profileId), 'eventlog'))
      this.logs.set(profileId, log)
    }
    return log
  }

  /** Ingest a batch of session events (idempotent per localId). */
  ingest(profileId: string, sessionId: string, events: IngestedSessionEvent[]): EventLogAppendResult[] {
    const log = this.log(profileId)
    const isNewSession = log.sessionInfo(sessionId) === null
    const results: EventLogAppendResult[] = []
    for (const event of events) {
      const result = log.append(sessionId, event.body, event.localId)
      results.push(result)
      this.events.emit('session-event', {
        profileId,
        sessionId,
        record: { seq: result.seq, ...(event.localId !== undefined ? { localId: event.localId } : {}), body: event.body, at: Date.now() },
        epoch: result.epoch,
        deduped: result.deduped,
      } satisfies SessionEventNotification)
    }
    if (isNewSession && events.length > 0) {
      this.events.emit('session-lifecycle', {
        profileId,
        sessionId,
        change: 'added',
        reason: 'session_created',
      } satisfies SessionLifecycleNotification)
    }
    return results
  }
}
