/**
 * Daemon event log — the single history source for ISCP mode (frozen
 * decision #3 of the dual-stack plan: the daemon owns session history; the
 * app pulls by cursor; the relay only does live delivery + short-TTL queues).
 *
 * Layout (under ~/.happy/iscp/<profileId>/eventlog/):
 *   sessions/<sessionId>/log.jsonl   append-only, one JSON record per line
 *   sessions/<sessionId>/meta.json   { epoch, lastSeq, ...lifecycle } (atomic rename write)
 *
 * Guarantees:
 * - seq is monotonically increasing per session, assigned by this log;
 * - appends are idempotent by localId: a retried append returns the existing
 *   seq without writing a second record (same dedupe contract as the legacy
 *   /v3 messages endpoint);
 * - epoch is minted when a session log is first created; a cursor carrying a
 *   different epoch means the log was reset and the reader must re-sync from
 *   scratch (see WireCursorPayload in @slopus/happy-wire).
 */

import { appendFileSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync, readdirSync } from 'node:fs'
import { randomUUID } from 'node:crypto'
import { join } from 'node:path'

export interface EventLogRecord {
  seq: number
  localId?: string
  body: unknown
  at: number
}

export interface EventLogAppendResult {
  seq: number
  epoch: string
  deduped: boolean
}

export interface EventLogReadResult {
  events: EventLogRecord[]
  lastSeq: number
  epoch: string
  hasMore: boolean
}

export interface SessionDescription {
  displayName?: string
  directory?: string
  agentType?: string
}

export interface SessionMeta extends SessionDescription {
  epoch: string
  lastSeq: number
  createdAt?: number
  lastActiveAt?: number
  archived?: boolean
}

interface SessionLogState extends SessionMeta {
  /** localId → seq for idempotent appends. */
  localIds: Map<string, number>
}

/**
 * On-disk meta.json. All fields beyond {epoch, lastSeq} are additive and
 * optional: logs written before the lifecycle fields existed parse unchanged.
 */
type SessionMetaFile = SessionMeta

export class DaemonEventLog {
  private readonly sessions = new Map<string, SessionLogState>()

  constructor(private readonly rootDir: string) {}

  private sessionDir(sessionId: string): string {
    if (sessionId === '' || sessionId.includes('/') || sessionId.includes('\\') || sessionId === '.' || sessionId === '..') {
      throw new Error(`invalid session id for event log: ${JSON.stringify(sessionId)}`)
    }
    return join(this.rootDir, 'sessions', sessionId)
  }

  /** Load (or lazily create) in-memory state for a session log. */
  private state(sessionId: string, createIfMissing: boolean): SessionLogState | null {
    const cached = this.sessions.get(sessionId)
    if (cached) return cached

    const dir = this.sessionDir(sessionId)
    const metaFile = join(dir, 'meta.json')
    const logFile = join(dir, 'log.jsonl')

    if (!existsSync(metaFile)) {
      if (!createIfMissing) return null
      mkdirSync(dir, { recursive: true, mode: 0o700 })
      const fresh: SessionLogState = { epoch: randomUUID(), lastSeq: 0, createdAt: Date.now(), localIds: new Map() }
      this.writeMeta(sessionId, fresh)
      this.sessions.set(sessionId, fresh)
      return fresh
    }

    const meta = JSON.parse(readFileSync(metaFile, 'utf8')) as SessionMetaFile
    const state: SessionLogState = { ...meta, localIds: new Map() }
    // Rebuild the dedupe index (and recover lastSeq if meta lagged a crash —
    // the log line is appended before meta is rewritten).
    if (existsSync(logFile)) {
      for (const line of readFileSync(logFile, 'utf8').split('\n')) {
        if (line === '') continue
        const record = JSON.parse(line) as EventLogRecord
        if (record.localId !== undefined) state.localIds.set(record.localId, record.seq)
        if (record.seq > state.lastSeq) state.lastSeq = record.seq
      }
    }
    this.sessions.set(sessionId, state)
    return state
  }

  private writeMeta(sessionId: string, state: SessionLogState): void {
    const dir = this.sessionDir(sessionId)
    const metaFile = join(dir, 'meta.json')
    const tmpFile = metaFile + '.tmp'
    const { localIds: _localIds, ...meta } = state
    writeFileSync(tmpFile, JSON.stringify(meta satisfies SessionMetaFile), { mode: 0o600 })
    renameSync(tmpFile, metaFile)
  }

  /** Append one event. Idempotent by localId. */
  append(sessionId: string, body: unknown, localId?: string): EventLogAppendResult {
    const state = this.state(sessionId, true)!
    if (localId !== undefined) {
      const existing = state.localIds.get(localId)
      if (existing !== undefined) {
        return { seq: existing, epoch: state.epoch, deduped: true }
      }
    }
    const seq = state.lastSeq + 1
    const record: EventLogRecord = {
      seq,
      ...(localId !== undefined ? { localId } : {}),
      body,
      at: Date.now(),
    }
    appendFileSync(join(this.sessionDir(sessionId), 'log.jsonl'), JSON.stringify(record) + '\n', { mode: 0o600 })
    state.lastSeq = seq
    state.lastActiveAt = record.at
    if (localId !== undefined) state.localIds.set(localId, seq)
    this.writeMeta(sessionId, state)
    return { seq, epoch: state.epoch, deduped: false }
  }

  /**
   * Persist display attributes so history entries stay identifiable after the
   * process exits. Creates the log if needed (a spawned session may be
   * described before its first event). No-op when nothing changes.
   */
  describe(sessionId: string, description: SessionDescription): void {
    const state = this.state(sessionId, true)!
    let changed = false
    for (const key of ['displayName', 'directory', 'agentType'] as const) {
      const value = description[key]
      if (value !== undefined && state[key] !== value) {
        state[key] = value
        changed = true
      }
    }
    if (changed) this.writeMeta(sessionId, state)
  }

  /** Mark a historical session as archived (or restore it). */
  setArchived(sessionId: string, archived: boolean): boolean {
    const state = this.state(sessionId, false)
    if (!state) return false
    if ((state.archived ?? false) !== archived) {
      state.archived = archived
      this.writeMeta(sessionId, state)
    }
    return true
  }

  /** Read events with seq > afterSeq, up to limit. */
  read(sessionId: string, afterSeq: number, limit: number): EventLogReadResult | null {
    const state = this.state(sessionId, false)
    if (!state) return null
    const logFile = join(this.sessionDir(sessionId), 'log.jsonl')
    const events: EventLogRecord[] = []
    let hasMore = false
    if (existsSync(logFile)) {
      for (const line of readFileSync(logFile, 'utf8').split('\n')) {
        if (line === '') continue
        const record = JSON.parse(line) as EventLogRecord
        if (record.seq <= afterSeq) continue
        if (events.length >= limit) {
          hasMore = true
          break
        }
        events.push(record)
      }
    }
    return { events, lastSeq: state.lastSeq, epoch: state.epoch, hasMore }
  }

  /** Session metadata without reading the log body. */
  sessionInfo(sessionId: string): SessionMeta | null {
    const state = this.state(sessionId, false)
    if (!state) return null
    const { localIds: _localIds, ...meta } = state
    return meta
  }

  listSessions(): string[] {
    const dir = join(this.rootDir, 'sessions')
    if (!existsSync(dir)) return []
    return readdirSync(dir).filter((entry) => existsSync(join(dir, entry, 'meta.json')))
  }
}
