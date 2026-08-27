/**
 * Materialized phone/text view of the daemon event log (OPS 2026-08-18
 * §10.16). The raw log stays the canonical, untouched history for the
 * official Happy client and diagnostics; a text-permission peer is served
 * from this derived log instead, with its OWN monotonically contiguous
 * seq/cursor/epoch — raw seqs are never exposed with holes, so a live gap
 * cannot send the phone into a re-pull loop and hidden pages still advance
 * the phone cursor.
 *
 * Layout (next to the raw files, under sessions/<sessionId>/):
 *   textview.v3.jsonl       one projected record per line
 *   textview.v3.meta.json   { viewEpoch, lastViewSeq, rawWatermark, rawEpoch }
 *
 * Invariants:
 * - projection is the single pure projector from @slopus/happy-wire
 *   (projectPhoneTextView); history pulls and live pushes share it by
 *   construction because both read THIS materialized log;
 * - rawWatermark is the highest raw seq ever considered (emitted or
 *   dropped); sync() only looks above it, so re-ingest, restarts and
 *   live/pull overlap are idempotent and localIds are preserved verbatim;
 * - record.at copies the raw record's timestamp, so a rebuild from the same
 *   raw log reproduces the identical view (only viewEpoch differs);
 * - a raw-log epoch change (log reset) or a missing/corrupt view state
 *   discards the view and rebuilds it deterministically under a NEW
 *   viewEpoch, forcing the app to re-sync from the projected history only.
 *
 * The version in the file names is the projector contract version: bumping
 * projection rules means new file names, a fresh build and a new epoch.
 */

import { appendFileSync, existsSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { randomUUID } from 'node:crypto'
import { join } from 'node:path'

import { projectPhoneTextView, type PhoneTextViewBody } from '@slopus/happy-wire'

import type { DaemonEventLog } from '@/iscp/eventLog'

export interface TextViewRecord {
  viewSeq: number
  /** Raw event-log seq this record was projected from (diagnostics only; never a wire cursor). */
  rawSeq: number
  localId?: string
  body: PhoneTextViewBody
  at: number
}

export interface TextViewReadResult {
  events: TextViewRecord[]
  lastSeq: number
  epoch: string
  hasMore: boolean
}

export interface TextViewInfo {
  epoch: string
  lastSeq: number
}

/** Structured projection trace for the P1 logging contract — no body content. */
export interface TextViewProjectionTrace {
  sessionId: string
  rawSeq: number
  kind: string
  emitted: boolean
  viewSeq?: number
  textLength?: number
  dropReason?: string
}

interface TextViewMetaFile {
  viewEpoch: string
  lastViewSeq: number
  rawWatermark: number
  rawEpoch: string
}

interface TextViewState extends TextViewMetaFile {
  /** localId → viewSeq, so messages.send can answer with a VIEW cursor. */
  localIds: Map<string, number>
}

const SYNC_BATCH = 500

export class TextViewLog {
  private readonly sessions = new Map<string, TextViewState>()

  constructor(
    private readonly raw: DaemonEventLog,
    private readonly rootDir: string,
    private readonly onProjection?: (trace: TextViewProjectionTrace) => void,
    /**
     * Fires for every newly materialized record no matter which entry point
     * triggered the sync (ingest, pull, list, send lookup) — the live-push
     * fan-out subscribes here so a pull-triggered catch-up still reaches
     * subscribed peers. Push+pull duplicate delivery of the same viewSeq is
     * fine: consumers dedupe by cursor.
     */
    private readonly onAppend?: (sessionId: string, record: TextViewRecord, viewEpoch: string) => void,
  ) {}

  private sessionDir(sessionId: string): string {
    // The raw log has already validated the id (same directory), but this
    // class is independently reachable — keep the same guard.
    if (sessionId === '' || sessionId.includes('/') || sessionId.includes('\\') || sessionId === '.' || sessionId === '..') {
      throw new Error(`invalid session id for text view log: ${JSON.stringify(sessionId)}`)
    }
    return join(this.rootDir, 'sessions', sessionId)
  }

  private viewFile(sessionId: string): string {
    return join(this.sessionDir(sessionId), 'textview.v3.jsonl')
  }

  private metaFile(sessionId: string): string {
    return join(this.sessionDir(sessionId), 'textview.v3.meta.json')
  }

  private writeMeta(sessionId: string, state: TextViewState): void {
    const metaFile = this.metaFile(sessionId)
    const tmpFile = metaFile + '.tmp'
    const { localIds: _localIds, ...meta } = state
    writeFileSync(tmpFile, JSON.stringify(meta satisfies TextViewMetaFile), { mode: 0o600 })
    renameSync(tmpFile, metaFile)
  }

  /**
   * Load (or initialize) view state for a session that has a raw log with
   * epoch `rawEpoch`. A missing meta file is the first migration; a raw
   * epoch mismatch or unreadable state is a reset — both start an empty view
   * under a fresh viewEpoch (sync() then rebuilds deterministically).
   */
  private state(sessionId: string, rawEpoch: string): TextViewState {
    const cached = this.sessions.get(sessionId)
    if (cached && cached.rawEpoch === rawEpoch) return cached

    let state: TextViewState | null = null
    if (existsSync(this.metaFile(sessionId))) {
      try {
        const meta = JSON.parse(readFileSync(this.metaFile(sessionId), 'utf8')) as TextViewMetaFile
        if (meta.rawEpoch === rawEpoch) {
          state = { ...meta, localIds: new Map() }
          // The view line is appended before meta is rewritten; recover both
          // counters from the log if meta lagged a crash. Dropped raw events
          // above the last emitted line are re-projected (and re-dropped) —
          // harmless, emitted ones are covered by the file scan.
          if (existsSync(this.viewFile(sessionId))) {
            for (const line of readFileSync(this.viewFile(sessionId), 'utf8').split('\n')) {
              if (line === '') continue
              const record = JSON.parse(line) as TextViewRecord
              if (record.localId !== undefined) state.localIds.set(record.localId, record.viewSeq)
              if (record.viewSeq > state.lastViewSeq) state.lastViewSeq = record.viewSeq
              if (record.rawSeq > state.rawWatermark) state.rawWatermark = record.rawSeq
            }
          }
        }
      } catch {
        state = null
      }
    }
    if (state === null) {
      state = { viewEpoch: randomUUID(), lastViewSeq: 0, rawWatermark: 0, rawEpoch, localIds: new Map() }
      writeFileSync(this.viewFile(sessionId), '', { mode: 0o600 })
      this.writeMeta(sessionId, state)
    }
    this.sessions.set(sessionId, state)
    return state
  }

  /**
   * Project raw events above the watermark into the view. Returns the
   * records appended by THIS call (for live push). Null when the session has
   * no raw log at all.
   */
  sync(sessionId: string): TextViewRecord[] | null {
    const rawInfo = this.raw.sessionInfo(sessionId)
    if (!rawInfo) return null
    const state = this.state(sessionId, rawInfo.epoch)
    const appended: TextViewRecord[] = []
    while (state.rawWatermark < rawInfo.lastSeq) {
      const page = this.raw.read(sessionId, state.rawWatermark, SYNC_BATCH)
      if (!page || page.events.length === 0) break
      for (const raw of page.events) {
        const projection = projectPhoneTextView(raw.body)
        state.rawWatermark = raw.seq
        if (projection.emit !== null) {
          const record: TextViewRecord = {
            viewSeq: state.lastViewSeq + 1,
            rawSeq: raw.seq,
            ...(raw.localId !== undefined ? { localId: raw.localId } : {}),
            body: projection.emit,
            at: raw.at,
          }
          appendFileSync(this.viewFile(sessionId), JSON.stringify(record) + '\n', { mode: 0o600 })
          state.lastViewSeq = record.viewSeq
          if (record.localId !== undefined) state.localIds.set(record.localId, record.viewSeq)
          appended.push(record)
          this.onAppend?.(sessionId, record, state.viewEpoch)
          this.onProjection?.({
            sessionId,
            rawSeq: raw.seq,
            kind: projection.kind,
            emitted: true,
            viewSeq: record.viewSeq,
            textLength: 'text' in projection.emit.content
              ? projection.emit.content.text.length
              : 'toolName' in projection.emit.content && typeof projection.emit.content.toolName === 'string'
                ? projection.emit.content.toolName.length
                : 0,
          })
        } else {
          this.onProjection?.({
            sessionId,
            rawSeq: raw.seq,
            kind: projection.kind,
            emitted: false,
            dropReason: projection.dropReason,
          })
        }
      }
      this.writeMeta(sessionId, state)
      if (!page.hasMore) break
    }
    return appended
  }

  /** Read view events with viewSeq > afterSeq. Syncs first (idempotent catch-up). */
  read(sessionId: string, afterSeq: number, limit: number): TextViewReadResult | null {
    if (this.sync(sessionId) === null) return null
    const state = this.sessions.get(sessionId)!
    const events: TextViewRecord[] = []
    let hasMore = false
    if (existsSync(this.viewFile(sessionId))) {
      for (const line of readFileSync(this.viewFile(sessionId), 'utf8').split('\n')) {
        if (line === '') continue
        const record = JSON.parse(line) as TextViewRecord
        if (record.viewSeq <= afterSeq) continue
        if (events.length >= limit) {
          hasMore = true
          break
        }
        events.push(record)
      }
    }
    return { events, lastSeq: state.lastViewSeq, epoch: state.viewEpoch, hasMore }
  }

  /** View cursor facts for sessions.list / cursor minting. Syncs first. */
  info(sessionId: string): TextViewInfo | null {
    if (this.sync(sessionId) === null) return null
    const state = this.sessions.get(sessionId)!
    return { epoch: state.viewEpoch, lastSeq: state.lastViewSeq }
  }

  /**
   * The view seq a given localId projected to (messages.send answers with a
   * view cursor so the phone's cursor line stays contiguous). Null when the
   * send did not project — the caller must treat that as a contract error,
   * not fall back to a raw seq.
   */
  viewSeqForLocalId(sessionId: string, localId: string): number | null {
    if (this.sync(sessionId) === null) return null
    return this.sessions.get(sessionId)!.localIds.get(localId) ?? null
  }
}
