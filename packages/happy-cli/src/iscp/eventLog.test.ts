import { mkdtempSync, rmSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'

import { DaemonEventLog } from './eventLog'

describe('DaemonEventLog', () => {
  let root: string
  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), 'iscp-eventlog-'))
  })
  afterEach(() => {
    rmSync(root, { recursive: true, force: true })
  })

  it('assigns monotonic seq per session and persists epoch', () => {
    const log = new DaemonEventLog(root)
    const a1 = log.append('sess-a', { t: 'one' }, 'local-1')
    const a2 = log.append('sess-a', { t: 'two' }, 'local-2')
    const b1 = log.append('sess-b', { t: 'other' })
    expect(a1.seq).toBe(1)
    expect(a2.seq).toBe(2)
    expect(b1.seq).toBe(1)
    expect(a1.epoch).toBe(a2.epoch)
    expect(a1.epoch).not.toBe(b1.epoch)
  })

  it('dedupes by localId, returning the original seq (idempotent resend)', () => {
    const log = new DaemonEventLog(root)
    const first = log.append('sess', { t: 'msg' }, 'local-1')
    const retry = log.append('sess', { t: 'msg' }, 'local-1')
    expect(retry).toEqual({ seq: first.seq, epoch: first.epoch, deduped: true })
    const read = log.read('sess', 0, 100)!
    expect(read.events).toHaveLength(1)
  })

  it('reads after a cursor with limit and hasMore', () => {
    const log = new DaemonEventLog(root)
    for (let i = 1; i <= 5; i++) log.append('sess', { i })
    const page1 = log.read('sess', 0, 2)!
    expect(page1.events.map((e) => e.seq)).toEqual([1, 2])
    expect(page1.hasMore).toBe(true)
    const page2 = log.read('sess', 2, 10)!
    expect(page2.events.map((e) => e.seq)).toEqual([3, 4, 5])
    expect(page2.hasMore).toBe(false)
    expect(page2.lastSeq).toBe(5)
  })

  it('survives reload: seq continues, dedupe index rebuilt, epoch stable', () => {
    const first = new DaemonEventLog(root)
    const r1 = first.append('sess', { t: 'a' }, 'local-1')

    const reloaded = new DaemonEventLog(root)
    const dedupe = reloaded.append('sess', { t: 'a' }, 'local-1')
    expect(dedupe).toEqual({ seq: r1.seq, epoch: r1.epoch, deduped: true })
    const next = reloaded.append('sess', { t: 'b' }, 'local-2')
    expect(next.seq).toBe(r1.seq + 1)
    expect(next.epoch).toBe(r1.epoch)
  })

  it('recovers lastSeq from the log when meta lags a crash', () => {
    const log = new DaemonEventLog(root)
    log.append('sess', { t: 'a' })
    log.append('sess', { t: 'b' })
    // Simulate a crash where meta.json was left behind at lastSeq 1.
    const metaFile = join(root, 'sessions', 'sess', 'meta.json')
    const meta = JSON.parse(readFileSync(metaFile, 'utf8'))
    meta.lastSeq = 1
    writeFileSync(metaFile, JSON.stringify(meta))

    const reloaded = new DaemonEventLog(root)
    expect(reloaded.append('sess', { t: 'c' }).seq).toBe(3)
  })

  it('tracks lifecycle metadata: createdAt, lastActiveAt, describe, archive', () => {
    const log = new DaemonEventLog(root)
    const before = Date.now()
    log.append('sess', { t: 'a' })
    const info = log.sessionInfo('sess')!
    expect(info.createdAt).toBeGreaterThanOrEqual(before)
    expect(info.lastActiveAt).toBeGreaterThanOrEqual(before)

    log.describe('sess', { displayName: 'My Session', directory: '/tmp/proj', agentType: 'codex' })
    expect(log.setArchived('sess', true)).toBe(true)
    expect(log.setArchived('missing', true)).toBe(false)

    // All lifecycle fields survive a reload (persisted in meta.json).
    const reloaded = new DaemonEventLog(root)
    const meta = reloaded.sessionInfo('sess')!
    expect(meta).toMatchObject({
      displayName: 'My Session',
      directory: '/tmp/proj',
      agentType: 'codex',
      archived: true,
    })
    expect(meta.createdAt).toBe(info.createdAt)
  })

  it('parses pre-lifecycle meta.json written before the additive fields existed', () => {
    const log = new DaemonEventLog(root)
    log.append('sess', { t: 'a' })
    // Rewrite meta in the legacy {epoch, lastSeq} shape.
    const metaFile = join(root, 'sessions', 'sess', 'meta.json')
    const meta = JSON.parse(readFileSync(metaFile, 'utf8'))
    writeFileSync(metaFile, JSON.stringify({ epoch: meta.epoch, lastSeq: meta.lastSeq }))

    const reloaded = new DaemonEventLog(root)
    const info = reloaded.sessionInfo('sess')!
    expect(info.epoch).toBe(meta.epoch)
    expect(info.createdAt).toBeUndefined()
    expect(info.archived).toBeUndefined()
    // Appending upgrades the meta in place without touching the epoch.
    reloaded.append('sess', { t: 'b' })
    expect(reloaded.sessionInfo('sess')!.lastActiveAt).toBeDefined()
    expect(reloaded.sessionInfo('sess')!.epoch).toBe(meta.epoch)
  })

  it('lists sessions and rejects path-traversal session ids', () => {
    const log = new DaemonEventLog(root)
    log.append('sess-a', {})
    log.append('sess-b', {})
    expect(log.listSessions().sort()).toEqual(['sess-a', 'sess-b'])
    expect(() => log.append('../evil', {})).toThrowError(/invalid session id/)
    expect(log.read('missing', 0, 10)).toBeNull()
  })
})
