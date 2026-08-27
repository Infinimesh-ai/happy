import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'

import { DaemonEventLog } from './eventLog'
import { TextViewLog, type TextViewProjectionTrace, type TextViewRecord } from './textViewLog'

/** The production Codex bodies from OPS 2026-08-18 §10.16 (seq 1–8). */
const CODEX_BODIES: Array<{ localId: string; body: unknown }> = [
  { localId: 'jingsi-37CD4599-F2FD-4A5A-B8C6-506A14DAB50E', body: { content: { type: 'text', text: '你好' }, localKey: 'jingsi-37CD4599-F2FD-4A5A-B8C6-506A14DAB50E', role: 'user' } },
  { localId: 'raw-2', body: { role: 'session', content: { id: 'hzg7p120nbryhqjpmljgqtk3', time: 1787210360745, role: 'agent', turn: 'wkiyvih5h2q4yhzgh6cqakst', ev: { t: 'turn-start' } }, meta: { sentFrom: 'cli' } } },
  { localId: 'raw-3', body: { role: 'session', content: { id: 'p88navwp70szsuwxjfrvd77v', time: 1787210365354, role: 'agent', usage: { input_tokens: 12042, output_tokens: 66 }, ev: { t: 'service', text: '' } }, meta: { sentFrom: 'cli' } } },
  { localId: 'raw-4', body: { role: 'session', content: { id: 'e56y52ycuq2pj6tp2014j19s', time: 1787210368162, role: 'agent', usage: { input_tokens: 12679, output_tokens: 21 }, ev: { t: 'service', text: '' } }, meta: { sentFrom: 'cli' } } },
  { localId: 'raw-5', body: { role: 'session', content: { id: 'ori39x6jae2tofh4lglcwlio', time: 1787210371565, role: 'agent', turn: 'wkiyvih5h2q4yhzgh6cqakst', ev: { t: 'text', text: '你好！有什么我可以帮你处理的？' } }, meta: { sentFrom: 'cli' } } },
  { localId: 'raw-6', body: { role: 'session', content: { id: 'wt3ioyd9hd300nseqgo2l92v', time: 1787210371567, role: 'agent', turn: 'wkiyvih5h2q4yhzgh6cqakst', ev: { t: 'turn-end', status: 'completed' } }, meta: { sentFrom: 'cli' } } },
  { localId: 'raw-7', body: { role: 'agent', content: { id: 'f7dfeb45-1cd9-4a9a-b703-a40042078b23', type: 'event', data: { type: 'ready' } } } },
  { localId: 'raw-8', body: { role: 'session', content: { id: 'iszvgosmrb33ngsforko9zay', time: 1787210371603, role: 'agent', usage: { input_tokens: 458, output_tokens: 14 }, ev: { t: 'service', text: '' } }, meta: { sentFrom: 'cli' } } },
]

describe('TextViewLog', () => {
  let root: string
  let raw: DaemonEventLog
  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), 'iscp-textview-'))
    raw = new DaemonEventLog(root)
  })
  afterEach(() => {
    rmSync(root, { recursive: true, force: true })
  })

  const ingestCodex = (sessionId = 'sess') => {
    for (const event of CODEX_BODIES) raw.append(sessionId, event.body, event.localId)
  }

  it('projects the Codex seq 1–8 history to two contiguous view records', () => {
    ingestCodex()
    const view = new TextViewLog(raw, root)
    const page = view.read('sess', 0, 100)!
    expect(page.events.map((e) => e.viewSeq)).toEqual([1, 2])
    expect(page.events[0]).toMatchObject({
      viewSeq: 1,
      rawSeq: 1,
      localId: 'jingsi-37CD4599-F2FD-4A5A-B8C6-506A14DAB50E',
      body: { role: 'user', content: { type: 'text', text: '你好' } },
    })
    expect(page.events[1]).toMatchObject({
      viewSeq: 2,
      rawSeq: 5,
      body: { role: 'agent', content: { type: 'text', text: '你好！有什么我可以帮你处理的？' } },
    })
    expect(page.lastSeq).toBe(2)
    expect(page.hasMore).toBe(false)
    // The raw log is untouched: still all 8 events.
    expect(raw.read('sess', 0, 100)!.events).toHaveLength(8)
  })

  it('keeps the projection watermark idempotent across incremental syncs and re-reads', () => {
    ingestCodex()
    const view = new TextViewLog(raw, root)
    expect(view.sync('sess')!.map((r) => r.viewSeq)).toEqual([1, 2])
    expect(view.sync('sess')).toEqual([])
    raw.append('sess', { role: 'session', content: { id: 'x2hqjpmljgqtk3hzg7p120nb', time: 1, role: 'agent', ev: { t: 'text', text: 'again' } } }, 'raw-9')
    expect(view.sync('sess')!.map((r) => r.viewSeq)).toEqual([3])
    expect(view.read('sess', 0, 100)!.events).toHaveLength(3)
  })

  it('first migration of an existing raw history is deterministic (same records, new epoch per build)', () => {
    ingestCodex()
    const first = new TextViewLog(raw, root)
    const firstPage = first.read('sess', 0, 100)!

    rmSync(join(root, 'sessions', 'sess', 'textview.v2.jsonl'))
    rmSync(join(root, 'sessions', 'sess', 'textview.v2.meta.json'))
    const second = new TextViewLog(new DaemonEventLog(root), root)
    const secondPage = second.read('sess', 0, 100)!

    expect(secondPage.events).toEqual(firstPage.events)
    expect(secondPage.epoch).not.toBe(firstPage.epoch)
  })

  it('survives reload: view seq continues, epoch stable, localId index rebuilt', () => {
    ingestCodex()
    const first = new TextViewLog(raw, root)
    const epoch = first.read('sess', 0, 100)!.epoch

    const reloadedRaw = new DaemonEventLog(root)
    reloadedRaw.append('sess', { role: 'session', content: { id: 'xx2qjpmljgqtk3hzg7p120nb', time: 2, role: 'agent', ev: { t: 'text', text: 'later' } } }, 'raw-9')
    const reloaded = new TextViewLog(reloadedRaw, root)
    const page = reloaded.read('sess', 0, 100)!
    expect(page.epoch).toBe(epoch)
    expect(page.events.map((e) => e.viewSeq)).toEqual([1, 2, 3])
    expect(reloaded.viewSeqForLocalId('sess', 'jingsi-37CD4599-F2FD-4A5A-B8C6-506A14DAB50E')).toBe(1)
  })

  it('recovers when meta lagged a crash (view line on disk, stale meta)', () => {
    ingestCodex()
    const view = new TextViewLog(raw, root)
    view.sync('sess')
    // Simulate the crash window: rewind meta to before the last append.
    const metaFile = join(root, 'sessions', 'sess', 'textview.v2.meta.json')
    const meta = JSON.parse(readFileSync(metaFile, 'utf8'))
    writeFileSync(metaFile, JSON.stringify({ ...meta, lastViewSeq: 0, rawWatermark: 0 }))

    const recovered = new TextViewLog(new DaemonEventLog(root), root)
    const page = recovered.read('sess', 0, 100)!
    // No duplicates: the file scan recovers both counters.
    expect(page.events.map((e) => e.viewSeq)).toEqual([1, 2])
    expect(page.epoch).toBe(meta.viewEpoch)
  })

  it('rebuilds under a fresh epoch when the raw log was reset', () => {
    ingestCodex()
    const view = new TextViewLog(raw, root)
    const before = view.read('sess', 0, 100)!

    // Raw reset: wipe the session dir and write a new log (new raw epoch).
    rmSync(join(root, 'sessions', 'sess'), { recursive: true, force: true })
    const newRaw = new DaemonEventLog(root)
    newRaw.append('sess', { role: 'user', content: { type: 'text', text: 'fresh start' } }, 'local-new')

    const rebuilt = new TextViewLog(newRaw, root)
    const after = rebuilt.read('sess', 0, 100)!
    expect(after.epoch).not.toBe(before.epoch)
    expect(after.events.map((e) => e.viewSeq)).toEqual([1])
    expect(after.events[0].body).toMatchObject({ role: 'user', content: { type: 'text', text: 'fresh start' } })
  })

  it('pages with limit/hasMore over a long history (500-page contract)', () => {
    for (let i = 1; i <= 505; i++) {
      raw.append('sess', { role: 'user', content: { type: 'text', text: `m${i}` } }, `local-${i}`)
    }
    const view = new TextViewLog(raw, root)
    const page1 = view.read('sess', 0, 500)!
    expect(page1.events).toHaveLength(500)
    expect(page1.hasMore).toBe(true)
    const page2 = view.read('sess', 500, 500)!
    expect(page2.events.map((e) => e.viewSeq)).toEqual([501, 502, 503, 504, 505])
    expect(page2.hasMore).toBe(false)
  })

  it('fires onAppend for every materialized record no matter which entry point synced', () => {
    ingestCodex()
    const appended: Array<{ sessionId: string; record: TextViewRecord; epoch: string }> = []
    const view = new TextViewLog(raw, root, undefined, (sessionId, record, epoch) => {
      appended.push({ sessionId, record, epoch })
    })
    view.info('sess')
    expect(appended.map((a) => a.record.viewSeq)).toEqual([1, 2])
    expect(new Set(appended.map((a) => a.epoch)).size).toBe(1)
  })

  it('traces projections without body content', () => {
    ingestCodex()
    const traces: TextViewProjectionTrace[] = []
    const view = new TextViewLog(raw, root, (trace) => traces.push(trace))
    view.sync('sess')
    expect(traces).toHaveLength(8)
    expect(traces.filter((t) => t.emitted)).toHaveLength(2)
    expect(traces.find((t) => t.rawSeq === 5)).toMatchObject({ kind: 'session-text', emitted: true, viewSeq: 2, textLength: 15 })
    expect(traces.find((t) => t.rawSeq === 7)).toMatchObject({ kind: 'legacy-agent-event', emitted: false })
    for (const trace of traces) {
      expect(JSON.stringify(trace)).not.toContain('你好')
    }
  })

  it('returns null for sessions with no raw log and never creates view files for them', () => {
    const view = new TextViewLog(raw, root)
    expect(view.sync('missing')).toBeNull()
    expect(view.read('missing', 0, 10)).toBeNull()
    expect(view.info('missing')).toBeNull()
    expect(existsSync(join(root, 'sessions', 'missing'))).toBe(false)
  })
})
