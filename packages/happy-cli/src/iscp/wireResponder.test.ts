import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { decodeWireCursor } from '@slopus/happy-wire'

import { DaemonIscpService, type SessionLifecycleNotification } from './daemonIscp'
import { WireResponder, type WireResponderDeps } from './wireResponder'
import type { TrackedSession } from '@/daemon/types'


describe('WireResponder', () => {
  let root: string
  let iscp: DaemonIscpService
  let responder: WireResponder
  const spawnSession = vi.fn(async () => ({ type: 'success' as const, sessionId: 'sess-new' }))
  const stopSession = vi.fn(() => true)

  const okFetch = vi.fn(async () => new Response(JSON.stringify({ ok: true, result: null }), { status: 200 }))
  const downFetch = vi.fn(async () => {
    throw new Error('connect ECONNREFUSED')
  })

  const build = (overrides?: Partial<WireResponderDeps>) => new WireResponder({
    iscp,
    profileId: 'p1',
    view: 'raw',
    getChildren: () => [],
    stopSession,
    spawnSession,
    ...overrides,
  })

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), 'iscp-wire-'))
    iscp = new DaemonIscpService((profileId) => join(root, profileId))
    responder = build()
    spawnSession.mockClear()
    okFetch.mockClear()
    downFetch.mockClear()
  })
  afterEach(() => {
    rmSync(root, { recursive: true, force: true })
  })

  it('messages.send requires idempotencyKey and dedupes delivered resends', async () => {
    iscp.registerSessionRpcPort('p1', 's1', 4242)
    responder = build({ fetchImpl: okFetch as unknown as typeof fetch })

    const missing = await responder.handle({ id: 'r1', method: 'messages.send', params: { sessionId: 's1', body: { t: 'hi' } } })
    expect(missing).toMatchObject({ ok: false, error: { code: 'invalid' } })

    const first = await responder.handle({ id: 'r2', method: 'messages.send', params: { sessionId: 's1', body: { t: 'hi' } }, idempotencyKey: 'k1' })
    const retry = await responder.handle({ id: 'r3', method: 'messages.send', params: { sessionId: 's1', body: { t: 'hi' } }, idempotencyKey: 'k1' })
    expect(first).toMatchObject({ ok: true, result: { seq: 1, deduped: false, delivery: 'delivered' } })
    expect(retry).toMatchObject({ ok: true, result: { seq: 1, deduped: true, delivery: 'delivered' } })
    // Confirmed-delivered dedupe does NOT re-forward.
    expect(okFetch).toHaveBeenCalledTimes(1)

    const pull = await responder.handle({ id: 'r4', method: 'messages.pull', params: { sessionId: 's1' } })
    expect(pull.ok).toBe(true)
    const result = (pull as { ok: true; result: { events: unknown[] } }).result
    expect(result.events).toHaveLength(1)
  })

  it('messages.send fails retryable when the agent is unreachable, then redelivers on retry', async () => {
    // No RPC port registered at all → persisted but not delivered.
    const noBridge = await responder.handle({ id: 'r1', method: 'messages.send', params: { sessionId: 's1', body: { t: 'hi' } }, idempotencyKey: 'k1' })
    expect(noBridge).toMatchObject({ ok: false, error: { code: 'retryable' } })
    // The idempotent outbox kept the message.
    const pull = await responder.handle({ id: 'r2', method: 'messages.pull', params: { sessionId: 's1' } })
    expect((pull as { ok: true; result: { events: unknown[] } }).result.events).toHaveLength(1)

    // Bridge up but fetch fails → still retryable.
    iscp.registerSessionRpcPort('p1', 's1', 4242)
    responder = build({ fetchImpl: downFetch as unknown as typeof fetch })
    const stillDown = await responder.handle({ id: 'r3', method: 'messages.send', params: { sessionId: 's1', body: { t: 'hi' } }, idempotencyKey: 'k1' })
    expect(stillDown).toMatchObject({ ok: false, error: { code: 'retryable' } })

    // Agent back → the SAME idempotencyKey now delivers (dedupe reuses seq 1
    // but the forward is re-attempted, not suppressed by the outbox).
    responder = build({ fetchImpl: okFetch as unknown as typeof fetch })
    const delivered = await responder.handle({ id: 'r4', method: 'messages.send', params: { sessionId: 's1', body: { t: 'hi' } }, idempotencyKey: 'k1' })
    expect(delivered).toMatchObject({ ok: true, result: { seq: 1, deduped: true, delivery: 'delivered' } })
    expect(okFetch).toHaveBeenCalledTimes(1)
  })

  it('messages.send does not resolve a port registered by another profile', async () => {
    iscp.registerSessionRpcPort('p2', 's1', 4242)
    responder = build({ fetchImpl: okFetch as unknown as typeof fetch })
    const response = await responder.handle({ id: 'r1', method: 'messages.send', params: { sessionId: 's1', body: {} }, idempotencyKey: 'k1' })
    expect(response).toMatchObject({ ok: false, error: { code: 'retryable' } })
    expect(okFetch).not.toHaveBeenCalled()
  })

  it('messages.pull resumes from a cursor and flags stale-epoch resets', async () => {
    iscp.registerSessionRpcPort('p1', 's1', 4242)
    responder = build({ fetchImpl: okFetch as unknown as typeof fetch })
    await responder.handle({ id: 'a', method: 'messages.send', params: { sessionId: 's1', body: { n: 1 } }, idempotencyKey: 'k1' })
    await responder.handle({ id: 'b', method: 'messages.send', params: { sessionId: 's1', body: { n: 2 } }, idempotencyKey: 'k2' })
    const page1 = await responder.handle({ id: 'c', method: 'messages.pull', params: { sessionId: 's1', limit: 1 } })
    const r1 = (page1 as { ok: true; result: { events: Array<{ cursor: string }>; hasMore: boolean } }).result
    expect(r1.hasMore).toBe(true)

    const page2 = await responder.handle({ id: 'd', method: 'messages.pull', params: { sessionId: 's1', afterCursor: r1.events[0].cursor } })
    const r2 = (page2 as { ok: true; result: { events: Array<{ seq: number }>; reset: boolean } }).result
    expect(r2.events.map((e) => e.seq)).toEqual([2])
    expect(r2.reset).toBe(false)

    // Foreign/stale cursor → reset flag + full history from 0.
    const cursor = decodeWireCursor(r1.events[0].cursor)!
    const staleEpoch = r1.events[0].cursor.replace(cursor.epoch, 'other-epoch')
    const page3 = await responder.handle({ id: 'e', method: 'messages.pull', params: { sessionId: 's1', afterCursor: staleEpoch } })
    const r3 = (page3 as { ok: true; result: { events: unknown[]; reset: boolean } }).result
    expect(r3.reset).toBe(true)
    expect(r3.events).toHaveLength(2)
  })

  it('sessions.spawn injects HAPPY_NETWORK_PROFILE', async () => {
    const response = await responder.handle({ id: 's', method: 'sessions.spawn', params: { directory: '/tmp/proj' }, idempotencyKey: 'spawn-1' })
    expect(response).toMatchObject({ ok: true, result: { sessionId: 'sess-new' } })
    expect(spawnSession).toHaveBeenCalledWith(expect.objectContaining({
      directory: '/tmp/proj',
      environmentVariables: { HAPPY_NETWORK_PROFILE: 'p1' },
    }))
  })

  it('sessions.list exposes lifecycle, last-active and display attributes', async () => {
    const child: TrackedSession = {
      startedBy: 'daemon',
      happySessionId: 'sess-live',
      pid: 4321,
      happySessionMetadataFromLocalWebhook: {
        path: '/tmp/proj',
        host: 'localhost',
        name: 'My Project',
        flavor: 'codex',
        homeDir: '/home/u',
        happyHomeDir: '/home/u/.happy',
        happyLibDir: '/home/u/.happy/lib',
        happyToolsDir: '/home/u/.happy/tools',
      },
    }
    responder = build({ getChildren: () => [child] })
    // Historical sessions: one idle, one archived.
    iscp.ingest('p1', 'sess-old', [{ body: { t: 'x' } }])
    iscp.ingest('p1', 'sess-archived', [{ body: { t: 'y' } }])
    iscp.log('p1').setArchived('sess-archived', true)

    const response = await responder.handle({ id: 'l', method: 'sessions.list', params: {} })
    const { sessions } = (response as { ok: true; result: { sessions: Array<Record<string, unknown>> } }).result
    const byId = new Map(sessions.map((s) => [s.sessionId, s]))
    expect(byId.get('sess-live')).toMatchObject({
      active: true,
      lifecycle: 'active',
      displayName: 'My Project',
      directory: '/tmp/proj',
      agentType: 'codex',
    })
    expect(byId.get('sess-old')).toMatchObject({ active: false, lifecycle: 'idle' })
    expect(byId.get('sess-old')!.lastActiveAt).toBeDefined()
    expect(byId.get('sess-archived')).toMatchObject({ active: false, lifecycle: 'archived' })

    // Display attributes were persisted: they survive the process exiting.
    responder = build({ getChildren: () => [] })
    const after = await responder.handle({ id: 'l2', method: 'sessions.list', params: {} })
    const gone = (after as { ok: true; result: { sessions: Array<Record<string, unknown>> } }).result.sessions
      .find((s) => s.sessionId === 'sess-live')
    expect(gone).toMatchObject({ active: false, lifecycle: 'idle', displayName: 'My Project' })
  })

  it('sessions.archive folds history away and refuses running sessions', async () => {
    const child: TrackedSession = { startedBy: 'daemon', happySessionId: 'sess-live', pid: 1 }
    responder = build({ getChildren: () => [child] })
    iscp.ingest('p1', 'sess-old', [{ body: {} }])

    expect(await responder.handle({ id: 'a', method: 'sessions.archive', params: { sessionId: 'sess-live' } }))
      .toMatchObject({ ok: false, error: { code: 'conflict' } })
    expect(await responder.handle({ id: 'b', method: 'sessions.archive', params: { sessionId: 'ghost' } }))
      .toMatchObject({ ok: false, error: { code: 'not_found' } })
    expect(await responder.handle({ id: 'c', method: 'sessions.archive', params: { sessionId: 'sess-old' } }))
      .toMatchObject({ ok: true, result: { sessionId: 'sess-old', archived: true } })
    expect(await responder.handle({ id: 'd', method: 'sessions.archive', params: { sessionId: 'sess-old', archived: false } }))
      .toMatchObject({ ok: true, result: { archived: false } })
  })

  it('rejects unknown methods as unsupported and keeps wakeup.v1 as a hook point', async () => {
    expect(await responder.handle({ id: 'x', method: 'nope', params: {} })).toMatchObject({ ok: false, error: { code: 'unsupported' } })
    expect(await responder.handle({ id: 'w', method: 'wakeup.v1', params: {} })).toMatchObject({ ok: false, error: { code: 'unsupported' } })
  })

  it('daemon restart: heartbeat re-registration alone marks the session active and fires session.lifecycle', async () => {
    // Life before the restart: the session ran as a child and left history
    // (and display attributes) in the on-disk event log.
    const child: TrackedSession = {
      startedBy: 'daemon',
      happySessionId: 'sess-survivor',
      pid: 4321,
      happySessionMetadataFromLocalWebhook: {
        path: '/tmp/proj',
        host: 'localhost',
        name: 'Survivor',
        homeDir: '/home/u',
        happyHomeDir: '/home/u/.happy',
        happyLibDir: '/home/u/.happy/lib',
        happyToolsDir: '/home/u/.happy/tools',
      },
    }
    responder = build({ getChildren: () => [child] })
    iscp.ingest('p1', 'sess-survivor', [{ body: { t: 'hello' } }])
    await responder.handle({ id: 'l0', method: 'sessions.list', params: {} })

    // Daemon restart: fresh in-memory state over the same on-disk log — the
    // agent process survives but is NOT a child of the new daemon.
    const restarted = new DaemonIscpService((profileId) => join(root, profileId))
    const lifecycle: SessionLifecycleNotification[] = []
    restarted.events.on('session-lifecycle', (n: SessionLifecycleNotification) => lifecycle.push(n))
    const listSessions = async (r: WireResponder) => {
      const response = await r.handle({ id: 'l', method: 'sessions.list', params: {} })
      return (response as { ok: true; result: { sessions: Array<Record<string, unknown>> } }).result.sessions
    }
    const freshResponder = new WireResponder({
      iscp: restarted,
      profileId: 'p1',
      view: 'raw',
      getChildren: () => [],
      stopSession,
      spawnSession,
    })

    // Before the heartbeat lands, the session reads as idle history.
    const before = await listSessions(freshResponder)
    expect(before.find((s) => s.sessionId === 'sess-survivor')).toMatchObject({ active: false, lifecycle: 'idle' })

    // The agent's lifetime heartbeat re-registers its RPC port with the new
    // daemon → the machine-event source fires (the app converges without
    // polling) and sessions.list reports active despite no child entry.
    restarted.registerSessionRpcPort('p1', 'sess-survivor', 4242)
    expect(lifecycle).toEqual([
      { profileId: 'p1', sessionId: 'sess-survivor', change: 'changed', reason: 'agent_reachable' },
    ])
    const after = await listSessions(freshResponder)
    const survivor = after.find((s) => s.sessionId === 'sess-survivor')
    expect(survivor).toMatchObject({ active: true, lifecycle: 'active', displayName: 'Survivor' })
    // No child-process entry means no pid — the field stays optional/absent.
    expect(survivor!.pid).toBeUndefined()

    // A reattached agent is running: archiving it must conflict.
    expect(await freshResponder.handle({ id: 'a', method: 'sessions.archive', params: { sessionId: 'sess-survivor' } }))
      .toMatchObject({ ok: false, error: { code: 'conflict' } })

    // When the registration drops (agent exit), the session folds back to
    // idle and the unreachable transition fires.
    restarted.unregisterSessionRpcPort('sess-survivor')
    expect(lifecycle[1]).toEqual({ profileId: 'p1', sessionId: 'sess-survivor', change: 'changed', reason: 'agent_unreachable' })
    const gone = await listSessions(freshResponder)
    expect(gone.find((s) => s.sessionId === 'sess-survivor')).toMatchObject({ active: false, lifecycle: 'idle' })
  })

  it('sessions.list ignores rpc registrations owned by another profile', async () => {
    iscp.registerSessionRpcPort('p2', 'sess-foreign', 4243)
    const response = await responder.handle({ id: 'l', method: 'sessions.list', params: {} })
    const { sessions } = (response as { ok: true; result: { sessions: Array<Record<string, unknown>> } }).result
    expect(sessions.find((s) => s.sessionId === 'sess-foreign')).toBeUndefined()
  })

  it('session.rpc separates unknown sessions from unreachable agents', async () => {
    const unknown = await responder.handle({ id: 'r', method: 'session.rpc', params: { sessionId: 'ghost', method: 'abort', params: {} } })
    expect(unknown).toMatchObject({ ok: false, error: { code: 'not_found' } })

    // Session with history but no registered bridge → transient, retryable.
    iscp.ingest('p1', 'sess-known', [{ body: {} }])
    const offline = await responder.handle({ id: 'r2', method: 'session.rpc', params: { sessionId: 'sess-known', method: 'abort', params: {} } })
    expect(offline).toMatchObject({ ok: false, error: { code: 'retryable' } })
  })

  // -------------------------------------------------------------------------
  // Text view (grant permission = 'text'): the phone-facing projection of
  // OPS 2026-08-18 §10.16. The raw internal session protocol must never
  // reach these peers; cursors live in view coordinates.
  // -------------------------------------------------------------------------
  describe('text view', () => {
    const textBuild = (overrides?: Partial<WireResponderDeps>) => build({ view: 'text', ...overrides })

    /** The agent-side raw events of the production Codex exchange (seq 2–8). */
    const agentRawEvents = (reply: string) => [
      { localId: 'a-1', body: { role: 'session', content: { id: 'hzg7p120nbryhqjpmljgqtk3', time: 1, role: 'agent', turn: 'wkiyvih5h2q4yhzgh6cqakst', ev: { t: 'turn-start' } }, meta: { sentFrom: 'cli' } } },
      { localId: 'a-2', body: { role: 'session', content: { id: 'p88navwp70szsuwxjfrvd77v', time: 2, role: 'agent', usage: { input_tokens: 1, output_tokens: 1 }, ev: { t: 'service', text: '' } }, meta: { sentFrom: 'cli' } } },
      { localId: 'a-3', body: { role: 'session', content: { id: 'ori39x6jae2tofh4lglcwlio', time: 3, role: 'agent', turn: 'wkiyvih5h2q4yhzgh6cqakst', ev: { t: 'text', text: reply } }, meta: { sentFrom: 'cli' } } },
      { localId: 'a-4', body: { role: 'session', content: { id: 'wt3ioyd9hd300nseqgo2l92v', time: 4, role: 'agent', turn: 'wkiyvih5h2q4yhzgh6cqakst', ev: { t: 'turn-end', status: 'completed' } }, meta: { sentFrom: 'cli' } } },
      { localId: 'a-5', body: { role: 'agent', content: { id: 'f7dfeb45-1cd9-4a9a-b703-a40042078b23', type: 'event', data: { type: 'ready' } } } },
      { localId: 'a-6', body: { role: 'session', content: { id: 'iszvgosmrb33ngsforko9zay', time: 5, role: 'agent', usage: { input_tokens: 1, output_tokens: 1 }, ev: { t: 'text', text: 'internal', thinking: true } }, meta: { sentFrom: 'cli' } } },
    ]

    it('serves exactly one user and one agent bubble for the Codex exchange, with contiguous view seqs', async () => {
      iscp.registerSessionRpcPort('p1', 's1', 4242)
      const textResponder = textBuild({ fetchImpl: okFetch as unknown as typeof fetch })
      const send = await textResponder.handle({
        id: 'r1',
        method: 'messages.send',
        params: { sessionId: 's1', body: { role: 'user', content: { type: 'text', text: '你好' }, localKey: 'jingsi-1' } },
        idempotencyKey: 'jingsi-1',
      })
      expect(send).toMatchObject({ ok: true, result: { seq: 1, delivery: 'delivered' } })
      iscp.ingest('p1', 's1', agentRawEvents('你好！有什么我可以帮你处理的？'))

      const pull = await textResponder.handle({ id: 'r2', method: 'messages.pull', params: { sessionId: 's1' } })
      const result = (pull as { ok: true; result: { events: Array<{ seq: number; localId?: string; body: unknown; cursor: string }>; reset: boolean; lastCursor: string } }).result
      expect(result.events.map((e) => e.seq)).toEqual([1, 2])
      expect(result.events[0]).toMatchObject({
        localId: 'jingsi-1',
        body: { role: 'user', content: { type: 'text', text: '你好' }, localKey: 'jingsi-1' },
      })
      expect(result.events[1].body).toEqual({ role: 'agent', content: { type: 'text', text: '你好！有什么我可以帮你处理的？' } })
      // Nothing else leaks: no turn/service/usage/ready/thinking JSON.
      expect(JSON.stringify(result.events)).not.toContain('turn-start')
      expect(JSON.stringify(result.events)).not.toContain('"usage"')
      expect(JSON.stringify(result.events)).not.toContain('ready')
      expect(JSON.stringify(result.events)).not.toContain('internal')

      // The send ack cursor is the view cursor of the user bubble.
      const ack = (send as { ok: true; result: { cursor: string } }).result.cursor
      expect(decodeWireCursor(ack)).toMatchObject({ scope: 's1', seq: 1 })
      expect(decodeWireCursor(ack)!.epoch).toBe(decodeWireCursor(result.lastCursor)!.epoch)
    })

    it('rejects non-text send bodies at the permission boundary before persisting', async () => {
      iscp.registerSessionRpcPort('p1', 's1', 4242)
      const textResponder = textBuild({ fetchImpl: okFetch as unknown as typeof fetch })
      const rejected = await textResponder.handle({
        id: 'r1',
        method: 'messages.send',
        params: { sessionId: 's1', body: { role: 'agent', content: { type: 'tool-call', name: 'Bash' } } },
        idempotencyKey: 'k-bad',
      })
      expect(rejected).toMatchObject({ ok: false, error: { code: 'invalid' } })
      expect(iscp.log('p1').sessionInfo('s1')).toBeNull()
      expect(okFetch).not.toHaveBeenCalled()
    })

    it('uses view coordinates for cursors: raw-epoch cursors reset, view cursors resume', async () => {
      iscp.registerSessionRpcPort('p1', 's1', 4242)
      const textResponder = textBuild({ fetchImpl: okFetch as unknown as typeof fetch })
      await textResponder.handle({
        id: 'r1',
        method: 'messages.send',
        params: { sessionId: 's1', body: { role: 'user', content: { type: 'text', text: 'one' } } },
        idempotencyKey: 'k1',
      })
      iscp.ingest('p1', 's1', agentRawEvents('reply one'))

      const pull = await textResponder.handle({ id: 'r2', method: 'messages.pull', params: { sessionId: 's1' } })
      const r1 = (pull as { ok: true; result: { events: Array<{ cursor: string }>; reset: boolean } }).result
      expect(r1.reset).toBe(false)

      // Resume from the user bubble's view cursor → only the agent bubble.
      const resumed = await textResponder.handle({ id: 'r3', method: 'messages.pull', params: { sessionId: 's1', afterCursor: r1.events[0].cursor } })
      const r2 = (resumed as { ok: true; result: { events: Array<{ seq: number; body: unknown }>; reset: boolean } }).result
      expect(r2.reset).toBe(false)
      expect(r2.events.map((e) => e.seq)).toEqual([2])

      // A cursor minted on the RAW epoch line (the "filtered raw cursor"
      // trap) must invalidate and trigger a full view re-sync.
      const rawEpoch = iscp.log('p1').sessionInfo('s1')!.epoch
      const viewCursor = decodeWireCursor(r1.events[0].cursor)!
      const rawStyleCursor = r1.events[0].cursor.replace(viewCursor.epoch, rawEpoch)
      const reset = await textResponder.handle({ id: 'r4', method: 'messages.pull', params: { sessionId: 's1', afterCursor: rawStyleCursor } })
      const r3 = (reset as { ok: true; result: { events: unknown[]; reset: boolean } }).result
      expect(r3.reset).toBe(true)
      expect(r3.events).toHaveLength(2)
    })

    it('sessions.list advertises view seq/cursor facts to text peers', async () => {
      iscp.registerSessionRpcPort('p1', 's1', 4242)
      const textResponder = textBuild({ fetchImpl: okFetch as unknown as typeof fetch })
      await textResponder.handle({
        id: 'r1',
        method: 'messages.send',
        params: { sessionId: 's1', body: { role: 'user', content: { type: 'text', text: 'one' } } },
        idempotencyKey: 'k1',
      })
      iscp.ingest('p1', 's1', agentRawEvents('reply'))

      const list = await textResponder.handle({ id: 'l', method: 'sessions.list', params: {} })
      const session = (list as { ok: true; result: { sessions: Array<{ sessionId: string; lastSeq: number; lastCursor?: string }> } })
        .result.sessions.find((s) => s.sessionId === 's1')!
      // Raw log holds 7 events; the view holds 2 bubbles.
      expect(iscp.log('p1').sessionInfo('s1')!.lastSeq).toBe(7)
      expect(session.lastSeq).toBe(2)
      const cursor = decodeWireCursor(session.lastCursor!)!
      expect(cursor.seq).toBe(2)
      expect(cursor.epoch).not.toBe(iscp.log('p1').sessionInfo('s1')!.epoch)
    })

    it('live push and pull share the materialized view (same seq, idempotent overlap)', async () => {
      iscp.registerSessionRpcPort('p1', 's1', 4242)
      const textResponder = textBuild({ fetchImpl: okFetch as unknown as typeof fetch })
      const live: Array<{ sessionId: string; record: { viewSeq: number; body: unknown }; viewEpoch: string }> = []
      iscp.events.on('text-view-event', (n: { sessionId: string; record: { viewSeq: number; body: unknown }; viewEpoch: string }) => live.push(n))

      await textResponder.handle({
        id: 'r1',
        method: 'messages.send',
        params: { sessionId: 's1', body: { role: 'user', content: { type: 'text', text: 'ping' } } },
        idempotencyKey: 'k1',
      })
      iscp.ingest('p1', 's1', agentRawEvents('pong'))

      // Live saw exactly the two bubbles, in view coordinates.
      expect(live.map((n) => n.record.viewSeq)).toEqual([1, 2])
      expect(live[1].record.body).toEqual({ role: 'agent', content: { type: 'text', text: 'pong' } })

      // Overlap: pulling the same range yields the same seqs and bodies — the
      // app can dedupe by cursor with no divergence between push and pull.
      const pull = await textResponder.handle({ id: 'r2', method: 'messages.pull', params: { sessionId: 's1' } })
      const events = (pull as { ok: true; result: { events: Array<{ seq: number; body: unknown }> } }).result.events
      expect(events.map((e) => e.seq)).toEqual(live.map((n) => n.record.viewSeq))
      expect(events[1].body).toEqual(live[1].record.body)

      // Re-ingesting the same localIds (agent retry) appends nothing new.
      iscp.ingest('p1', 's1', agentRawEvents('pong'))
      expect(live.map((n) => n.record.viewSeq)).toEqual([1, 2])
    })

    it('daemon restart keeps the view epoch and seq line stable', async () => {
      iscp.registerSessionRpcPort('p1', 's1', 4242)
      const textResponder = textBuild({ fetchImpl: okFetch as unknown as typeof fetch })
      await textResponder.handle({
        id: 'r1',
        method: 'messages.send',
        params: { sessionId: 's1', body: { role: 'user', content: { type: 'text', text: 'before restart' } } },
        idempotencyKey: 'k1',
      })
      const before = await textResponder.handle({ id: 'r2', method: 'messages.pull', params: { sessionId: 's1' } })
      const beforeResult = (before as { ok: true; result: { lastCursor: string } }).result

      const restarted = new DaemonIscpService((profileId) => join(root, profileId))
      const freshResponder = new WireResponder({
        iscp: restarted,
        profileId: 'p1',
        view: 'text',
        getChildren: () => [],
        stopSession,
        spawnSession,
      })
      restarted.ingest('p1', 's1', agentRawEvents('after restart'))
      const after = await freshResponder.handle({ id: 'r3', method: 'messages.pull', params: { sessionId: 's1', afterCursor: beforeResult.lastCursor } })
      const afterResult = (after as { ok: true; result: { events: Array<{ seq: number; body: unknown }>; reset: boolean } }).result
      expect(afterResult.reset).toBe(false)
      expect(afterResult.events.map((e) => e.seq)).toEqual([2])
      expect(afterResult.events[0].body).toEqual({ role: 'agent', content: { type: 'text', text: 'after restart' } })
    })
  })
})
