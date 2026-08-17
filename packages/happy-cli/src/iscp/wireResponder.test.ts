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
})
