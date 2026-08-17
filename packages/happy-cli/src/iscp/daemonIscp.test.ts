import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'

import { DaemonIscpService, type SessionLifecycleNotification } from './daemonIscp'

describe('DaemonIscpService', () => {
  let root: string
  let iscp: DaemonIscpService
  let lifecycle: SessionLifecycleNotification[]

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), 'iscp-daemon-'))
    iscp = new DaemonIscpService((profileId) => join(root, profileId))
    lifecycle = []
    iscp.events.on('session-lifecycle', (n: SessionLifecycleNotification) => lifecycle.push(n))
  })
  afterEach(() => {
    rmSync(root, { recursive: true, force: true })
  })

  it('scopes session RPC ports to the owning profile', () => {
    expect(iscp.registerSessionRpcPort('p1', 's1', 1000)).toBe(true)
    expect(iscp.sessionRpcPort('p1', 's1')).toBe(1000)
    expect(iscp.sessionRpcPort('p2', 's1')).toBeNull()
    expect(iscp.sessionRpcPort('p1', 'other')).toBeNull()
  })

  it('treats heartbeat re-registrations as no-ops and emits only on change', () => {
    expect(iscp.registerSessionRpcPort('p1', 's1', 1000)).toBe(true)
    expect(iscp.registerSessionRpcPort('p1', 's1', 1000)).toBe(false)
    expect(iscp.registerSessionRpcPort('p1', 's1', 1001)).toBe(true)
    expect(lifecycle).toEqual([
      { profileId: 'p1', sessionId: 's1', change: 'changed', reason: 'agent_reachable' },
      { profileId: 'p1', sessionId: 's1', change: 'changed', reason: 'agent_reachable' },
    ])
  })

  it('enumerates registered rpc sessions per profile and for the daemon list view', () => {
    iscp.registerSessionRpcPort('p1', 's1', 1000)
    iscp.registerSessionRpcPort('p1', 's2', 1001)
    iscp.registerSessionRpcPort('p2', 's3', 1002)
    expect(iscp.sessionIdsWithRpcPort('p1').sort()).toEqual(['s1', 's2'])
    expect(iscp.sessionIdsWithRpcPort('p2')).toEqual(['s3'])
    expect(iscp.sessionIdsWithRpcPort('p3')).toEqual([])
    expect(iscp.listRegisteredRpcSessions().sort((a, b) => a.sessionId.localeCompare(b.sessionId))).toEqual([
      { sessionId: 's1', profileId: 'p1', port: 1000 },
      { sessionId: 's2', profileId: 'p1', port: 1001 },
      { sessionId: 's3', profileId: 'p2', port: 1002 },
    ])
    iscp.unregisterSessionRpcPort('s1')
    expect(iscp.sessionIdsWithRpcPort('p1')).toEqual(['s2'])
  })

  it('a fresh service (daemon restart) emits agent_reachable on the first heartbeat re-registration', () => {
    // The restarted daemon has an empty port table; the surviving agent's
    // heartbeat re-registration is indistinguishable from a first
    // registration and must fire the lifecycle machine-event source.
    expect(iscp.registerSessionRpcPort('p1', 's1', 1000)).toBe(true)
    expect(lifecycle).toEqual([
      { profileId: 'p1', sessionId: 's1', change: 'changed', reason: 'agent_reachable' },
    ])
  })

  it('emits agent_unreachable when a registration is dropped', () => {
    iscp.registerSessionRpcPort('p1', 's1', 1000)
    lifecycle.length = 0
    iscp.unregisterSessionRpcPort('s1')
    iscp.unregisterSessionRpcPort('s1')
    expect(iscp.sessionRpcPort('p1', 's1')).toBeNull()
    expect(lifecycle).toEqual([
      { profileId: 'p1', sessionId: 's1', change: 'changed', reason: 'agent_unreachable' },
    ])
  })

  it('emits session.added exactly once when a new session log appears', () => {
    iscp.ingest('p1', 's1', [{ body: { t: 'a' } }])
    iscp.ingest('p1', 's1', [{ body: { t: 'b' } }])
    const added = lifecycle.filter((n) => n.change === 'added')
    expect(added).toEqual([
      { profileId: 'p1', sessionId: 's1', change: 'added', reason: 'session_created' },
    ])
  })
})
