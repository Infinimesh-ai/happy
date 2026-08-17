/**
 * Regression (OPS 2026-08-17 rollout log §7.3, defect 2): after a daemon
 * restart the surviving agents are not children of the new daemon process,
 * but their session-RPC heartbeat re-registers within one interval. The
 * control /list response must expose those registrations (additively, next
 * to the child table) so `happy daemon list` does not report a reachable
 * agent as absent/idle.
 */

import { afterEach, describe, expect, it } from 'vitest'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { startDaemonControlServer } from './controlServer'
import { DaemonIscpService } from '@/iscp/daemonIscp'
import type { TrackedSession } from './types'

const postList = async (port: number): Promise<Record<string, unknown>> => {
  const response = await fetch(`http://127.0.0.1:${port}/list`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: '{}',
  })
  expect(response.ok).toBe(true)
  return await response.json() as Record<string, unknown>
}

describe('control server /list', () => {
  let stop: (() => Promise<void>) | null = null
  afterEach(async () => {
    await stop?.()
    stop = null
  })

  const baseDeps = {
    stopSession: () => true,
    spawnSession: async () => ({ type: 'error' as const, errorMessage: 'not exercised by this test' }),
    requestShutdown: () => {},
    onHappySessionWebhook: () => {},
  }

  it('additively lists heartbeat-re-registered agents next to child sessions', async () => {
    // The profile dir resolver is never touched: registration is in-memory.
    const iscp = new DaemonIscpService((profileId) => join(tmpdir(), 'unused-ctrl-list', profileId))
    // Daemon-restart shape: the agent re-registered via heartbeat but has no
    // entry in the child-process table.
    iscp.registerSessionRpcPort('p1', 'sess-reattached', 4242)
    const children: TrackedSession[] = [
      { startedBy: 'daemon', happySessionId: 'sess-child', pid: 123 },
    ]
    const server = await startDaemonControlServer({
      ...baseDeps,
      getChildren: () => children,
      iscp,
    })
    stop = server.stop

    const body = await postList(server.port)
    expect(body.children).toEqual([
      { startedBy: 'daemon', happySessionId: 'sess-child', pid: 123 },
    ])
    expect(body.iscpAgents).toEqual([
      { sessionId: 'sess-reattached', profileId: 'p1', port: 4242 },
    ])
  })

  it('omits iscpAgents when ISCP is not enabled on this daemon', async () => {
    const server = await startDaemonControlServer({
      ...baseDeps,
      getChildren: () => [],
    })
    stop = server.stop

    const body = await postList(server.port)
    expect(body.children).toEqual([])
    expect(body.iscpAgents).toBeUndefined()
  })
})
