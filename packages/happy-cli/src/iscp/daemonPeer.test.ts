/**
 * Daemon ISCP peers: single-flight reload semantics
 * (createIscpPeersController) and the session-event listener lifecycle —
 * every reload must remove the previous listeners (the pre-§4.2 code leaked
 * one listener per reload, doubling event pushes).
 */

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import { encodeTicketForTransport } from '@slopus/iscp'

import { CloudFixture } from '@/iscp/testing/cloudFixture'

const homeDir = mkdtempSync(join(tmpdir(), 'happy-iscp-daemonpeer-'))
process.env.HAPPY_HOME_DIR = homeDir

const RELAY_ID = 'relay-cloud-test'
const TRUST_ROOT_ID = 'trust-cloud-test'
const DOMAIN_ID = 'dom_fixture'
const PHONE_DEVICE_ID = 'dev_phone_fixture'

describe('createIscpPeersController (single-flight reload)', () => {
  let createIscpPeersController: typeof import('@/iscp/daemonPeer').createIscpPeersController

  beforeAll(async () => {
    ;({ createIscpPeersController } = await import('@/iscp/daemonPeer'))
  })

  function fakePeers(profiles: string[], events: { starts: number[]; stops: number[] }, runId: number) {
    return {
      profiles,
      connectionStates: () => [],
      statuses: () => [],
      stop: () => {
        events.stops.push(runId)
      },
    }
  }

  it('concurrent reload calls coalesce: one inflight run plus at most one queued follow-up', async () => {
    const events = { starts: [] as number[], stops: [] as number[] }
    let runs = 0
    const controller = createIscpPeersController(async () => {
      runs += 1
      const runId = runs
      events.starts.push(runId)
      await new Promise((resolve) => setTimeout(resolve, 20))
      return fakePeers([`run-${runId}`], events, runId)
    })

    const results = await Promise.all([
      controller.reload(),
      controller.reload(),
      controller.reload(),
      controller.reload(),
      controller.reload(),
    ])
    // 5 concurrent triggers → exactly 2 serial runs (1 inflight + 1 queued).
    expect(runs).toBe(2)
    // Serial chain: run 2 starts only after run 1 finished, and run 1's peers
    // were stopped before run 2 started.
    expect(events.starts).toEqual([1, 2])
    expect(events.stops).toEqual([1])
    for (const result of results) {
      expect(result.profiles.length).toBe(1)
    }
    // Later callers see the final state.
    expect(controller.profiles()).toEqual(['run-2'])

    // A reload after the dust settles runs again (single-flight only applies
    // to concurrent triggers).
    await controller.reload()
    expect(runs).toBe(3)
    controller.stop()
    expect(events.stops).toEqual([1, 2, 3])
  })

  it('a failed reload leaves the controller usable', async () => {
    let runs = 0
    const controller = createIscpPeersController(async () => {
      runs += 1
      if (runs === 1) throw new Error('relay down')
      return { profiles: ['ok'], connectionStates: () => [], statuses: () => [], stop: () => { } }
    })
    await expect(controller.reload()).rejects.toThrowError(/relay down/)
    expect(controller.profiles()).toEqual([])
    await expect(controller.reload()).resolves.toEqual({ profiles: ['ok'] })
    expect(controller.profiles()).toEqual(['ok'])
  })
})

describe('startDaemonIscpPeers listener lifecycle (real peers against the fixture)', () => {
  const fixture = new CloudFixture({ relayId: RELAY_ID, trustRootId: TRUST_ROOT_ID, domainId: DOMAIN_ID, phoneDeviceId: PHONE_DEVICE_ID })
  let enrollment: typeof import('@/iscp/enrollment')
  let daemonPeer: typeof import('@/iscp/daemonPeer')
  let daemonIscp: typeof import('@/iscp/daemonIscp')

  beforeAll(async () => {
    await fixture.start()
    enrollment = await import('@/iscp/enrollment')
    daemonPeer = await import('@/iscp/daemonPeer')
    daemonIscp = await import('@/iscp/daemonIscp')
    await enrollment.enroll({
      relayUrl: fixture.baseUrl,
      trustUrl: fixture.baseUrl,
      relayId: RELAY_ID,
      trustRootId: TRUST_ROOT_ID,
      ticket: encodeTicketForTransport(fixture.issueTicket()),
      profileId: 'peer-profile',
      log: () => { },
    })
  }, 30_000)

  afterAll(async () => {
    await fixture.stop()
    rmSync(homeDir, { recursive: true, force: true })
    delete process.env.HAPPY_HOME_DIR
  })

  function peerDeps(iscp: InstanceType<typeof daemonIscp.DaemonIscpService>) {
    return {
      iscp,
      getChildren: () => [],
      stopSession: () => false,
      spawnSession: async () => ({ type: 'error' as const, errorMessage: 'not in this test' }),
    }
  }

  it('reload keeps exactly one session-event listener; stop removes it', async () => {
    const iscp = new daemonIscp.DaemonIscpService()
    const controller = daemonPeer.createIscpPeersController(() => daemonPeer.startDaemonIscpPeers(peerDeps(iscp)))

    const first = await controller.reload()
    expect(first.profiles).toEqual(['peer-profile'])
    expect(iscp.events.listenerCount('session-event')).toBe(1)

    const second = await controller.reload()
    expect(second.profiles).toEqual(['peer-profile'])
    // The old peer's listener was removed: still exactly one, not two.
    expect(iscp.events.listenerCount('session-event')).toBe(1)

    const statuses = controller.statuses()
    expect(statuses).toHaveLength(1)
    expect(statuses[0]).toMatchObject({
      profileId: 'peer-profile',
      generation: 1,
      peerDeviceId: PHONE_DEVICE_ID,
    })
    expect(statuses[0]!.deviceId).toMatch(/^dev_official_/)
    expect(['connecting', 'ready', 'authorization_expired', 'failed']).toContain(statuses[0]!.session)

    controller.stop()
    expect(iscp.events.listenerCount('session-event')).toBe(0)
  }, 30_000)

  it('the initiator classifies an unresolvable audience as identity_unavailable (no endless dialing)', async () => {
    const iscp = new daemonIscp.DaemonIscpService()
    const peers = await daemonPeer.startDaemonIscpPeers(peerDeps(iscp))
    try {
      // The fixture has no /v2/trust/devices/status route → 404 → fatal.
      const deadline = Date.now() + 10_000
      let status = peers.statuses()[0]
      while (status !== undefined && status.session === 'connecting' && Date.now() < deadline) {
        await new Promise((resolve) => setTimeout(resolve, 25))
        status = peers.statuses()[0]
      }
      expect(status).toBeDefined()
      expect(status!.session).toBe('failed')
      expect(status!.sessionDetail).toBe('identity_unavailable')
    } finally {
      peers.stop()
    }
  }, 30_000)
})
