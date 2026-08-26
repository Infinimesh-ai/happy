/**
 * ISCP-only ApiSessionClient contract (OPS 2026-08-26 §4.1.2/§4.1.3): no
 * Happy Server socket or HTTP outbox is ever created; history flows through
 * the daemon tee, metadata/agent-state are versioned locally and propagated
 * over the /session-started webhook, flush drains the tee, and close stops
 * the localhost RPC bridge. Exercised against a real fastify control server
 * standing in for the daemon (no mocking).
 */

import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import fastify, { type FastifyInstance } from 'fastify'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

const homeDir = mkdtempSync(join(tmpdir(), 'happy-iscp-only-session-'))
process.env.HAPPY_HOME_DIR = homeDir
process.env.HAPPY_NETWORK_PROFILE = 'test-profile'

const PROFILE_ID = 'test-profile'

type Captured = { url: string; body: any }

describe('ApiSessionClient (ISCP-only)', () => {
  let app: FastifyInstance
  const sessionStarted: Captured[] = []
  const sessionEvents: Captured[] = []
  const rpcRegistrations: Captured[] = []

  let ApiSessionClient: typeof import('@/api/apiSession').ApiSessionClient
  let createIscpOnlySession: typeof import('@/iscp/iscpOnlySession').createIscpOnlySession

  beforeAll(async () => {
    app = fastify({ logger: false })
    app.post('/session-started', async (request) => {
      sessionStarted.push({ url: request.url, body: request.body })
      return { ok: true }
    })
    app.post('/iscp/session-event', async (request) => {
      sessionEvents.push({ url: request.url, body: request.body })
      const events = (request.body as any).events ?? []
      return { ok: true, results: events.map((e: any, i: number) => ({ localId: e.localId, seq: i + 1 })) }
    })
    app.post('/iscp/session-rpc', async (request) => {
      rpcRegistrations.push({ url: request.url, body: request.body })
      return { ok: true }
    })
    const address = await app.listen({ port: 0, host: '127.0.0.1' })
    const port = parseInt(address.split(':').pop()!)
    writeFileSync(join(homeDir, 'daemon.state.json'), JSON.stringify({
      pid: process.pid,
      httpPort: port,
      startTime: new Date().toLocaleString(),
      startedWithCliVersion: 'test',
    }))

    // Dynamic import so HAPPY_HOME_DIR (temp) is set before configuration loads.
    ApiSessionClient = (await import('@/api/apiSession')).ApiSessionClient
    createIscpOnlySession = (await import('@/iscp/iscpOnlySession')).createIscpOnlySession
  })

  afterAll(async () => {
    await app.close()
    rmSync(homeDir, { recursive: true, force: true })
    delete process.env.HAPPY_NETWORK_PROFILE
  })

  function mintSession() {
    return createIscpOnlySession({
      path: process.cwd(),
      host: 'test-host',
      homeDir,
      happyHomeDir: homeDir,
      happyLibDir: homeDir,
      happyToolsDir: homeDir,
      machineId: 'machine-test',
      flavor: 'claude',
    }, {})
  }

  async function until(predicate: () => boolean, timeoutMs = 5000): Promise<void> {
    const deadline = Date.now() + timeoutMs
    while (!predicate()) {
      if (Date.now() > deadline) throw new Error('condition not reached in time')
      await new Promise((resolve) => setTimeout(resolve, 25))
    }
  }

  it('mints a local identity with fresh versions and a content key', () => {
    const session = mintSession()
    expect(session.id.length).toBeGreaterThan(0)
    expect(session.seq).toBe(0)
    expect(session.metadataVersion).toBe(0)
    expect(session.agentStateVersion).toBe(0)
    expect(session.encryptionKey.length).toBe(32)
  })

  it('runs the full ISCP-only lifecycle without any Happy Server connection', async () => {
    const session = mintSession()
    const client = new ApiSessionClient(null, session)
    try {
      // No legacy socket is ever created.
      expect((client as any).socket).toBeNull()

      // History goes through the tee to the daemon event log; flush drains it.
      client.sendCodexMessage({ hello: 'world' })
      await client.flush()
      const delivered = sessionEvents.flatMap((c) => c.body.events ?? [])
      expect(delivered.length).toBe(1)
      expect(sessionEvents[0].body.profileId).toBe(PROFILE_ID)
      expect(sessionEvents[0].body.sessionId).toBe(session.id)
      expect(delivered[0].body.content.type).toBe('codex')

      // Metadata: local versioning + webhook propagation to the daemon.
      client.updateMetadata((m) => ({ ...m, name: 'renamed' }))
      await until(() => sessionStarted.some((c) => c.body.metadata?.name === 'renamed'))
      expect(client.getMetadata()?.name).toBe('renamed')
      const propagated = sessionStarted.find((c) => c.body.metadata?.name === 'renamed')!
      expect(propagated.body.sessionId).toBe(session.id)
      expect(propagated.body.encryption.metadataVersion).toBe(1)

      // Agent state: same local versioning + propagation.
      client.updateAgentState((s) => ({ ...s, controlledByUser: false }))
      await until(() => sessionStarted.some((c) => c.body.encryption?.agentStateVersion === 1))

      // Liveness/usage surfaces are explicit no-ops, not crashes.
      client.keepAlive(false, 'remote')
      client.sendUsageData({ input_tokens: 1, output_tokens: 2 } as any)
      client.sendSessionDeath()

      // Legacy-only surfaces fail closed with a clear reason.
      await expect(client.downloadAttachment('ref')).rejects.toThrow(/ISCP-only/)
      await expect(client.uploadLocalImageAttachmentEnvelope({
        data: new Uint8Array([1]), mimeType: 'image/png', name: 'x.png',
      })).rejects.toThrow(/ISCP-only/)

      // The localhost RPC bridge registered itself with the daemon…
      await until(() => rpcRegistrations.some((c) => c.body.sessionId === session.id))
      const registration = rpcRegistrations.find((c) => c.body.sessionId === session.id)!
      expect(registration.body.profileId).toBe(PROFILE_ID)
      const rpcPort = registration.body.port as number

      // …serves user messages into the session…
      const messages: unknown[] = []
      client.onUserMessage((m) => messages.push(m))
      const response = await fetch(`http://127.0.0.1:${rpcPort}/rpc`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          method: 'iscp.user-message',
          params: {
            role: 'user',
            content: { type: 'text', text: 'hi from phone' },
          },
        }),
      })
      expect(response.ok).toBe(true)
      await until(() => messages.length === 1)

      // …and close() stops it.
      await client.close()
      await expect(fetch(`http://127.0.0.1:${rpcPort}/rpc`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ method: 'noop', params: null }),
      })).rejects.toThrow()
    } finally {
      await client.close().catch(() => undefined)
    }
  })

  it('refuses ISCP-only construction without a network profile', () => {
    const saved = process.env.HAPPY_NETWORK_PROFILE
    delete process.env.HAPPY_NETWORK_PROFILE
    try {
      expect(() => new ApiSessionClient(null, mintSession())).toThrow(/HAPPY_NETWORK_PROFILE/)
    } finally {
      process.env.HAPPY_NETWORK_PROFILE = saved
    }
  })
})
