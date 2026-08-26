/**
 * Cross-client acceptance runner: boots the real daemon-side ISCP stack
 * (enrollment → startDaemonIscpPeers → WireResponder over the event log)
 * against the reference harness and keeps it alive so an external client —
 * e.g. the JingSi iOS Swift stack (`ISCP_HARNESS=1 swift test` in the
 * JingSi-iOS repo) — can run the full handshake + happy-wire.v1 flow
 * against it.
 *
 *   docker compose -f environments/iscp/docker-compose.yaml up -d
 *   cd packages/happy-cli && HAPPY_HOME_DIR=$(mktemp -d) npx tsx src/iscp/e2eDaemonRunner.ts
 *
 * Control endpoints (default 127.0.0.1:18099, override ISCP_E2E_CTRL_PORT):
 *   GET  /info    → { daemonDeviceId, profileId }
 *   POST /ingest  → { sessionId, localId?, body }  (simulates a session tee
 *                    append, which fans out to events.subscribe'd peers)
 *
 * Each scripted spawn also starts a real localhost session RPC endpoint. A
 * user message delivered through Happy's WireResponder is acknowledged there
 * and echoed back through the daemon event log as a visible Agent reply. This
 * keeps the external-client acceptance honest: messages.send must reach an
 * active spawned session, not merely persist in the outbox.
 */

import fastify from 'fastify'

const RELAY_URL = process.env.ISCP_RELAY_URL ?? 'http://localhost:18080'
const TRUST_URL = process.env.ISCP_TRUST_URL ?? 'http://localhost:18081'
const CTRL_PORT = Number(process.env.ISCP_E2E_CTRL_PORT ?? 18099)

async function main(): Promise<void> {
  if (!process.env.HAPPY_HOME_DIR) {
    throw new Error('set HAPPY_HOME_DIR to a scratch directory before running')
  }
  // Dynamic imports so HAPPY_HOME_DIR is set before configuration loads.
  const { enroll } = await import('@/iscp/enrollment')
  const { DaemonIscpService } = await import('@/iscp/daemonIscp')
  const { startDaemonIscpPeers } = await import('@/iscp/daemonPeer')

  const { profileId, bundle } = await enroll({
    relayUrl: RELAY_URL,
    trustUrl: TRUST_URL,
    relayId: 'relay-local',
    trustRootId: 'trust-local',
    domainId: 'local',
    log: (line) => console.log(line),
  })
  const daemonDeviceId = bundle.device_identity.device_id

  const iscp = new DaemonIscpService()
  let spawnCounter = 0
  let replyCounter = 0
  const rpcServers: Array<ReturnType<typeof fastify>> = []
  const peers = await startDaemonIscpPeers({
    iscp,
    getChildren: () => [],
    stopSession: () => true,
    // Unique per spawn so repeated external test runs get isolated logs.
    spawnSession: async () => {
      const sessionId = `sess-swift-e2e-${++spawnCounter}`
      const rpc = fastify({ logger: false })
      rpc.post('/rpc', async (request, reply) => {
        const body = request.body as { method?: unknown; params?: unknown }
        if (body.method !== 'iscp.user-message') {
          reply.code(500)
          return { ok: false as const, error: `unsupported scripted RPC method ${String(body.method)}` }
        }

        const nextReply = ++replyCounter
        iscp.ingest(profileId, sessionId, [{
          localId: `agent-reply-${nextReply}`,
          body: {
            role: 'session',
            content: {
              id: `swift-e2e-agent-${nextReply}`,
              time: Date.now(),
              role: 'agent',
              ev: { t: 'text', text: `agent reply ${nextReply}` },
            },
          },
        }])
        return { ok: true as const, result: null }
      })
      const address = await rpc.listen({ port: 0, host: '127.0.0.1' })
      const port = Number(new URL(address).port)
      rpcServers.push(rpc)
      iscp.registerSessionRpcPort(profileId, sessionId, port)
      return { type: 'success' as const, sessionId }
    },
  })
  if (!peers.profiles.includes(profileId)) {
    throw new Error('daemon peer failed to come online')
  }

  const ctrl = fastify({ logger: false })
  ctrl.get('/info', async () => ({ daemonDeviceId, profileId }))
  ctrl.post('/ingest', async (request) => {
    const { sessionId, localId, body } = request.body as { sessionId: string; localId?: string; body: unknown }
    const results = iscp.ingest(profileId, sessionId, [{ localId, body }])
    return { seq: results[0].seq, deduped: results[0].deduped }
  })
  await ctrl.listen({ port: CTRL_PORT, host: '127.0.0.1' })

  console.log('')
  console.log(`e2e daemon runner online: device ${daemonDeviceId} (profile ${profileId})`)
  console.log(`control plane: http://127.0.0.1:${CTRL_PORT}  (GET /info, POST /ingest)`)

  setInterval(() => {
    console.log(`[heartbeat] peer ws state: ${peers.connectionStates().join(', ')}`)
  }, 10_000).unref?.()

  const shutdown = () => {
    peers.stop()
    void Promise.all([
      ctrl.close(),
      ...rpcServers.map((rpc) => rpc.close()),
    ]).then(() => process.exit(0))
  }
  process.on('SIGINT', shutdown)
  process.on('SIGTERM', shutdown)
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
