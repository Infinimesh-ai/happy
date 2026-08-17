/**
 * ISCP-mode session RPC server: a localhost HTTP endpoint each ISCP session
 * process exposes so the daemon's wire responder can bridge happy-wire.v1
 * requests (session.rpc, user message delivery) to the session's existing
 * RpcHandlerManager — plaintext over 127.0.0.1; the E2E leg is
 * iscp_session_v1 on the relay.
 *
 * The session registers its port with the daemon control server
 * (POST /iscp/session-rpc) and keeps re-registering on a heartbeat for the
 * whole session lifetime: the daemon's port table is in-memory only, so a
 * daemon restart at any point (not just the startup window) must re-learn
 * the port within one heartbeat interval. Registration is idempotent on the
 * daemon side; unreachable daemons are retried on a tighter interval.
 */

import fastify from 'fastify'
import { z } from 'zod'
import { serializerCompiler, validatorCompiler, ZodTypeProvider } from 'fastify-type-provider-zod'

import { daemonPost } from '@/daemon/controlClient'
import { logger } from '@/ui/logger'

const REGISTER_RETRY_INTERVAL_MS = 2000
const REGISTER_HEARTBEAT_INTERVAL_MS = 15_000

export const USER_MESSAGE_METHOD = 'iscp.user-message'

export interface IscpSessionRpcServer {
  port: number
  stop: () => Promise<void>
}

export async function startIscpSessionRpcServer(opts: {
  profileId: string
  sessionId: string
  onUserMessage: (body: unknown) => void
  callHandler: (method: string, params: unknown) => Promise<unknown>
  /** Injectable for tests. */
  retryIntervalMs?: number
  heartbeatIntervalMs?: number
}): Promise<IscpSessionRpcServer> {
  const app = fastify({ logger: false })
  app.setValidatorCompiler(validatorCompiler)
  app.setSerializerCompiler(serializerCompiler)
  const typed = app.withTypeProvider<ZodTypeProvider>()

  typed.post('/rpc', {
    schema: {
      body: z.object({
        method: z.string().min(1),
        params: z.unknown()
      }),
      response: {
        200: z.object({
          ok: z.literal(true),
          result: z.unknown()
        }),
        500: z.object({
          ok: z.literal(false),
          error: z.string()
        })
      }
    }
  }, async (request, reply) => {
    const { method, params } = request.body
    try {
      if (method === USER_MESSAGE_METHOD) {
        opts.onUserMessage(params)
        return { ok: true as const, result: null }
      }
      const result = await opts.callHandler(method, params)
      return { ok: true as const, result: result ?? null }
    } catch (error) {
      reply.code(500)
      return { ok: false as const, error: error instanceof Error ? error.message : 'Unknown error' }
    }
  })

  const port = await new Promise<number>((resolve, reject) => {
    app.listen({ port: 0, host: '127.0.0.1' }, (err, address) => {
      if (err) {
        reject(err)
        return
      }
      resolve(parseInt(address.split(':').pop()!))
    })
  })
  logger.debug(`[ISCP SESSION RPC] Listening on 127.0.0.1:${port} for session ${opts.sessionId}`)

  // Registration heartbeat: never stops while the session lives. A success
  // only means the *current* daemon knows the port; the next daemon won't.
  const retryMs = opts.retryIntervalMs ?? REGISTER_RETRY_INTERVAL_MS
  const heartbeatMs = opts.heartbeatIntervalMs ?? REGISTER_HEARTBEAT_INTERVAL_MS
  let stopped = false
  let wake: (() => void) | null = null
  const sleep = (ms: number) => new Promise<void>((resolve) => {
    const timer = setTimeout(() => {
      wake = null
      resolve()
    }, ms)
    timer.unref?.()
    wake = () => {
      clearTimeout(timer)
      wake = null
      resolve()
    }
  })

  const heartbeat = (async () => {
    let registered = false
    while (!stopped) {
      const result = await daemonPost('/iscp/session-rpc', {
        profileId: opts.profileId,
        sessionId: opts.sessionId,
        port
      })
      const ok = !result?.error
      if (ok && !registered) {
        logger.debug(`[ISCP SESSION RPC] Registered with daemon for session ${opts.sessionId}`)
      } else if (!ok && registered) {
        logger.debug(`[ISCP SESSION RPC] Daemon unreachable for session ${opts.sessionId}; retrying until it returns`)
      }
      registered = ok
      if (stopped) break
      await sleep(ok ? heartbeatMs : retryMs)
    }
  })()

  return {
    port,
    stop: async () => {
      stopped = true
      wake?.()
      await heartbeat
      await app.close()
    }
  }
}
