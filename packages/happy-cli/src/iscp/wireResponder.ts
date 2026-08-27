/**
 * happy-wire.v1 responder: maps HappyWireRequest envelopes arriving over the
 * ISCP transport onto daemon capabilities. The daemon event log is the only
 * history source (messages.pull), and mutations dedupe via idempotencyKey
 * (= localId, same contract as the legacy /v3 endpoint).
 *
 * Method catalog (transport-owned; unknown methods → 'unsupported'):
 *   sessions.list / sessions.spawn / sessions.stop
 *   sessions.archive { sessionId, archived? } (history housekeeping; running → conflict)
 *   messages.pull { sessionId, afterCursor?, limit? }
 *   messages.send { sessionId, body }        (idempotencyKey required; 'retryable'
 *                                             failure when the agent is unreachable —
 *                                             the message stays persisted and a retry
 *                                             with the same idempotencyKey redelivers)
 *   session.rpc   { sessionId, method, params }
 *   machine.rpc   { method, params }
 *   events.subscribe { }                     (live push flag; caller pulls backlog)
 *   wakeup.v1                                (Phase 4/5 hook point → unsupported)
 *
 * Network scoping: with a legacy token present, ISCP sessions also create
 * their legacy server session (dual-stack); ISCP-only profiles run fully
 * serverless (decideSessionNetwork/decideDaemonNetwork in networkStartup.ts).
 */

import { createHash, randomUUID } from 'node:crypto'
import { z } from 'zod'

import {
  encodeWireCursor,
  decodeWireCursor,
  PhoneTextViewBodySchema,
  UserMessageSchema,
  type HappyWireRequest,
  type HappyWireResponse,
  type HappyWireError,
  type WireHistoryView,
} from '@slopus/happy-wire'

import type { TrackedSession } from '@/daemon/types'
import type { SpawnSessionOptions, SpawnSessionResult } from '@/modules/common/registerCommonHandlers'
import { logger } from '@/ui/logger'
import type { DaemonIscpService } from '@/iscp/daemonIscp'
import { USER_MESSAGE_METHOD } from '@/iscp/sessionRpcServer'

const SessionsSpawnParams = z.object({
  directory: z.string().min(1),
  agent: z.enum(['claude', 'codex', 'gemini', 'openclaw', 'agy']).optional(),
  permissionMode: z.string().optional(),
  modelMode: z.string().optional(),
})

const SessionsStopParams = z.object({ sessionId: z.string().min(1) })

const SessionsArchiveParams = z.object({
  sessionId: z.string().min(1),
  archived: z.boolean().optional(),
})

const MessagesPullParams = z.object({
  sessionId: z.string().min(1),
  afterCursor: z.string().optional(),
  limit: z.number().int().min(1).max(500).optional(),
})

const MessagesSendParams = z.object({
  sessionId: z.string().min(1),
  body: z.unknown(),
})

const SessionRpcParams = z.object({
  sessionId: z.string().min(1),
  method: z.string().min(1),
  params: z.unknown(),
})

const MachineRpcParams = z.object({
  method: z.string().min(1),
  params: z.unknown(),
})

function failure(id: string, code: HappyWireError['code'], message: string): HappyWireResponse {
  return { ok: false, id, error: { code, message } }
}

function success(id: string, result: unknown): HappyWireResponse {
  return { ok: true, id, result }
}

export interface WireResponderDeps {
  iscp: DaemonIscpService
  profileId: string
  /**
   * History surface this peer's Trust Grant authorizes
   * (wireViewForPermissions): 'raw' serves the internal session protocol
   * verbatim (official Happy client), 'text' serves the materialized
   * phone/text view — projected bubbles, view-local contiguous cursors, and
   * a text-only write boundary (OPS 2026-08-18 §10.16).
   */
  view: WireHistoryView
  getChildren: () => TrackedSession[]
  stopSession: (sessionId: string) => boolean
  spawnSession: (options: SpawnSessionOptions) => Promise<SpawnSessionResult>
  /** Injectable for tests; defaults to global fetch. */
  fetchImpl?: typeof fetch
}

/** Short stable hash for logging opaque cursors without their content. */
function cursorHash(cursor: string | undefined): string | null {
  if (cursor === undefined) return null
  return createHash('sha256').update(cursor).digest('hex').slice(0, 12)
}

export class WireResponder {
  constructor(private readonly deps: WireResponderDeps) {}

  /**
   * sessionId → localIds confirmed delivered to the agent process. Delivery
   * (not persistence) is the success criterion for messages.send, so a
   * deduped retry must re-forward until the agent has actually confirmed.
   * In-memory only: after a daemon restart a retried send re-forwards, which
   * is the safe direction (at-least-once toward the agent).
   */
  private readonly deliveredUserMessages = new Map<string, Set<string>>()

  async handle(request: HappyWireRequest): Promise<HappyWireResponse> {
    // P1 wire logging contract: request id / method / session / result code /
    // duration — never bodies.
    const startedAt = Date.now()
    const response = await this.dispatch(request)
    const params = request.params as { sessionId?: unknown } | undefined
    logger.debug('[WIRE RESPONDER] request handled', {
      profileId: this.deps.profileId,
      requestId: request.id,
      method: request.method,
      sessionId: typeof params?.sessionId === 'string' ? params.sessionId : null,
      view: this.deps.view,
      resultCode: response.ok ? 'ok' : response.error.code,
      durationMs: Date.now() - startedAt,
    })
    return response
  }

  private async dispatch(request: HappyWireRequest): Promise<HappyWireResponse> {
    try {
      switch (request.method) {
        case 'sessions.list':
          return success(request.id, this.sessionsList())
        case 'sessions.spawn':
          return await this.sessionsSpawn(request)
        case 'sessions.stop': {
          const params = SessionsStopParams.parse(request.params)
          return success(request.id, { stopped: this.deps.stopSession(params.sessionId) })
        }
        case 'sessions.archive':
          return this.sessionsArchive(request)
        case 'messages.pull':
          return this.messagesPull(request)
        case 'messages.send':
          return await this.messagesSend(request)
        case 'session.rpc':
          return await this.sessionRpc(request)
        case 'machine.rpc':
          return await this.machineRpc(request)
        case 'events.subscribe':
          // Subscription state is tracked by the peer runner (per device);
          // this response just acknowledges the switch to live push.
          return success(request.id, { subscribed: true })
        case 'wakeup.v1':
          // Phase 4/5 hook point: Cloud-triggered wakeups (data-only push).
          return failure(request.id, 'unsupported', 'wakeup.v1 is not available in this phase')
        default:
          return failure(request.id, 'unsupported', `unknown method ${request.method}`)
      }
    } catch (error) {
      if (error instanceof z.ZodError) {
        return failure(request.id, 'invalid', `invalid params for ${request.method}`)
      }
      logger.debug('[WIRE RESPONDER] request failed', { method: request.method, error })
      return failure(request.id, 'retryable', error instanceof Error ? error.message : 'internal error')
    }
  }

  private runningSessions(): Map<string, TrackedSession> {
    const running = new Map<string, TrackedSession>()
    for (const child of this.deps.getChildren()) {
      if (child.happySessionId !== undefined) running.set(child.happySessionId, child)
    }
    return running
  }

  /**
   * Liveness is the UNION of the child-process table and the registered
   * session RPC bridges. After a daemon restart the agent process is not a
   * child of the new daemon (it cannot be re-adopted — there is no
   * ChildProcess handle and the registration carries no pid), but its
   * lifetime heartbeat re-registers the RPC port; that registration is the
   * daemon's authoritative proof of a reachable agent.
   */
  private isSessionLive(sessionId: string, running: Map<string, TrackedSession>): boolean {
    return running.has(sessionId)
      || this.deps.iscp.sessionRpcPort(this.deps.profileId, sessionId) !== null
  }

  private sessionsList(): unknown {
    const log = this.deps.iscp.log(this.deps.profileId)
    const running = this.runningSessions()
    // Persist display attributes while the process is alive, so history
    // entries stay identifiable (not just an opaque id) after it exits.
    for (const [sessionId, child] of running) {
      const metadata = child.happySessionMetadataFromLocalWebhook
      if (!metadata) continue
      log.describe(sessionId, {
        ...(metadata.name !== undefined ? { displayName: metadata.name } : {}),
        directory: metadata.path,
        ...(metadata.flavor !== undefined ? { agentType: metadata.flavor } : {}),
      })
    }
    const known = new Set<string>([
      ...running.keys(),
      ...this.deps.iscp.sessionIdsWithRpcPort(this.deps.profileId),
      ...log.listSessions(),
    ])
    const sessions = [...known].map((sessionId) => {
      const info = log.sessionInfo(sessionId)
      const active = this.isSessionLive(sessionId, running)
      // Lifecycle contract for list consumers: show 'active' prominently,
      // fold 'idle' history away, and let 'archived' be safely hidden.
      const lifecycle = active ? 'active' : (info?.archived ?? false) ? 'archived' : 'idle'
      // A text-view peer's cursor line lives in view coordinates: advertising
      // the raw lastSeq here would make the phone chase seqs it can never
      // pull (the "filtered raw cursor" trap the projection contract forbids).
      const cursorFacts = this.deps.view === 'text' && info
        ? this.deps.iscp.textView(this.deps.profileId).info(sessionId)
        : info
      return {
        sessionId,
        active,
        lifecycle,
        pid: running.get(sessionId)?.pid,
        lastSeq: cursorFacts?.lastSeq ?? 0,
        lastCursor: cursorFacts ? encodeWireCursor({ scope: sessionId, seq: cursorFacts.lastSeq, epoch: cursorFacts.epoch }) : undefined,
        ...(info?.createdAt !== undefined ? { createdAt: info.createdAt } : {}),
        ...(info?.lastActiveAt !== undefined ? { lastActiveAt: info.lastActiveAt } : {}),
        ...(info?.displayName !== undefined ? { displayName: info.displayName } : {}),
        ...(info?.directory !== undefined ? { directory: info.directory } : {}),
        ...(info?.agentType !== undefined ? { agentType: info.agentType } : {}),
      }
    })
    return { sessions }
  }

  private sessionsArchive(request: HappyWireRequest): HappyWireResponse {
    const params = SessionsArchiveParams.parse(request.params)
    const archived = params.archived ?? true
    // Same union as sessions.list: an agent that only re-registered via the
    // heartbeat (daemon restarted) is still running and must not be archived.
    if (archived && this.isSessionLive(params.sessionId, this.runningSessions())) {
      return failure(request.id, 'conflict', `session ${params.sessionId} is running; stop it before archiving`)
    }
    const found = this.deps.iscp.log(this.deps.profileId).setArchived(params.sessionId, archived)
    if (!found) {
      return failure(request.id, 'not_found', `session ${params.sessionId} has no history on this machine`)
    }
    return success(request.id, { sessionId: params.sessionId, archived })
  }

  private async sessionsSpawn(request: HappyWireRequest): Promise<HappyWireResponse> {
    const params = SessionsSpawnParams.parse(request.params)
    const result = await this.deps.spawnSession({
      directory: params.directory,
      agent: params.agent,
      permissionMode: params.permissionMode,
      modelMode: params.modelMode,
      environmentVariables: { HAPPY_NETWORK_PROFILE: this.deps.profileId },
    })
    switch (result.type) {
      case 'success':
        if (!result.sessionId) {
          return failure(request.id, 'retryable', 'spawn returned no session id')
        }
        return success(request.id, { sessionId: result.sessionId })
      case 'requestToApproveDirectoryCreation':
        return failure(request.id, 'conflict', `directory requires approval: ${result.directory}`)
      case 'error':
        return failure(request.id, 'invalid', result.errorMessage)
    }
  }

  private messagesPull(request: HappyWireRequest): HappyWireResponse {
    const params = MessagesPullParams.parse(request.params)
    const log = this.deps.iscp.log(this.deps.profileId)
    const info = log.sessionInfo(params.sessionId)
    if (!info) {
      return success(request.id, { events: [], hasMore: false, lastCursor: null, reset: false })
    }
    const epoch = this.deps.view === 'text'
      ? this.deps.iscp.textView(this.deps.profileId).info(params.sessionId)!.epoch
      : info.epoch
    // Cursor validation: wrong scope or stale epoch → full re-sync from 0,
    // flagged so the client knows to discard local state. For a text-view
    // peer the epoch is the VIEW epoch — a projector rebuild invalidates the
    // phone's cursor even when the raw log kept its own.
    let afterSeq = 0
    let reset = false
    if (params.afterCursor !== undefined) {
      const cursor = decodeWireCursor(params.afterCursor)
      if (cursor !== null && cursor.scope === params.sessionId && cursor.epoch === epoch) {
        afterSeq = cursor.seq
      } else {
        reset = true
      }
    }
    const limit = params.limit ?? 200
    const page = this.deps.view === 'text'
      ? this.readTextPage(params.sessionId, afterSeq, limit)
      : log.read(params.sessionId, afterSeq, limit)!
    logger.debug('[WIRE RESPONDER] messages.pull', {
      profileId: this.deps.profileId,
      requestId: request.id,
      sessionId: params.sessionId,
      view: this.deps.view,
      afterCursorHash: cursorHash(params.afterCursor),
      afterSeq,
      returnedRange: page.events.length > 0 ? [page.events[0].seq, page.events[page.events.length - 1].seq] : null,
      returnedCount: page.events.length,
      reset,
      hasMore: page.hasMore,
      lastSeq: page.lastSeq,
    })
    return success(request.id, {
      events: page.events.map((event) => ({
        seq: event.seq,
        cursor: encodeWireCursor({ scope: params.sessionId, seq: event.seq, epoch: page.epoch }),
        ...(event.localId !== undefined ? { localId: event.localId } : {}),
        body: event.body,
        at: event.at,
      })),
      hasMore: page.hasMore,
      lastCursor: encodeWireCursor({ scope: params.sessionId, seq: page.lastSeq, epoch: page.epoch }),
      reset,
    })
  }

  /**
   * Text-view history page in the raw page's shape (seq/localId/body/at).
   * Every body is re-validated against the published view schema — the
   * responder never emits anything that does not pass it (fail-closed).
   */
  private readTextPage(sessionId: string, afterSeq: number, limit: number): {
    events: Array<{ seq: number; localId?: string; body: unknown; at: number }>
    lastSeq: number
    epoch: string
    hasMore: boolean
  } {
    const page = this.deps.iscp.textView(this.deps.profileId).read(sessionId, afterSeq, limit)!
    return {
      events: page.events
        .filter((event) => PhoneTextViewBodySchema.safeParse(event.body).success)
        .map((event) => ({
          seq: event.viewSeq,
          ...(event.localId !== undefined ? { localId: event.localId } : {}),
          body: event.body,
          at: event.at,
        })),
      lastSeq: page.lastSeq,
      epoch: page.epoch,
      hasMore: page.hasMore,
    }
  }

  private async messagesSend(request: HappyWireRequest): Promise<HappyWireResponse> {
    const params = MessagesSendParams.parse(request.params)
    const localId = request.idempotencyKey
    if (localId === undefined || localId === '') {
      return failure(request.id, 'invalid', 'messages.send requires an idempotencyKey')
    }
    // Write boundary for a text-permission grant: only plain user text may
    // enter the log. Anything else is rejected before persistence — the
    // permission gate cuts both directions.
    if (this.deps.view === 'text') {
      const userText = UserMessageSchema.safeParse(params.body)
      if (!userText.success || userText.data.content.text === '') {
        return failure(request.id, 'invalid', 'this grant only permits plain text user messages')
      }
    }
    // Persist first (idempotent outbox), but success means DELIVERED to the
    // agent, not persisted: a send whose forward fails returns 'retryable'
    // and the caller redelivers with the same idempotencyKey — the dedupe
    // then reuses the stored seq while the forward is attempted again.
    const result = this.deps.iscp.ingest(this.deps.profileId, params.sessionId, [
      { localId, body: params.body },
    ])[0]
    const alreadyDelivered = this.deliveredUserMessages.get(params.sessionId)?.has(localId) ?? false
    if (!alreadyDelivered) {
      const delivered = await this.forwardToSession(params.sessionId, USER_MESSAGE_METHOD, params.body)
      if (delivered === null || !delivered.ok) {
        return failure(
          request.id,
          'retryable',
          `session ${params.sessionId} agent is not reachable; the message is persisted — retry with the same idempotencyKey to deliver it`,
        )
      }
      let deliveredSet = this.deliveredUserMessages.get(params.sessionId)
      if (!deliveredSet) {
        deliveredSet = new Set()
        this.deliveredUserMessages.set(params.sessionId, deliveredSet)
      }
      deliveredSet.add(localId)
      logger.debug('[WIRE RESPONDER] user message delivered', { sessionId: params.sessionId, seq: result.seq })
    }
    // A text-view peer's ack cursor must live on the VIEW seq line (same
    // localId), or its next pull would resume from a raw seq it cannot see.
    if (this.deps.view === 'text') {
      const view = this.deps.iscp.textView(this.deps.profileId)
      const viewSeq = view.viewSeqForLocalId(params.sessionId, localId)
      const viewInfo = view.info(params.sessionId)
      if (viewSeq === null || viewInfo === null) {
        return failure(request.id, 'retryable', 'message persisted but not yet visible in the text view; retry with the same idempotencyKey')
      }
      return success(request.id, {
        seq: viewSeq,
        deduped: result.deduped,
        delivery: 'delivered',
        cursor: encodeWireCursor({ scope: params.sessionId, seq: viewSeq, epoch: viewInfo.epoch }),
      })
    }
    return success(request.id, {
      seq: result.seq,
      deduped: result.deduped,
      delivery: 'delivered',
      cursor: encodeWireCursor({ scope: params.sessionId, seq: result.seq, epoch: result.epoch }),
    })
  }

  private async sessionRpc(request: HappyWireRequest): Promise<HappyWireResponse> {
    const params = SessionRpcParams.parse(request.params)
    const result = await this.forwardToSession(params.sessionId, params.method, params.params)
    if (result === null) {
      // Distinguish "no such session" from "session exists but its agent
      // bridge is down": the latter is transient (heartbeat re-registers) and
      // must not be classified as a missing session by the caller.
      const known = this.isSessionLive(params.sessionId, this.runningSessions())
        || this.deps.iscp.log(this.deps.profileId).sessionInfo(params.sessionId) !== null
      if (!known) {
        return failure(request.id, 'not_found', `session ${params.sessionId} is unknown on this machine`)
      }
      return failure(request.id, 'retryable', `session ${params.sessionId} agent is not reachable`)
    }
    if (!result.ok) {
      return failure(request.id, 'invalid', result.error)
    }
    return success(request.id, result.result)
  }

  private async machineRpc(request: HappyWireRequest): Promise<HappyWireResponse> {
    const params = MachineRpcParams.parse(request.params)
    switch (params.method) {
      case 'spawn-happy-session':
        return await this.sessionsSpawn({ ...request, params: params.params })
      case 'stop-session': {
        const stop = SessionsStopParams.parse(params.params)
        return success(request.id, { stopped: this.deps.stopSession(stop.sessionId) })
      }
      default:
        return failure(request.id, 'unsupported', `unknown machine method ${params.method}`)
    }
  }

  private async forwardToSession(
    sessionId: string,
    method: string,
    params: unknown,
  ): Promise<{ ok: true; result: unknown } | { ok: false; error: string } | null> {
    const port = this.deps.iscp.sessionRpcPort(this.deps.profileId, sessionId)
    if (port === null) return null
    const fetchImpl = this.deps.fetchImpl ?? fetch
    try {
      const response = await fetchImpl(`http://127.0.0.1:${port}/rpc`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ method, params }),
        signal: AbortSignal.timeout(30_000),
      })
      const body = (await response.json()) as { ok: boolean; result?: unknown; error?: string }
      if (body.ok) return { ok: true, result: body.result ?? null }
      return { ok: false, error: body.error ?? 'session rpc failed' }
    } catch (error) {
      logger.debug('[WIRE RESPONDER] session rpc unreachable', { sessionId, method, error })
      return null
    }
  }
}

export function newWireRequestId(): string {
  return randomUUID()
}
