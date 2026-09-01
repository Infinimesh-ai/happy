/**
 * Daemon-side ISCP peer runner: one IscpPeer per enrolled profile (the
 * daemon is the machine's single ISCP device; session processes never touch
 * ISCP keys). Bridges wire traffic to the WireResponder and pushes live
 * wire events to subscribed app peers.
 *
 * Payload routing after capability exchange:
 *   happy/wire-request.v1  → WireResponder.handle → happy/wire-response.v1
 *   happy/wire-event.v1    ← live session events for events.subscribe'd peers
 *
 * Each profile additionally runs a session INITIATOR loop
 * (sessionInitiator.ts): the daemon dials the grant audience proactively so
 * "device online but session never established" is a visible, classified
 * state instead of silence. `createIscpPeersController` wraps the whole set
 * with single-flight reload semantics for `POST /iscp/reload`.
 */

import { randomUUID } from 'node:crypto'

import {
  WIRE_EVENT_PAYLOAD_TYPE,
  WIRE_REQUEST_PAYLOAD_TYPE,
  WIRE_RESPONSE_PAYLOAD_TYPE,
  HappyWireRequestSchema,
  defaultAgentCapabilityManifest,
  encodeWireCursor,
  wireViewForPermissions,
  type MachineWireEvent,
  type SessionWireEvent,
} from '@slopus/happy-wire'
import {
  IscpErrorCodes,
  IscpPeer,
  RelayHttpClient,
  TrustRootClient,
  createNobleProvider,
  iscpError,
  verifyRelayDescriptor,
  verifyTrustRootDescriptor,
  utf8Decode,
  utf8Encode,
  type CryptoProvider,
} from '@slopus/iscp'

import { logger } from '@/ui/logger'
import { listProfiles, readProfileBundle, readProfileDevice, updateProfileCredentials } from '@/iscp/enrollment'
import { recoverProfileCredentialsNow } from '@/iscp/credentialRecovery'
import {
  startSessionInitiator,
  type ProfilePeerStatus,
  type ProfileSessionState,
} from '@/iscp/sessionInitiator'
import type { DaemonIscpService, SessionEventNotification, SessionLifecycleNotification, TextViewEventNotification } from '@/iscp/daemonIscp'
import { WireResponder, type WireResponderDeps } from '@/iscp/wireResponder'

export type { ProfilePeerStatus, ProfileSessionState } from '@/iscp/sessionInitiator'

export interface DaemonIscpPeers {
  /** Profiles that came online. */
  profiles: string[]
  /** Relay WS state per online peer (diagnostics). */
  connectionStates: () => string[]
  /** Full per-profile diagnostics (transport + session layers). */
  statuses: () => ProfilePeerStatus[]
  /** Trigger a bounded fresh Session for one profile, or every ready profile. */
  reopen: (profileId?: string) => { profiles: string[] }
  stop: () => void
}

interface ProfilePeerHandle {
  profileId: string
  status: () => ProfilePeerStatus
  reopen: () => boolean
  stop: () => void
}

/**
 * Start peers for every enrolled profile. Profiles that fail to come online
 * (relay unreachable, revoked credentials) are logged and skipped — the
 * daemon must keep serving legacy traffic regardless.
 */
export async function startDaemonIscpPeers(
  deps: Omit<WireResponderDeps, 'profileId' | 'view'>,
): Promise<DaemonIscpPeers> {
  const provider = createNobleProvider()
  const handles: ProfilePeerHandle[] = []
  for (const profileId of listProfiles()) {
    try {
      const handle = await startProfilePeer(provider, profileId, deps)
      if (handle) handles.push(handle)
    } catch (error) {
      logger.debug(`[ISCP PEER] profile ${profileId} failed to start`, { error })
    }
  }
  return {
    profiles: handles.map((handle) => handle.profileId),
    connectionStates: () => handles.map((handle) => handle.status().connectionState),
    statuses: () => handles.map((handle) => handle.status()),
    reopen: (profileId) => {
      const targets = profileId === undefined
        ? handles
        : handles.filter((handle) => handle.profileId === profileId)
      return {
        profiles: targets
          .filter((handle) => handle.reopen())
          .map((handle) => handle.profileId),
      }
    },
    stop: () => {
      for (const handle of handles) handle.stop()
    },
  }
}

async function startProfilePeer(
  provider: CryptoProvider,
  profileId: string,
  deps: Omit<WireResponderDeps, 'profileId' | 'view'>,
): Promise<ProfilePeerHandle | null> {
  const bundle = readProfileBundle(profileId)
  const device = readProfileDevice(provider, profileId)
  if (!bundle || !device) {
    logger.debug(`[ISCP PEER] profile ${profileId} has no usable bundle/key; skipping`)
    return null
  }

  // Re-fetch a fresh signed relay descriptor: reference services mint a new
  // signing key per boot, so the enrollment-time pin only warns.
  const enrolledRelay = verifyRelayDescriptor(provider, bundle.relay_descriptor, { now: new Date(bundle.enrolled_at) })
  const relayHttp = new RelayHttpClient({ baseUrl: enrolledRelay.base_url, relayId: bundle.relay_id, provider })
  const { descriptor: freshSigned, pin } = await relayHttp.fetchSignedDescriptor()
  const relayDescriptor = verifyRelayDescriptor(provider, freshSigned)
  if (pin !== undefined && pin !== bundle.relay_pin) {
    logger.debug(`[ISCP PEER] relay descriptor pin changed since enrollment for ${profileId} (reference services rotate keys per boot)`)
  }

  const enrolledTrust = verifyTrustRootDescriptor(provider, bundle.trust_root_descriptor, { now: new Date(bundle.enrolled_at) })
  const trustRoot = new TrustRootClient({ baseUrl: enrolledTrust.base_url, trustRootId: bundle.trust_root_id, domainId: bundle.domain_id, provider })

  // The Trust Grant's permission set decides which history surface this
  // profile's peers may see: only an explicit raw-session permission gets
  // the internal session protocol; the production phone grant (['text'])
  // gets the projected text view (OPS 2026-08-18 §10.16, fail-closed).
  const view = wireViewForPermissions(bundle.trust_grant.permissions)
  const responder = new WireResponder({ ...deps, profileId, view })
  const subscribedPeers = new Set<string>()
  let requestSessionReopen: ((cause: string) => boolean) | undefined
  let sessionReopenCoalesceCount = 0
  let helloAttemptCount = 0
  let helloSupersededCount = 0
  let helloCoalescedCount = 0

  const peer: IscpPeer = new IscpPeer({
    device,
    grant: bundle.trust_grant,
    relayDescriptor,
    credentials: {
      accessToken: bundle.access_credential.token,
      refreshToken: bundle.refresh_credential.token,
    },
    // The reference relay closes after every drain (sub-second cycles), so a
    // silent socket is dead after seconds, not the generic 60s default —
    // keep the daemon reachable across app reconnects.
    wsBackoff: { idleTimeoutMs: 15_000 },
    // The control phone may be offline while this daemon remains healthy.
    // Keep public handshakes short-lived so Relay drain cannot replay minutes
    // of obsolete initial attempts when the phone returns.
    handshakeTTLSeconds: 35,
    resolvePeerIdentity: async (deviceId) => {
      const record = await trustRoot.deviceStatus(deviceId)
      const status = record.status.toLowerCase()
      if (status === 'revoked') {
        throw iscpError(IscpErrorCodes.TrustInvalid, 'peer device has been revoked')
      }
      if (status !== 'authorized' && status !== 'trusted') {
        throw iscpError(IscpErrorCodes.TrustInvalid, 'peer device is not currently trusted')
      }
      return record.identity
    },
    manifest: defaultAgentCapabilityManifest(),
    provider,
    onCredentialsRotated: (credentials) => {
      try {
        // The full wire credentials carry the server's expiry facts
        // (expires_at/issued_at/credential_id/rotation_counter) — persisted
        // so status output reflects the REAL current lifecycle, not the
        // enrollment-time snapshot (OPS 2026-08-18 §8.2.4).
        updateProfileCredentials(profileId, credentials)
      } catch (error) {
        // Lock contention with an in-flight enroll/renew: tokens stay valid
        // in memory; the next rotation persists them.
        logger.debug(`[ISCP PEER] credential persistence deferred for ${profileId}`, { error })
      }
    },
    // Terminal refresh failure (expired past the 24h TTL / revoked chain):
    // recover with the device key + current grant instead of dying on a dead
    // bearer (InfinimeshCloud §11). recoverProfileCredentialsNow persists the
    // pair atomically itself; a non-recovered outcome (action-required,
    // transient, unknown) propagates as a transport error and never falls
    // back to enroll/replace. The stale token is the cross-process fence
    // (OPS 2026-08-18 §10.6.2): a recovery that another process already
    // completed is adopted, never re-issued.
    recoverCredentials: async ({ staleRefreshToken }) => {
      const outcome = await recoverProfileCredentialsNow({
        profileId,
        provider,
        staleRefreshToken,
        log: (line) => logger.debug(`[ISCP PEER] ${line}`),
      })
      if (outcome.result !== 'recovered') {
        throw new Error(`relay credential recovery did not complete (${outcome.result}${'reason' in outcome ? `: ${outcome.reason}` : ''})`)
      }
      return { accessToken: outcome.accessToken, refreshToken: outcome.refreshToken }
    },
    onPeerReady: (peerDeviceId) => {
      logger.debug(`[ISCP PEER] app peer ready: ${peerDeviceId} (profile ${profileId})`)
    },
    onSessionReopen: (request) => {
      const cause = `peer_${request.cause}`
      const accepted = requestSessionReopen?.(cause) ?? false
      if (!accepted) sessionReopenCoalesceCount += 1
      logger.debug('[ISCP PEER] authenticated Session reopen received', {
        profileId,
        peerDeviceId: request.device_id,
        cause: request.cause,
        accepted,
        coalesceCount: sessionReopenCoalesceCount,
      })
    },
    onSessionDiagnostic: (event) => {
      if (event.event === 'reopen_coalesced') sessionReopenCoalesceCount += 1
      if (event.event === 'hello_attempt') helloAttemptCount += 1
      if (event.event === 'hello_superseded') helloSupersededCount += 1
      if (event.event === 'hello_coalesced') helloCoalescedCount += 1
      const { pendingCount, ...metadata } = event
      logger.debug('[ISCP PEER] Session lifecycle', {
        profileId,
        ...metadata,
        ...(pendingCount !== undefined ? { pending_count: pendingCount } : {}),
      })
    },
    onPayload: (peerDeviceId, payloadType, plaintext) => {
      if (payloadType !== WIRE_REQUEST_PAYLOAD_TYPE) return
      void (async () => {
        const request = HappyWireRequestSchema.parse(JSON.parse(utf8Decode(plaintext)))
        if (request.method === 'events.subscribe') {
          subscribedPeers.add(peerDeviceId)
          logger.debug('[ISCP PEER] events.subscribe', { profileId, peerDeviceId, view, subscriberCount: subscribedPeers.size })
        }
        const response = await responder.handle(request)
        try {
          await peer.sendPayload(peerDeviceId, WIRE_RESPONSE_PAYLOAD_TYPE, utf8Encode(JSON.stringify(response)))
        } catch (error) {
          // P1 logging contract: response submission success/failure must be
          // distinguishable from "responder never answered".
          logger.debug('[ISCP PEER] wire response submit failed', { profileId, peerDeviceId, requestId: request.id, method: request.method, error })
          throw error
        }
        logger.debug('[ISCP PEER] wire response submitted', { profileId, peerDeviceId, requestId: request.id, method: request.method, resultCode: response.ok ? 'ok' : response.error.code })
      })().catch((error) => {
        logger.debug('[ISCP PEER] wire request handling failed', { peerDeviceId, error })
      })
    },
    onConnectionState: (state) => {
      // READY fires every drain cycle (reference relay closes after drain);
      // only transitions around failures are interesting.
      if (state === 'CLOSED') {
        logger.debug(`[ISCP PEER] relay ws CLOSED (profile ${profileId}) — peer will no longer receive envelopes`)
      }
    },
    onError: (error) => {
      logger.debug(`[ISCP PEER] transport error (profile ${profileId})`, { error })
    },
  })

  // Live push: fan session-event notifications out to subscribed peers.
  // The handler reference is kept so stop() can remove it — otherwise every
  // reload doubles the pushes (listener leak).
  // Session lifecycle push (session.added / agent reachable / unreachable):
  // the app must not depend on polling sessions.list to notice that a spawned
  // session's agent finished registering its RPC bridge. There is no machine
  // event log to replay, so the cursor is ordering-only (per-peer epoch).
  const machineEventEpoch = randomUUID()
  let machineEventSeq = 0
  const onSessionLifecycle = (notification: SessionLifecycleNotification) => {
    if (notification.profileId !== profileId) return
    machineEventSeq += 1
    const event: MachineWireEvent = {
      type: 'machine-event',
      machineId: device.identity.device_id,
      cursor: encodeWireCursor({ scope: `machine:${device.identity.device_id}`, seq: machineEventSeq, epoch: machineEventEpoch }),
      body: {
        kind: 'session.lifecycle',
        sessionId: notification.sessionId,
        change: notification.change,
        reason: notification.reason,
        at: Date.now(),
      },
    }
    for (const peerDeviceId of subscribedPeers) {
      peer.sendPayload(peerDeviceId, WIRE_EVENT_PAYLOAD_TYPE, utf8Encode(JSON.stringify(event))).catch((error) => {
        logger.debug('[ISCP PEER] lifecycle push failed', { peerDeviceId, error })
      })
    }
  }
  deps.iscp.events.on('session-lifecycle', onSessionLifecycle)

  // Chat history push branches on the grant's view: raw peers get the
  // internal protocol events verbatim (unchanged behavior), text peers get
  // ONLY materialized text-view records — same projector and store as
  // messages.pull, in view coordinates, so live and history can never
  // disagree (OPS 2026-08-18 §10.16).
  const pushWireEvent = (event: SessionWireEvent, eventKind: string) => {
    for (const peerDeviceId of subscribedPeers) {
      peer.sendPayload(peerDeviceId, WIRE_EVENT_PAYLOAD_TYPE, utf8Encode(JSON.stringify(event)))
        .then(() => {
          logger.debug('[ISCP PEER] event push submitted', { profileId, peerDeviceId, sessionId: event.sessionId, seq: event.seq, eventKind, view })
        })
        .catch((error) => {
          // No retry here by design: the phone recovers via messages.pull
          // from its cursor; the log line is what distinguishes "projected
          // but never submitted" from "phone never caught up".
          logger.debug('[ISCP PEER] event push failed (peer recovers via pull)', { profileId, peerDeviceId, sessionId: event.sessionId, seq: event.seq, eventKind, view, error })
        })
    }
  }
  const onSessionEvent = (notification: SessionEventNotification) => {
    if (view !== 'raw' || notification.profileId !== profileId || notification.deduped) return
    pushWireEvent({
      type: 'session-event',
      sessionId: notification.sessionId,
      seq: notification.record.seq,
      cursor: encodeWireCursor({ scope: notification.sessionId, seq: notification.record.seq, epoch: notification.epoch }),
      ...(notification.record.localId !== undefined ? { localId: notification.record.localId } : {}),
      body: notification.record.body,
    }, 'raw-session-event')
  }
  deps.iscp.events.on('session-event', onSessionEvent)

  const onTextViewEvent = (notification: TextViewEventNotification) => {
    if (view !== 'text' || notification.profileId !== profileId) return
    pushWireEvent({
      type: 'session-event',
      sessionId: notification.sessionId,
      seq: notification.record.viewSeq,
      cursor: encodeWireCursor({ scope: notification.sessionId, seq: notification.record.viewSeq, epoch: notification.viewEpoch }),
      ...(notification.record.localId !== undefined ? { localId: notification.record.localId } : {}),
      body: notification.record.body,
    }, 'text-view-event')
  }
  deps.iscp.events.on('text-view-event', onTextViewEvent)

  peer.start()
  logger.debug(`[ISCP PEER] profile ${profileId} online as device ${device.identity.device_id}`)

  // Proactively dial the grant audience (the phone) — see sessionInitiator.ts.
  const audience = bundle.trust_grant.audience
  let sessionState: ProfileSessionState = 'connecting'
  let sessionDetail: string | undefined
  let sessionAttempt = 0
  let sessionReopenCount = 0
  const initiator = startSessionInitiator({
    peerDeviceId: audience,
    openSession: (peerDeviceId, opts) => {
      sessionAttempt += 1
      return peer.openSession(peerDeviceId, opts)
    },
    closeSession: (peerDeviceId) => peer.closeSession(peerDeviceId),
    grantExpiresAt: () => new Date(bundle.trust_grant.expires_at),
    onState: (state, detail) => {
      sessionState = state
      sessionDetail = detail
    },
    log: (line) => logger.debug(`[ISCP PEER] ${profileId}: ${line}`),
    // Managed profiles rotate only from the authenticated phone control
    // signal (or the local control endpoint), never from idle time alone.
    superviseReopen: true,
    // Paired with the 35-second Hello TTL: at most the current and boundary
    // attempt can still be valid at the Relay, with <=30s reconnect latency.
    timeoutMs: 30_000,
    sessionStatus: () => {
      const current = peer.sessionStatus(audience)
      if (!current) return undefined
      return {
        sessionId: current.sessionId,
        role: current.role,
        ...(current.lastAuthenticatedAt !== undefined ? { lastAuthenticatedAt: current.lastAuthenticatedAt } : {}),
      }
    },
    onBeforeReopen: (cause, previous) => {
      sessionReopenCount += 1
      subscribedPeers.delete(audience)
      logger.debug('[ISCP PEER] session reopening', {
        profileId,
        peerDeviceId: audience,
        cause,
        sessionId: previous?.sessionId,
        role: previous?.role,
        lastVerifiedAt: previous?.lastAuthenticatedAt,
        attempt: sessionAttempt,
        reopenCount: sessionReopenCount,
      })
    },
  })
  requestSessionReopen = (cause) => initiator.requestReopen(cause)

  return {
    profileId,
    status: () => {
      const current = peer.sessionStatus(audience)
      return {
        profileId,
        deviceId: device.identity.device_id,
        generation: bundle.generation ?? 1,
        connectionState: peer.connectionState,
        session: sessionState,
        ...(sessionDetail !== undefined ? { sessionDetail } : {}),
        peerDeviceId: audience,
        ...(current !== undefined ? {
          sessionId: current.sessionId,
          sessionRole: current.role,
          ...(current.lastAuthenticatedAt !== undefined ? { sessionLastVerifiedAt: current.lastAuthenticatedAt } : {}),
        } : {}),
        sessionAttempt,
        sessionReopenCount,
        sessionReopenCoalesceCount,
        helloAttemptCount,
        helloSupersededCount,
        helloCoalescedCount,
        pendingCount: peer.pendingHelloCount(audience),
      }
    },
    reopen: () => initiator.requestReopen('controlled_reopen'),
    stop: () => {
      initiator.stop()
      // Settle any pending openSession so the loop terminates promptly.
      peer.closeSession(audience)
      deps.iscp.events.off('session-event', onSessionEvent)
      deps.iscp.events.off('text-view-event', onTextViewEvent)
      deps.iscp.events.off('session-lifecycle', onSessionLifecycle)
      peer.stop()
    },
  }
}

// ---------------------------------------------------------------------------
// Reloadable controller (single-flight)
// ---------------------------------------------------------------------------

export interface IscpPeersController {
  /**
   * Stop the current peers and rescan/restart every enrolled profile.
   * Single-flight: while a reload runs, concurrent calls coalesce into
   * exactly one queued follow-up reload (so a call always observes a scan
   * that started after it).
   */
  reload: () => Promise<{ profiles: string[] }>
  profiles: () => string[]
  statuses: () => ProfilePeerStatus[]
  connectionStates: () => string[]
  /** Request a fresh Session without replacing the peer runtime or identity. */
  reopen: (profileId?: string) => { profiles: string[] }
  stop: () => void
}

export function createIscpPeersController(start: () => Promise<DaemonIscpPeers>): IscpPeersController {
  let current: DaemonIscpPeers | null = null
  let inflight: Promise<{ profiles: string[] }> | null = null
  let queued: Promise<{ profiles: string[] }> | null = null

  const runReload = async (): Promise<{ profiles: string[] }> => {
    current?.stop()
    current = null
    current = await start()
    return { profiles: current.profiles }
  }

  const reload = (): Promise<{ profiles: string[] }> => {
    if (inflight !== null) {
      queued ??= inflight
        .catch(() => {
          /* the queued run reloads regardless of the inflight outcome */
        })
        .then(() => {
          queued = null
          return reload()
        })
      return queued
    }
    inflight = runReload().finally(() => {
      inflight = null
    })
    return inflight
  }

  return {
    reload,
    profiles: () => current?.profiles ?? [],
    statuses: () => current?.statuses() ?? [],
    connectionStates: () => current?.connectionStates() ?? [],
    reopen: (profileId) => current?.reopen(profileId) ?? { profiles: [] },
    stop: () => {
      current?.stop()
      current = null
    },
  }
}
