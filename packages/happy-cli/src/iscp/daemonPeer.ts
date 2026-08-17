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

import {
  WIRE_EVENT_PAYLOAD_TYPE,
  WIRE_REQUEST_PAYLOAD_TYPE,
  WIRE_RESPONSE_PAYLOAD_TYPE,
  HappyWireRequestSchema,
  defaultAgentCapabilityManifest,
  encodeWireCursor,
  type SessionWireEvent,
} from '@slopus/happy-wire'
import {
  IscpPeer,
  RelayHttpClient,
  TrustRootClient,
  createNobleProvider,
  verifyRelayDescriptor,
  verifyTrustRootDescriptor,
  utf8Decode,
  utf8Encode,
  type CryptoProvider,
} from '@slopus/iscp'

import { logger } from '@/ui/logger'
import { listProfiles, readProfileBundle, readProfileDevice, updateProfileCredentials } from '@/iscp/enrollment'
import { startSessionInitiator, type ProfilePeerStatus, type ProfileSessionState } from '@/iscp/sessionInitiator'
import type { DaemonIscpService, SessionEventNotification } from '@/iscp/daemonIscp'
import { WireResponder, type WireResponderDeps } from '@/iscp/wireResponder'

export type { ProfilePeerStatus, ProfileSessionState } from '@/iscp/sessionInitiator'

export interface DaemonIscpPeers {
  /** Profiles that came online. */
  profiles: string[]
  /** Relay WS state per online peer (diagnostics). */
  connectionStates: () => string[]
  /** Full per-profile diagnostics (transport + session layers). */
  statuses: () => ProfilePeerStatus[]
  stop: () => void
}

interface ProfilePeerHandle {
  profileId: string
  status: () => ProfilePeerStatus
  stop: () => void
}

/**
 * Start peers for every enrolled profile. Profiles that fail to come online
 * (relay unreachable, revoked credentials) are logged and skipped — the
 * daemon must keep serving legacy traffic regardless.
 */
export async function startDaemonIscpPeers(
  deps: Omit<WireResponderDeps, 'profileId'>,
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
    stop: () => {
      for (const handle of handles) handle.stop()
    },
  }
}

async function startProfilePeer(
  provider: CryptoProvider,
  profileId: string,
  deps: Omit<WireResponderDeps, 'profileId'>,
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
  const trustRoot = new TrustRootClient({ baseUrl: enrolledTrust.base_url, trustRootId: bundle.trust_root_id, provider })

  const responder = new WireResponder({ ...deps, profileId })
  const subscribedPeers = new Set<string>()

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
    resolvePeerIdentity: async (deviceId) => (await trustRoot.deviceStatus(deviceId)).identity,
    manifest: defaultAgentCapabilityManifest(),
    provider,
    onCredentialsRotated: (credentials) => {
      try {
        updateProfileCredentials(profileId, credentials)
      } catch (error) {
        // Lock contention with an in-flight enroll/renew: tokens stay valid
        // in memory; the next rotation persists them.
        logger.debug(`[ISCP PEER] credential persistence deferred for ${profileId}`, { error })
      }
    },
    onPeerReady: (peerDeviceId) => {
      logger.debug(`[ISCP PEER] app peer ready: ${peerDeviceId} (profile ${profileId})`)
    },
    onPayload: (peerDeviceId, payloadType, plaintext) => {
      if (payloadType !== WIRE_REQUEST_PAYLOAD_TYPE) return
      void (async () => {
        const request = HappyWireRequestSchema.parse(JSON.parse(utf8Decode(plaintext)))
        if (request.method === 'events.subscribe') {
          subscribedPeers.add(peerDeviceId)
        }
        const response = await responder.handle(request)
        await peer.sendPayload(peerDeviceId, WIRE_RESPONSE_PAYLOAD_TYPE, utf8Encode(JSON.stringify(response)))
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
  const onSessionEvent = (notification: SessionEventNotification) => {
    if (notification.profileId !== profileId || notification.deduped) return
    const event: SessionWireEvent = {
      type: 'session-event',
      sessionId: notification.sessionId,
      seq: notification.record.seq,
      cursor: encodeWireCursor({ scope: notification.sessionId, seq: notification.record.seq, epoch: notification.epoch }),
      ...(notification.record.localId !== undefined ? { localId: notification.record.localId } : {}),
      body: notification.record.body,
    }
    for (const peerDeviceId of subscribedPeers) {
      peer.sendPayload(peerDeviceId, WIRE_EVENT_PAYLOAD_TYPE, utf8Encode(JSON.stringify(event))).catch((error) => {
        logger.debug('[ISCP PEER] event push failed', { peerDeviceId, error })
      })
    }
  }
  deps.iscp.events.on('session-event', onSessionEvent)

  peer.start()
  logger.debug(`[ISCP PEER] profile ${profileId} online as device ${device.identity.device_id}`)

  // Proactively dial the grant audience (the phone) — see sessionInitiator.ts.
  const audience = bundle.trust_grant.audience
  let sessionState: ProfileSessionState = 'connecting'
  let sessionDetail: string | undefined
  const initiator = startSessionInitiator({
    peerDeviceId: audience,
    openSession: (peerDeviceId, opts) => peer.openSession(peerDeviceId, opts),
    closeSession: (peerDeviceId) => peer.closeSession(peerDeviceId),
    grantExpiresAt: () => new Date(bundle.trust_grant.expires_at),
    onState: (state, detail) => {
      sessionState = state
      sessionDetail = detail
    },
    log: (line) => logger.debug(`[ISCP PEER] ${profileId}: ${line}`),
  })

  return {
    profileId,
    status: () => ({
      profileId,
      deviceId: device.identity.device_id,
      generation: bundle.generation ?? 1,
      connectionState: peer.connectionState,
      session: sessionState,
      ...(sessionDetail !== undefined ? { sessionDetail } : {}),
      peerDeviceId: audience,
    }),
    stop: () => {
      initiator.stop()
      // Settle any pending openSession so the loop terminates promptly.
      peer.closeSession(audience)
      deps.iscp.events.off('session-event', onSessionEvent)
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
    stop: () => {
      current?.stop()
      current = null
    },
  }
}
