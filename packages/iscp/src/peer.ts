/**
 * IscpPeer: one enrolled device talking to its peers through a relay.
 *
 * Responsibilities:
 * - relay WS receive loop (challenge → proof → ready → drain, reconnect with
 *   backoff) and HTTP envelope submission with PoP + access-credential
 *   refresh;
 * - session lifecycle: hello exchange, transcript-bound key establishment,
 *   ready confirmation; business payloads are refused until `session.ready`
 *   is verified in both directions;
 * - the first business payload after ready is the capability manifest
 *   (agent.capability.v1 by convention — the schema lives in
 *   @slopus/happy-wire); all other payload types are gated until manifests
 *   have been exchanged;
 * - outbound offline queue: envelopes that fail to submit are queued and
 *   flushed once the relay is reachable again.
 *
 * Handshake transport convention (documented Happy-layer choice): session
 * hello/ready objects are themselves signed public objects with no
 * confidential content, and no session key exists yet, so they travel in
 * envelope-shaped messages whose `payload_type` is the handshake object type
 * and whose `ciphertext` field carries base64url(JSON) of the signed object
 * (sequence 0, random nonce). Receivers never treat handshake payload types
 * as business payloads.
 */

import { fromBase64Url, parseRfc3339, rfc3339Seconds, toBase64Url, utf8Decode, utf8Encode } from './encoding';
import { IscpError, IscpErrorCodes, iscpError } from './errors';
import { identityThumbprint, type Device } from './identity';
import { compareCodePoints } from './jcs';
import { createNobleProvider } from './crypto/noble';
import type { CryptoProvider } from './crypto/provider';
import { RelayHttpClient, type FetchLike, type RelayCredential, type RelayCredentialPair } from './relay/http';
import { RelayWsClient, type RelayWsBackoff, type RelayWsState } from './relay/ws';
import {
  SECURE_ENVELOPE_TYPE,
  SessionHelloSchema,
  SessionReopenSchema,
  SessionReadySchema,
  type DeviceIdentity,
  type EnvelopeRoute,
  type RelayDescriptor,
  type SecureEnvelope,
  type SessionReopen,
  type SessionReopenCause,
  type TrustGrant,
} from './schemas';
import { SESSION_HELLO_TYPE, SESSION_READY_TYPE, SESSION_REOPEN_TYPE } from './schemas';
import { signObject, verifyObjectSignature } from './signing';
import { createHello, establish, type LocalHello, type SessionState } from './session/handshake';
import { decryptEnvelope, encryptEnvelope } from './session/secureEnvelope';
import type { ReplayStore } from './session/replay';
import type { WebSocketFactory } from './ws-adapter';

export const CAPABILITY_MANIFEST_PAYLOAD_TYPE = 'agent.capability.v1';

const HANDSHAKE_PAYLOAD_TYPES = new Set<string>([SESSION_HELLO_TYPE, SESSION_READY_TYPE, SESSION_REOPEN_TYPE]);
const SESSION_REOPEN_TTL_MS = 30_000;

export interface SessionDiagnosticEvent {
  peerDeviceId: string;
  sessionId?: string;
  role?: 'initiator' | 'responder';
  event: 'create' | 'replace' | 'tombstone' | 'reopen_sent' | 'reopen_accepted' | 'reopen_rejected' | 'reopen_coalesced';
  cause?: string;
}

interface PeerSession {
  sessionId: string;
  role: 'initiator' | 'responder';
  peerDeviceId: string;
  peerIdentity: DeviceIdentity;
  local: LocalHello;
  state?: SessionState;
  manifestSent: boolean;
  peerManifest?: unknown;
  /** Last successfully authenticated inbound frame from this peer. */
  lastAuthenticatedAt?: number;
  readyWaiters: Array<{ resolve: (manifest: unknown) => void; reject: (error: unknown) => void }>;
}

/** Metadata-only view of a peer session. Never exposes transcript keys or payloads. */
export interface PeerSessionStatus {
  sessionId: string;
  role: PeerSession['role'];
  ready: boolean;
  manifestExchanged: boolean;
  lastAuthenticatedAt?: number;
}

export interface IscpPeerOptions {
  device: Device;
  grant: TrustGrant;
  relayDescriptor: RelayDescriptor;
  credentials: { accessToken: string; refreshToken: string };
  /** Resolve a peer's device identity (e.g. TrustRootClient.deviceStatus). */
  resolvePeerIdentity: (deviceId: string) => Promise<DeviceIdentity>;
  /** Capability manifest sent as the first business payload after session.ready. */
  manifest: unknown;
  manifestPayloadType?: string;
  provider?: CryptoProvider;
  wsFactory?: WebSocketFactory;
  wsBackoff?: Partial<RelayWsBackoff>;
  fetchImpl?: FetchLike;
  route?: Partial<Omit<EnvelopeRoute, 'relay_id'>>;
  replayStoreFor?: (sessionId: string, peerDeviceId: string) => ReplayStore | undefined;
  /**
   * Called whenever access/refresh credentials rotate, so callers can persist
   * them. `access`/`refresh` carry the full wire credentials (expires_at and,
   * on Infinimesh Cloud, credential_id/issued_at/rotation_counter) so callers
   * persist the real server expiry facts, never just token strings
   * (OPS 2026-08-18 §8.2.4).
   */
  onCredentialsRotated?: (credentials: {
    accessToken: string;
    refreshToken: string;
    access?: RelayCredential;
    refresh?: RelayCredential;
  }) => void;
  /**
   * Existing-device credential recovery hook (InfinimeshCloud
   * docs/10-design/12-managed-provisioning.md §11): invoked when the refresh
   * rotation itself fails terminally (the refresh bearer is expired or
   * revoked — a state `refreshAccess` can never leave). The callback owns
   * the whole recovery flow (PoP request, unseal, atomic persistence,
   * reload bookkeeping) and returns the fresh tokens; the peer then resumes
   * with them. It must NEVER fall back to enroll/replace. Without this hook
   * a terminal refresh failure propagates unchanged.
   *
   * `context.staleRefreshToken` is the exact bearer that just failed: the
   * cross-process fence (OPS 2026-08-18 §10.6.2) compares it against the
   * persisted bundle and ADOPTS a concurrent recovery instead of issuing a
   * second logical attempt for an epoch that already ended.
   */
  recoverCredentials?: (context: { staleAccessToken: string; staleRefreshToken: string }) => Promise<{ accessToken: string; refreshToken: string }>;
  onPayload?: (peerDeviceId: string, payloadType: string, plaintext: Uint8Array, envelope: SecureEnvelope) => void;
  /** Fires once per session when capability manifests have been exchanged. */
  onPeerReady?: (peerDeviceId: string, manifest: unknown) => void;
  /** Authenticated, grant-authorized request for the Happy initiator to rotate the transcript. */
  onSessionReopen?: (request: SessionReopen) => void;
  /** Metadata only. Never contains signed objects, manifests, credentials, or plaintext. */
  onSessionDiagnostic?: (event: SessionDiagnosticEvent) => void;
  onConnectionState?: (state: RelayWsState) => void;
  onError?: (error: unknown) => void;
  now?: () => Date;
}

export class IscpPeer {
  private readonly provider: CryptoProvider;
  private readonly http: RelayHttpClient;
  private readonly ws: RelayWsClient;
  private readonly manifestPayloadType: string;
  private readonly sessions = new Map<string, PeerSession>();
  /**
   * Session ids we have abandoned, per peer (closed locally or lost a
   * competing-session tie-break). Late hello/ready envelopes for these ids
   * are dropped instead of re-adopted — without this, two queued hellos from
   * the same initiator make both sides flip between the session ids forever.
   */
  private readonly staleSessionIds = new Map<string, Set<string>>();
  /** Short-lived authenticated reopen replay window, bounded per peer. */
  private readonly seenReopenRequestIds = new Map<string, string[]>();
  private readonly outboundQueue: SecureEnvelope[] = [];
  private accessToken: string;
  private refreshToken: string;
  private flushing = false;
  /**
   * Inbound envelopes are processed strictly in arrival order. Handlers
   * contain awaits (identity resolution, handshake submissions); without the
   * chain a WS delivery arriving mid-await could be handled out of order —
   * e.g. a peer's manifest overtaking its session.ready.
   */
  private inboundChain: Promise<void> = Promise.resolve();

  constructor(private readonly opts: IscpPeerOptions) {
    this.provider = opts.provider ?? createNobleProvider();
    this.manifestPayloadType = opts.manifestPayloadType ?? CAPABILITY_MANIFEST_PAYLOAD_TYPE;
    this.accessToken = opts.credentials.accessToken;
    this.refreshToken = opts.credentials.refreshToken;
    this.http = new RelayHttpClient({
      baseUrl: opts.relayDescriptor.base_url,
      relayId: opts.relayDescriptor.relay_id,
      provider: this.provider,
      fetchImpl: opts.fetchImpl,
      now: opts.now,
    });
    this.ws = new RelayWsClient({
      websocketUrl: opts.relayDescriptor.websocket_url,
      relayId: opts.relayDescriptor.relay_id,
      device: opts.device,
      provider: this.provider,
      wsFactory: opts.wsFactory,
      backoff: opts.wsBackoff,
      now: opts.now,
      onEnvelope: (envelope) => {
        this.inboundChain = this.inboundChain
          .then(() => this.handleEnvelope(envelope))
          .catch((error) => opts.onError?.(error));
      },
      onStateChange: (state) => {
        opts.onConnectionState?.(state);
        if (state === 'READY') void this.flushQueue();
      },
      onError: (error) => opts.onError?.(error),
    });
  }

  get connectionState(): RelayWsState {
    return this.ws.currentState;
  }

  get pendingOutbound(): number {
    return this.outboundQueue.length;
  }

  /** Metadata-only session status for liveness supervision and diagnostics. */
  sessionStatus(peerDeviceId: string): PeerSessionStatus | undefined {
    const session = this.sessions.get(peerDeviceId);
    if (!session) return undefined;
    return {
      sessionId: session.sessionId,
      role: session.role,
      ready: session.state?.ready ?? false,
      manifestExchanged: session.manifestSent && session.peerManifest !== undefined,
      ...(session.lastAuthenticatedAt !== undefined ? { lastAuthenticatedAt: session.lastAuthenticatedAt } : {}),
    };
  }

  start(): void {
    this.ws.start();
  }

  stop(): void {
    this.ws.stop();
  }

  /**
   * Forget the session with a peer: drops the sessions entry and rejects any
   * pending openSession waiters with a retryable session error. The relay WS
   * is untouched. Callers use this after an openSession timeout so the next
   * openSession sends a fresh hello instead of waiting on the stale session.
   */
  closeSession(peerDeviceId: string): void {
    const session = this.sessions.get(peerDeviceId);
    if (!session) return;
    this.sessions.delete(peerDeviceId);
    this.markSessionStale(peerDeviceId, session.sessionId);
    this.opts.onSessionDiagnostic?.({
      peerDeviceId,
      sessionId: session.sessionId,
      role: session.role,
      event: 'tombstone',
      cause: 'local_close',
    });
    this.dropQueuedSessionEnvelopes(session.sessionId);
    const error = iscpError(IscpErrorCodes.SessionInvalid, 'session closed locally before peer became ready', { retryable: true });
    for (const waiter of session.readyWaiters.splice(0)) waiter.reject(error);
  }

  /** Initiate a session with a peer. Resolves once capability manifests are exchanged. */
  async openSession(peerDeviceId: string, opts?: { timeoutMs?: number }): Promise<unknown> {
    const existing = this.sessions.get(peerDeviceId);
    if (existing?.peerManifest !== undefined) return existing.peerManifest;
    let session = existing;
    if (!session) {
      const peerIdentity = await this.opts.resolvePeerIdentity(peerDeviceId);
      const sessionId = `sess-${toBase64Url(this.provider.randomBytes(12))}`;
      const local = createHello(this.provider, this.opts.device, {
        sessionId,
        peerDeviceId,
        grantId: this.opts.grant.grant_id,
        now: this.now(),
      });
      session = {
        sessionId,
        role: 'initiator',
        peerDeviceId,
        peerIdentity,
        local,
        manifestSent: false,
        readyWaiters: [],
      };
      this.sessions.set(peerDeviceId, session);
      this.opts.onSessionDiagnostic?.({
        peerDeviceId,
        sessionId,
        role: 'initiator',
        event: 'create',
        cause: 'open_session',
      });
      await this.submitHandshake(peerDeviceId, sessionId, SESSION_HELLO_TYPE, local.hello);
    }
    // The awaits above suspend: our just-created session can lose a
    // competing-session tie-break (dual initiator) and be replaced by an
    // adopted responder session in the meantime. Always wait on the CURRENT
    // session for this peer — a waiter attached to the superseded object
    // would never resolve.
    const current = this.sessions.get(peerDeviceId);
    if (!current) {
      throw iscpError(IscpErrorCodes.SessionInvalid, 'session was closed while opening', { retryable: true });
    }
    return this.waitForPeerReady(current, opts?.timeoutMs ?? 60_000);
  }

  /**
   * Ask the grant-authorized peer to replace its cached Session state. This
   * control request is deliberately not queued while offline: it expires in
   * 30 seconds and a later runtime/activation must create a new request.
   */
  async requestSessionReopen(peerDeviceId: string, cause: SessionReopenCause): Promise<string> {
    if (this.ws.currentState !== 'READY') {
      throw iscpError(IscpErrorCodes.AccessInvalid, 'relay receive channel is not READY for session reopen', { retryable: true });
    }
    const issued = this.now();
    const requestId = `reopen-${toBase64Url(this.provider.randomBytes(12))}`;
    const unsigned = {
      type: SESSION_REOPEN_TYPE,
      request_id: requestId,
      domain_id: this.opts.device.identity.domain_id,
      device_id: this.opts.device.identity.device_id,
      peer_device_id: peerDeviceId,
      relay_id: this.opts.relayDescriptor.relay_id,
      cause,
      issued_at: rfc3339Seconds(issued),
      expires_at: rfc3339Seconds(new Date(issued.getTime() + SESSION_REOPEN_TTL_MS)),
      nonce: toBase64Url(this.provider.randomBytes(16)),
    };
    const request = SessionReopenSchema.parse(signObject(
      this.provider,
      SESSION_REOPEN_TYPE,
      unsigned,
      this.opts.device.privateKey,
      this.opts.device.identity.public_key.kid,
    ));
    const envelope: SecureEnvelope = {
      type: SECURE_ENVELOPE_TYPE,
      domain_id: this.opts.device.identity.domain_id,
      message_id: `ctl-${toBase64Url(this.provider.randomBytes(12))}`,
      session_id: requestId,
      sender_device_id: this.opts.device.identity.device_id,
      recipient_device_id: peerDeviceId,
      sequence: 0,
      nonce: toBase64Url(this.provider.randomBytes(12)),
      payload_type: SESSION_REOPEN_TYPE,
      route: this.route(30),
      ciphertext: toBase64Url(utf8Encode(JSON.stringify(request))),
    };
    await this.submit(envelope);
    this.opts.onSessionDiagnostic?.({ peerDeviceId, event: 'reopen_sent', cause });
    return requestId;
  }

  /** Send a business payload. Forbidden before session.ready + manifest exchange. */
  async sendPayload(peerDeviceId: string, payloadType: string, plaintext: Uint8Array): Promise<void> {
    if (HANDSHAKE_PAYLOAD_TYPES.has(payloadType)) {
      throw iscpError(IscpErrorCodes.EnvelopeInvalid, 'handshake payload types are reserved');
    }
    const session = this.sessions.get(peerDeviceId);
    if (!session?.state?.ready) {
      throw iscpError(IscpErrorCodes.SessionInvalid, 'session is not ready for payload delivery');
    }
    if (payloadType !== this.manifestPayloadType && (!session.manifestSent || session.peerManifest === undefined)) {
      throw iscpError(IscpErrorCodes.SessionInvalid, 'capability manifest has not been exchanged');
    }
    const envelope = encryptEnvelope(this.provider, session.state, {
      messageId: `msg-${toBase64Url(this.provider.randomBytes(12))}`,
      payloadType,
      route: this.route(),
      plaintext,
    });
    await this.submitOrQueue(envelope);
  }

  /** Retry queued envelopes (also runs automatically when the relay becomes READY). */
  async flushQueue(): Promise<void> {
    if (this.flushing) return;
    this.flushing = true;
    try {
      while (this.outboundQueue.length > 0) {
        const envelope = this.outboundQueue[0];
        await this.submit(envelope);
        this.outboundQueue.shift();
      }
    } catch {
      // Leave remaining envelopes queued; next READY or send retries.
    } finally {
      this.flushing = false;
    }
  }

  // -------------------------------------------------------------------------
  // Inbound
  // -------------------------------------------------------------------------

  private async handleEnvelope(envelope: SecureEnvelope): Promise<void> {
    if (envelope.recipient_device_id !== this.opts.device.identity.device_id) return;
    if (envelope.payload_type === SESSION_HELLO_TYPE) {
      await this.handleHello(envelope);
      return;
    }
    if (envelope.payload_type === SESSION_READY_TYPE) {
      await this.handleReady(envelope);
      return;
    }
    if (envelope.payload_type === SESSION_REOPEN_TYPE) {
      await this.handleSessionReopen(envelope);
      return;
    }
    // A close/rekey tombstones the previous transcript. Frames already in
    // the relay may still arrive, but they must not be decrypted against or
    // reported as failures on the replacement session.
    if (this.isSessionStale(envelope.sender_device_id, envelope.session_id)) return;
    const session = this.sessions.get(envelope.sender_device_id);
    if (!session?.state?.ready) {
      throw iscpError(IscpErrorCodes.SessionInvalid, 'business payload received before session.ready');
    }
    if (session.sessionId !== envelope.session_id) return;
    const plaintext = decryptEnvelope(this.provider, session.state, envelope);
    session.lastAuthenticatedAt = this.now().getTime();
    if (envelope.payload_type === this.manifestPayloadType) {
      session.peerManifest = JSON.parse(utf8Decode(plaintext));
      this.opts.onPeerReady?.(session.peerDeviceId, session.peerManifest);
      for (const waiter of session.readyWaiters.splice(0)) waiter.resolve(session.peerManifest);
      return;
    }
    if (session.peerManifest === undefined) {
      throw iscpError(IscpErrorCodes.SessionInvalid, 'business payload received before capability manifest');
    }
    this.opts.onPayload?.(session.peerDeviceId, envelope.payload_type, plaintext, envelope);
  }

  private async handleHello(envelope: SecureEnvelope): Promise<void> {
    const hello = SessionHelloSchema.parse(JSON.parse(utf8Decode(fromBase64Url(envelope.ciphertext))));
    const peerDeviceId = hello.device_id;
    if (this.isSessionStale(peerDeviceId, hello.session_id)) return; // late reply to a session we abandoned
    let session = this.sessions.get(peerDeviceId);
    let carriedWaiters: PeerSession['readyWaiters'] = [];
    if (session && session.sessionId !== hello.session_id) {
      // Competing session. The tie-break must pick the same winner on both
      // sides or the peers flip between session ids forever:
      // - an established session always wins;
      // - if the peer re-initiated (our session is theirs too, role
      //   'responder'), the newest hello wins — relay delivery is FIFO, so
      //   both sides see the same "newest";
      // - if both sides initiated, the session of the device with the lower
      //   device id wins.
      // The losing session id is tombstoned so its late replies are dropped.
      if (session.state?.ready) return;
      if (session.role === 'initiator' && compareCodePoints(this.opts.device.identity.device_id, peerDeviceId) < 0) {
        return;
      }
      this.sessions.delete(peerDeviceId);
      this.markSessionStale(peerDeviceId, session.sessionId);
      this.opts.onSessionDiagnostic?.({
        peerDeviceId,
        sessionId: session.sessionId,
        role: session.role,
        event: 'replace',
        cause: 'competing_hello',
      });
      carriedWaiters = session.readyWaiters.splice(0);
      session = undefined;
    }
    if (!session) {
      // Responder path: adopt the initiator's session id and answer with our hello + ready.
      const peerIdentity = await this.opts.resolvePeerIdentity(peerDeviceId);
      const local = createHello(this.provider, this.opts.device, {
        sessionId: hello.session_id,
        peerDeviceId,
        grantId: this.opts.grant.grant_id,
        now: this.now(),
      });
      const state = establish(this.provider, local, hello, this.opts.device.identity, peerIdentity, {
        replayStore: this.opts.replayStoreFor?.(hello.session_id, peerDeviceId),
      });
      session = {
        sessionId: hello.session_id,
        role: 'responder',
        peerDeviceId,
        peerIdentity,
        local,
        state,
        manifestSent: false,
        lastAuthenticatedAt: this.now().getTime(),
        readyWaiters: carriedWaiters,
      };
      this.sessions.set(peerDeviceId, session);
      this.opts.onSessionDiagnostic?.({
        peerDeviceId,
        sessionId: hello.session_id,
        role: 'responder',
        event: 'create',
        cause: 'verified_hello',
      });
      await this.submitHandshake(peerDeviceId, hello.session_id, SESSION_HELLO_TYPE, local.hello);
      await this.submitHandshake(peerDeviceId, hello.session_id, SESSION_READY_TYPE, state.createReady(this.provider, this.opts.device));
      return;
    }
    if (session.state) return; // duplicate hello
    // Initiator path: the responder answered; derive keys and confirm.
    session.state = establish(this.provider, session.local, hello, this.opts.device.identity, session.peerIdentity, {
      replayStore: this.opts.replayStoreFor?.(session.sessionId, peerDeviceId),
    });
    session.lastAuthenticatedAt = this.now().getTime();
    await this.submitHandshake(peerDeviceId, session.sessionId, SESSION_READY_TYPE, session.state.createReady(this.provider, this.opts.device));
  }

  private async handleSessionReopen(envelope: SecureEnvelope): Promise<void> {
    let request: SessionReopen | undefined;
    try {
      request = SessionReopenSchema.parse(JSON.parse(utf8Decode(fromBase64Url(envelope.ciphertext))));
      const local = this.opts.device.identity;
      const grant = this.opts.grant;
      if (envelope.domain_id !== local.domain_id || request.domain_id !== local.domain_id) {
        throw iscpError(IscpErrorCodes.TrustInvalid, 'session reopen domain mismatch');
      }
      if (envelope.sender_device_id !== request.device_id ||
        envelope.recipient_device_id !== request.peer_device_id ||
        envelope.session_id !== request.request_id ||
        request.peer_device_id !== local.device_id) {
        throw iscpError(IscpErrorCodes.TrustInvalid, 'session reopen envelope binding mismatch');
      }
      if (request.relay_id !== this.opts.relayDescriptor.relay_id ||
        envelope.route.relay_id !== request.relay_id ||
        envelope.route.ttl_seconds < 1 || envelope.route.ttl_seconds > 30) {
        throw iscpError(IscpErrorCodes.TrustInvalid, 'session reopen relay constraint mismatch');
      }
      if (grant.subject_device_id !== local.device_id ||
        grant.audience !== request.device_id ||
        identityThumbprint(this.provider, local) !== grant.confirmation_thumbprint ||
        (grant.relay_constraints !== undefined && !grant.relay_constraints.includes(request.relay_id))) {
        throw iscpError(IscpErrorCodes.TrustInvalid, 'session reopen is not authorized by the current grant');
      }
      const now = this.now().getTime();
      const grantNotBefore = parseRfc3339(grant.not_before).getTime();
      const grantExpires = parseRfc3339(grant.expires_at).getTime();
      const issued = parseRfc3339(request.issued_at).getTime();
      const expires = parseRfc3339(request.expires_at).getTime();
      if (grantNotBefore > now || grantExpires <= now) {
        throw iscpError(IscpErrorCodes.TrustInvalid, 'session reopen grant is not currently valid');
      }
      if (issued > now + 5_000 || expires <= now || expires < issued || expires - issued > SESSION_REOPEN_TTL_MS) {
        throw iscpError(IscpErrorCodes.SignatureInvalid, 'session reopen is outside its allowed time window');
      }
      const ids = this.seenReopenRequestIds.get(request.device_id) ?? [];
      if (ids.includes(request.request_id)) {
        this.opts.onSessionDiagnostic?.({
          peerDeviceId: request.device_id,
          event: 'reopen_coalesced',
          cause: 'duplicate_request',
        });
        return;
      }
      const identity = await this.opts.resolvePeerIdentity(request.device_id);
      if (identity.domain_id !== request.domain_id || identity.device_id !== request.device_id ||
        request.signature.kid !== identity.public_key.kid) {
        throw iscpError(IscpErrorCodes.TrustInvalid, 'session reopen identity mismatch');
      }
      verifyObjectSignature(
        this.provider,
        SESSION_REOPEN_TYPE,
        request,
        identity.public_key.public,
        IscpErrorCodes.SignatureInvalid,
        'session reopen signature verification failed',
      );
      ids.push(request.request_id);
      if (ids.length > 64) ids.splice(0, ids.length - 64);
      this.seenReopenRequestIds.set(request.device_id, ids);
      this.opts.onSessionDiagnostic?.({ peerDeviceId: request.device_id, event: 'reopen_accepted', cause: request.cause });
      this.opts.onSessionReopen?.(request);
    } catch (error) {
      this.opts.onSessionDiagnostic?.({
        peerDeviceId: request?.device_id ?? envelope.sender_device_id,
        event: 'reopen_rejected',
        cause: error instanceof IscpError ? error.code : 'invalid_control',
      });
      throw error;
    }
  }

  private async handleReady(envelope: SecureEnvelope): Promise<void> {
    const ready = SessionReadySchema.parse(JSON.parse(utf8Decode(fromBase64Url(envelope.ciphertext))));
    if (this.isSessionStale(envelope.sender_device_id, ready.session_id)) return; // late reply to a session we abandoned
    const session = this.sessions.get(envelope.sender_device_id);
    if (session && ready.session_id !== session.sessionId) return; // ready for a session that lost the tie-break
    if (!session?.state) {
      throw iscpError(IscpErrorCodes.SessionInvalid, 'session ready received before hello exchange');
    }
    if (session.state.ready) return; // duplicate ready
    session.state.verifyReady(this.provider, ready, session.peerIdentity);
    session.lastAuthenticatedAt = this.now().getTime();
    // First business payload after ready: our capability manifest.
    if (!session.manifestSent) {
      session.manifestSent = true;
      await this.sendPayload(session.peerDeviceId, this.manifestPayloadType, utf8Encode(JSON.stringify(this.opts.manifest)));
    }
  }

  private markSessionStale(peerDeviceId: string, sessionId: string): void {
    let stale = this.staleSessionIds.get(peerDeviceId);
    if (!stale) {
      stale = new Set();
      this.staleSessionIds.set(peerDeviceId, stale);
    }
    stale.add(sessionId);
    // Bounded: only recently-abandoned ids matter (in-flight relay replies).
    while (stale.size > 32) {
      stale.delete(stale.values().next().value as string);
    }
  }

  private isSessionStale(peerDeviceId: string, sessionId: string): boolean {
    return this.staleSessionIds.get(peerDeviceId)?.has(sessionId) ?? false;
  }

  private dropQueuedSessionEnvelopes(sessionId: string): void {
    for (let index = this.outboundQueue.length - 1; index >= 0; index -= 1) {
      if (this.outboundQueue[index]?.session_id === sessionId) {
        this.outboundQueue.splice(index, 1);
      }
    }
  }

  // -------------------------------------------------------------------------
  // Outbound plumbing
  // -------------------------------------------------------------------------

  private waitForPeerReady(session: PeerSession, timeoutMs: number): Promise<unknown> {
    if (session.peerManifest !== undefined) return Promise.resolve(session.peerManifest);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        const index = session.readyWaiters.findIndex((w) => w.resolve === wrappedResolve);
        if (index >= 0) session.readyWaiters.splice(index, 1);
        reject(iscpError(IscpErrorCodes.SessionInvalid, 'timed out waiting for peer session', { retryable: true }));
      }, timeoutMs);
      const wrappedResolve = (manifest: unknown) => {
        clearTimeout(timer);
        resolve(manifest);
      };
      const wrappedReject = (error: unknown) => {
        clearTimeout(timer);
        reject(error);
      };
      session.readyWaiters.push({ resolve: wrappedResolve, reject: wrappedReject });
    });
  }

  private route(ttlSeconds?: number): EnvelopeRoute {
    return {
      relay_id: this.opts.relayDescriptor.relay_id,
      ttl_seconds: ttlSeconds ?? this.opts.route?.ttl_seconds ?? 600,
      priority: this.opts.route?.priority ?? 5,
    };
  }

  private async submitHandshake(peerDeviceId: string, sessionId: string, payloadType: string, object: unknown): Promise<void> {
    const envelope: SecureEnvelope = {
      type: SECURE_ENVELOPE_TYPE,
      domain_id: this.opts.device.identity.domain_id,
      message_id: `hs-${toBase64Url(this.provider.randomBytes(12))}`,
      session_id: sessionId,
      sender_device_id: this.opts.device.identity.device_id,
      recipient_device_id: peerDeviceId,
      sequence: 0,
      nonce: toBase64Url(this.provider.randomBytes(12)),
      payload_type: payloadType,
      route: this.route(),
      ciphertext: toBase64Url(utf8Encode(JSON.stringify(object))),
    };
    await this.submitOrQueue(envelope);
  }

  private async submitOrQueue(envelope: SecureEnvelope): Promise<void> {
    try {
      await this.submit(envelope);
    } catch (error) {
      if (error instanceof IscpError && !error.retryable && error.code === IscpErrorCodes.AccessInvalid) {
        throw error;
      }
      this.outboundQueue.push(envelope);
      this.opts.onError?.(error);
    }
  }

  private async submit(envelope: SecureEnvelope): Promise<void> {
    try {
      await this.http.submitEnvelope(envelope, this.opts.device, this.accessToken);
    } catch (error) {
      // Rotate only on a hard credential failure. Retryable ISCPACCESS001
      // (e.g. relay rate limiting) must NOT rotate: it would burn the
      // refresh pair and add more requests against the limiter.
      if (error instanceof IscpError && error.code === IscpErrorCodes.AccessInvalid && !error.retryable) {
        await this.rotateCredentials();
        await this.http.submitEnvelope(envelope, this.opts.device, this.accessToken);
        return;
      }
      throw error;
    }
  }

  private async rotateCredentials(): Promise<void> {
    let pair: RelayCredentialPair;
    try {
      pair = await this.http.refreshAccess(this.refreshToken);
    } catch (error) {
      // Terminal refresh failure: the refresh bearer itself is expired or
      // revoked, so rotation can never succeed again. Escalate to the
      // recovery hook (device-key PoP + valid grant) when the caller wired
      // one; the hook persisted the fresh pair itself, so onCredentialsRotated
      // is not re-fired here.
      if (this.opts.recoverCredentials !== undefined &&
        error instanceof IscpError && error.code === IscpErrorCodes.AccessInvalid && !error.retryable) {
        const recovered = await this.opts.recoverCredentials({
          staleAccessToken: this.accessToken,
          staleRefreshToken: this.refreshToken,
        });
        this.accessToken = recovered.accessToken;
        this.refreshToken = recovered.refreshToken;
        return;
      }
      throw error;
    }
    this.accessToken = pair.access.token as string;
    this.refreshToken = pair.refresh.token as string;
    this.opts.onCredentialsRotated?.({
      accessToken: this.accessToken,
      refreshToken: this.refreshToken,
      access: pair.access,
      refresh: pair.refresh,
    });
  }

  private now(): Date {
    return this.opts.now?.() ?? new Date();
  }
}
