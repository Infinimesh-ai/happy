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

import { fromBase64Url, toBase64Url, utf8Decode, utf8Encode } from './encoding';
import { IscpError, IscpErrorCodes, iscpError } from './errors';
import type { Device } from './identity';
import { createNobleProvider } from './crypto/noble';
import type { CryptoProvider } from './crypto/provider';
import { RelayHttpClient, type FetchLike } from './relay/http';
import { RelayWsClient, type RelayWsBackoff, type RelayWsState } from './relay/ws';
import {
  SECURE_ENVELOPE_TYPE,
  SessionHelloSchema,
  SessionReadySchema,
  type DeviceIdentity,
  type EnvelopeRoute,
  type RelayDescriptor,
  type SecureEnvelope,
  type TrustGrant,
} from './schemas';
import { SESSION_HELLO_TYPE, SESSION_READY_TYPE } from './schemas';
import { createHello, establish, type LocalHello, type SessionState } from './session/handshake';
import { decryptEnvelope, encryptEnvelope } from './session/secureEnvelope';
import type { ReplayStore } from './session/replay';
import type { WebSocketFactory } from './ws-adapter';

export const CAPABILITY_MANIFEST_PAYLOAD_TYPE = 'agent.capability.v1';

const HANDSHAKE_PAYLOAD_TYPES = new Set<string>([SESSION_HELLO_TYPE, SESSION_READY_TYPE]);

interface PeerSession {
  sessionId: string;
  role: 'initiator' | 'responder';
  peerDeviceId: string;
  peerIdentity: DeviceIdentity;
  local: LocalHello;
  state?: SessionState;
  manifestSent: boolean;
  peerManifest?: unknown;
  readyWaiters: Array<{ resolve: (manifest: unknown) => void; reject: (error: unknown) => void }>;
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
  /** Called whenever access/refresh credentials rotate, so callers can persist them. */
  onCredentialsRotated?: (credentials: { accessToken: string; refreshToken: string }) => void;
  onPayload?: (peerDeviceId: string, payloadType: string, plaintext: Uint8Array, envelope: SecureEnvelope) => void;
  /** Fires once per session when capability manifests have been exchanged. */
  onPeerReady?: (peerDeviceId: string, manifest: unknown) => void;
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
      await this.submitHandshake(peerDeviceId, sessionId, SESSION_HELLO_TYPE, local.hello);
    }
    return this.waitForPeerReady(session, opts?.timeoutMs ?? 60_000);
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
    const session = this.sessions.get(envelope.sender_device_id);
    if (!session?.state?.ready) {
      throw iscpError(IscpErrorCodes.SessionInvalid, 'business payload received before session.ready');
    }
    const plaintext = decryptEnvelope(this.provider, session.state, envelope);
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
    let session = this.sessions.get(peerDeviceId);
    if (session && session.sessionId !== hello.session_id) {
      // A stale or competing session: latest initiator wins only if we have
      // no established state yet.
      if (session.state?.ready) return;
      this.sessions.delete(peerDeviceId);
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
        readyWaiters: [],
      };
      this.sessions.set(peerDeviceId, session);
      await this.submitHandshake(peerDeviceId, hello.session_id, SESSION_HELLO_TYPE, local.hello);
      await this.submitHandshake(peerDeviceId, hello.session_id, SESSION_READY_TYPE, state.createReady(this.provider, this.opts.device));
      return;
    }
    if (session.state) return; // duplicate hello
    // Initiator path: the responder answered; derive keys and confirm.
    session.state = establish(this.provider, session.local, hello, this.opts.device.identity, session.peerIdentity, {
      replayStore: this.opts.replayStoreFor?.(session.sessionId, peerDeviceId),
    });
    await this.submitHandshake(peerDeviceId, session.sessionId, SESSION_READY_TYPE, session.state.createReady(this.provider, this.opts.device));
  }

  private async handleReady(envelope: SecureEnvelope): Promise<void> {
    const ready = SessionReadySchema.parse(JSON.parse(utf8Decode(fromBase64Url(envelope.ciphertext))));
    const session = this.sessions.get(envelope.sender_device_id);
    if (!session?.state) {
      throw iscpError(IscpErrorCodes.SessionInvalid, 'session ready received before hello exchange');
    }
    if (session.state.ready) return; // duplicate ready
    session.state.verifyReady(this.provider, ready, session.peerIdentity);
    // First business payload after ready: our capability manifest.
    if (!session.manifestSent) {
      session.manifestSent = true;
      await this.sendPayload(session.peerDeviceId, this.manifestPayloadType, utf8Encode(JSON.stringify(this.opts.manifest)));
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

  private route(): EnvelopeRoute {
    return {
      relay_id: this.opts.relayDescriptor.relay_id,
      ttl_seconds: this.opts.route?.ttl_seconds ?? 600,
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
    const pair = await this.http.refreshAccess(this.refreshToken);
    this.accessToken = pair.access.token as string;
    this.refreshToken = pair.refresh.token as string;
    this.opts.onCredentialsRotated?.({ accessToken: this.accessToken, refreshToken: this.refreshToken });
  }

  private now(): Date {
    return this.opts.now?.() ?? new Date();
  }
}
