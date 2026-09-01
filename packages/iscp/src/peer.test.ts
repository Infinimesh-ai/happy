import { describe, expect, it } from 'vitest';

import { createNobleProvider } from './crypto/noble';
import { utf8Decode, utf8Encode } from './encoding';
import { IscpError } from './errors';
import { createDevice, identityThumbprint, type Device } from './identity';
import { IscpPeer } from './peer';
import { signObject } from './signing';
import { SESSION_HELLO_TYPE, SESSION_READY_TYPE, TRUST_GRANT_TYPE, type DeviceIdentity, type RelayDescriptor, type TrustGrant } from './schemas';
import { FakeRelay } from './testing/fakeRelay';

const provider = createNobleProvider();

function makeGrant(issuer: Device, subject: Device, relayId: string, audience = 'happy-domain'): TrustGrant {
  const unsigned = {
    type: TRUST_GRANT_TYPE,
    grant_id: `grant-${subject.identity.device_id}`,
    issuer: issuer.identity.device_id,
    subject_device_id: subject.identity.device_id,
    audience,
    confirmation_thumbprint: identityThumbprint(provider, subject.identity),
    permissions: ['text', 'agent.capability.v1', 'happy-wire.v1'],
    relay_constraints: [relayId],
    not_before: '2026-01-01T00:00:00Z',
    expires_at: '2036-01-01T00:00:00Z',
    revocation_epoch: 0,
  };
  return signObject(provider, TRUST_GRANT_TYPE, unsigned, issuer.privateKey, issuer.identity.public_key.kid) as TrustGrant;
}

function relayDescriptor(relay: FakeRelay): RelayDescriptor {
  return {
    type: 'iscp.relay.descriptor.v2',
    relay_id: relay.relayId,
    domain_id: relay.domainId,
    base_url: 'http://fake-relay.local',
    websocket_url: 'ws://fake-relay.local/v2/relay/connect',
    signing_keys: [{ kty: 'Ed25519', use: 'descriptor-signature', kid: 'k', public: 'AA' }],
    issued_at: '2026-01-01T00:00:00Z',
    expires_at: '2036-01-01T00:00:00Z',
  };
}

interface TestPeer {
  device: Device;
  peer: IscpPeer;
  received: Array<{ from: string; payloadType: string; text: string }>;
  errors: unknown[];
  manifests: Array<{ from: string; manifest: unknown }>;
  sessionDiagnostics: Array<{ event: string; cause?: string; attempt?: number; pendingCount?: number }>;
}

function createTestPeer(
  relay: FakeRelay,
  deviceId: string,
  identities: Map<string, DeviceIdentity>,
  issuer: Device,
  opts?: {
    device?: Device;
    grantAudience?: string;
    onSessionReopen?: (cause: string) => void;
    now?: () => Date;
    handshakeTTLSeconds?: number;
  },
): TestPeer {
  const device = opts?.device ?? createDevice(provider, { domainId: relay.domainId, deviceId });
  identities.set(deviceId, device.identity);
  const credentials = relay.issueCredentials(deviceId);
  const result: TestPeer = {
    device,
    peer: undefined as unknown as IscpPeer,
    received: [],
    errors: [],
    manifests: [],
    sessionDiagnostics: [],
  };
  result.peer = new IscpPeer({
    device,
    grant: makeGrant(issuer, device, relay.relayId, opts?.grantAudience),
    relayDescriptor: relayDescriptor(relay),
    credentials,
    resolvePeerIdentity: async (id) => {
      const identity = identities.get(id);
      if (!identity) throw new Error(`unknown device ${id}`);
      return identity;
    },
    manifest: { product_kind: 'happy', device: deviceId, capabilities: ['agent.sessions'] },
    provider,
    wsFactory: relay.wsFactory,
    fetchImpl: relay.fetchImpl,
    onPayload: (from, payloadType, plaintext) => {
      result.received.push({ from, payloadType, text: utf8Decode(plaintext) });
    },
    onPeerReady: (from, manifest) => {
      result.manifests.push({ from, manifest });
    },
    onSessionReopen: (request) => opts?.onSessionReopen?.(request.cause),
    onSessionDiagnostic: (event) => result.sessionDiagnostics.push({
      event: event.event,
      ...(event.cause !== undefined ? { cause: event.cause } : {}),
      ...(event.attempt !== undefined ? { attempt: event.attempt } : {}),
      ...(event.pendingCount !== undefined ? { pendingCount: event.pendingCount } : {}),
    }),
    onError: (error) => {
      result.errors.push(error);
    },
    ...(opts?.handshakeTTLSeconds !== undefined
      ? { handshakeTTLSeconds: opts.handshakeTTLSeconds }
      : {}),
    ...(opts?.now !== undefined ? { now: opts.now } : {}),
  });
  return result;
}

async function waitFor(predicate: () => boolean, timeoutMs = 5000, what = 'condition'): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

describe('IscpPeer over an in-memory relay', () => {
  it('replaces a daemon-preserved Session after an authenticated phone process restart', async () => {
    const relay = new FakeRelay();
    const identities = new Map<string, DeviceIdentity>();
    const issuer = createDevice(provider, { domainId: relay.domainId, deviceId: 'trust-local-signer' });
    let happy: TestPeer;
    let reopenCount = 0;
    let reopened: Promise<unknown> | undefined;
    const phone = createTestPeer(relay, 'device-phone', identities, issuer);
    happy = createTestPeer(relay, 'device-happy', identities, issuer, {
      grantAudience: phone.device.identity.device_id,
      onSessionReopen: () => {
        reopenCount += 1;
        happy.peer.closeSession(phone.device.identity.device_id);
        reopened = happy.peer.openSession(phone.device.identity.device_id, { timeoutMs: 5000 });
      },
    });
    phone.peer.start();
    happy.peer.start();
    let replacement: TestPeer | undefined;
    try {
      await waitFor(() => phone.peer.connectionState === 'READY' && happy.peer.connectionState === 'READY', 5000, 'initial transports');
      await happy.peer.openSession(phone.device.identity.device_id, { timeoutMs: 5000 });
      const oldSessionId = happy.peer.sessionStatus(phone.device.identity.device_id)?.sessionId;
      expect(oldSessionId).toBeTruthy();

      // Process replacement keeps the durable phone identity/key but drops
      // every in-memory Session. The Happy peer/runtime remains untouched.
      phone.peer.stop();
      replacement = createTestPeer(relay, phone.device.identity.device_id, identities, issuer, {
        device: phone.device,
      });
      replacement.peer.start();
      await waitFor(() => replacement?.peer.connectionState === 'READY', 5000, 'replacement phone transport');
      await replacement.peer.requestSessionReopen(happy.device.identity.device_id, 'runtime_started');
      await waitFor(() => reopened !== undefined, 5000, 'Happy accepts reopen');
      await reopened;
      await waitFor(
        () => replacement?.peer.sessionStatus(happy.device.identity.device_id)?.manifestExchanged === true,
        5000,
        'replacement phone manifest exchange',
      );

      const happySession = happy.peer.sessionStatus(phone.device.identity.device_id);
      const phoneSession = replacement.peer.sessionStatus(happy.device.identity.device_id);
      expect(reopenCount).toBe(1);
      expect(happySession?.sessionId).toBe(phoneSession?.sessionId);
      expect(happySession?.sessionId).not.toBe(oldSessionId);
      expect(happySession?.ready).toBe(true);
      expect(phoneSession?.manifestExchanged).toBe(true);
      expect(happy.sessionDiagnostics.some((event) => event.event === 'reopen_accepted')).toBe(true);
      expect(happy.sessionDiagnostics.some((event) => event.event === 'tombstone')).toBe(true);
    } finally {
      phone.peer.stop();
      replacement?.peer.stop();
      happy.peer.stop();
    }
  });

  it('rejects a signed reopen when the sender is not the current Grant audience', async () => {
    const relay = new FakeRelay();
    const identities = new Map<string, DeviceIdentity>();
    const issuer = createDevice(provider, { domainId: relay.domainId, deviceId: 'trust-local-signer' });
    const authorizedPhone = createTestPeer(relay, 'device-phone', identities, issuer);
    const rogue = createTestPeer(relay, 'device-rogue', identities, issuer);
    let accepted = 0;
    const happy = createTestPeer(relay, 'device-happy', identities, issuer, {
      grantAudience: authorizedPhone.device.identity.device_id,
      onSessionReopen: () => { accepted += 1; },
    });
    rogue.peer.start();
    happy.peer.start();
    try {
      await waitFor(() => rogue.peer.connectionState === 'READY' && happy.peer.connectionState === 'READY', 5000, 'rogue transports');
      await rogue.peer.requestSessionReopen(happy.device.identity.device_id, 'runtime_started');
      await waitFor(() => happy.errors.length > 0, 5000, 'reopen rejection');
      expect(accepted).toBe(0);
      expect(happy.sessionDiagnostics.at(-1)).toMatchObject({ event: 'reopen_rejected' });
    } finally {
      authorizedPhone.peer.stop();
      rogue.peer.stop();
      happy.peer.stop();
    }
  });

  it('never queues an expiring reopen control while the Relay is offline', async () => {
    const relay = new FakeRelay();
    const identities = new Map<string, DeviceIdentity>();
    const issuer = createDevice(provider, { domainId: relay.domainId, deviceId: 'trust-local-signer' });
    const phone = createTestPeer(relay, 'device-phone', identities, issuer);
    phone.peer.start();
    try {
      await waitFor(() => phone.peer.connectionState === 'READY', 5000, 'phone transport');
      relay.offline = true;
      await expect(phone.peer.requestSessionReopen('device-happy', 'foreground_recovery')).rejects.toThrowError();
      expect(phone.peer.pendingOutbound).toBe(0);
    } finally {
      relay.offline = false;
      phone.peer.stop();
    }
  });

  it('deduplicates a replayed authenticated reopen request', async () => {
    const relay = new FakeRelay();
    const identities = new Map<string, DeviceIdentity>();
    const issuer = createDevice(provider, { domainId: relay.domainId, deviceId: 'trust-local-signer' });
    const phone = createTestPeer(relay, 'device-phone', identities, issuer);
    let accepted = 0;
    const happy = createTestPeer(relay, 'device-happy', identities, issuer, {
      grantAudience: phone.device.identity.device_id,
      onSessionReopen: () => { accepted += 1; },
    });
    phone.peer.start();
    happy.peer.start();
    try {
      await waitFor(() => phone.peer.connectionState === 'READY' && happy.peer.connectionState === 'READY', 5000, 'replay transports');
      await phone.peer.requestSessionReopen(happy.device.identity.device_id, 'runtime_started');
      await waitFor(() => accepted === 1, 5000, 'first reopen');
      const envelope = relay.submitted.find((item) => item.payload_type === 'iscp.session.reopen.v1');
      expect(envelope).toBeDefined();
      relay.redeliver(envelope!);
      await waitFor(
        () => happy.sessionDiagnostics.some((event) => event.event === 'reopen_coalesced'),
        5000,
        'duplicate reopen diagnostic',
      );
      expect(accepted).toBe(1);
    } finally {
      phone.peer.stop();
      happy.peer.stop();
    }
  });

  it('rejects an expired otherwise-valid reopen request', async () => {
    const relay = new FakeRelay();
    const identities = new Map<string, DeviceIdentity>();
    const issuer = createDevice(provider, { domainId: relay.domainId, deviceId: 'trust-local-signer' });
    const phone = createTestPeer(relay, 'device-phone', identities, issuer, {
      now: () => new Date('2026-01-01T00:00:00Z'),
    });
    let accepted = 0;
    const happy = createTestPeer(relay, 'device-happy', identities, issuer, {
      grantAudience: phone.device.identity.device_id,
      onSessionReopen: () => { accepted += 1; },
    });
    phone.peer.start();
    happy.peer.start();
    try {
      await waitFor(() => phone.peer.connectionState === 'READY' && happy.peer.connectionState === 'READY', 5000, 'expiry transports');
      await phone.peer.requestSessionReopen(happy.device.identity.device_id, 'runtime_started');
      await waitFor(() => happy.errors.length > 0, 5000, 'expired reopen rejection');
      expect(accepted).toBe(0);
      expect(happy.sessionDiagnostics.at(-1)).toMatchObject({ event: 'reopen_rejected' });
    } finally {
      phone.peer.stop();
      happy.peer.stop();
    }
  });

  it('handshakes, exchanges manifests, and delivers payloads both ways', async () => {
    const relay = new FakeRelay();
    const identities = new Map<string, DeviceIdentity>();
    const issuer = createDevice(provider, { domainId: relay.domainId, deviceId: 'trust-local-signer' });
    const alpha = createTestPeer(relay, 'device-alpha', identities, issuer);
    const beta = createTestPeer(relay, 'device-beta', identities, issuer);
    alpha.peer.start();
    beta.peer.start();
    try {
      await waitFor(() => alpha.peer.connectionState === 'READY' && beta.peer.connectionState === 'READY', 5000, 'both peers READY');

      const betaManifest = await alpha.peer.openSession('device-beta', { timeoutMs: 5000 });
      expect(betaManifest).toMatchObject({ device: 'device-beta' });
      await waitFor(() => beta.manifests.length > 0, 5000, 'beta receives alpha manifest');
      expect(beta.manifests[0].manifest).toMatchObject({ device: 'device-alpha' });

      await alpha.peer.sendPayload('device-beta', 'text', utf8Encode('{"text":"hi beta"}'));
      await waitFor(() => beta.received.length > 0, 5000, 'beta payload delivery');
      expect(beta.received[0]).toMatchObject({ from: 'device-alpha', payloadType: 'text', text: '{"text":"hi beta"}' });

      await beta.peer.sendPayload('device-alpha', 'text', utf8Encode('{"text":"hi alpha"}'));
      await waitFor(() => alpha.received.length > 0, 5000, 'alpha payload delivery');
      expect(alpha.received[0].text).toBe('{"text":"hi alpha"}');
    } finally {
      alpha.peer.stop();
      beta.peer.stop();
    }
  });

  it('refuses business payloads before session.ready and before manifest exchange', async () => {
    const relay = new FakeRelay();
    const identities = new Map<string, DeviceIdentity>();
    const issuer = createDevice(provider, { domainId: relay.domainId, deviceId: 'trust-local-signer' });
    const alpha = createTestPeer(relay, 'device-alpha', identities, issuer);
    createTestPeer(relay, 'device-beta', identities, issuer); // identity registered, peer never started
    alpha.peer.start();
    try {
      await expect(alpha.peer.sendPayload('device-beta', 'text', utf8Encode('x'))).rejects.toThrowError(/not ready/);
    } finally {
      alpha.peer.stop();
    }
  });

  it('survives a killed WS: reconnects and drains envelopes queued while offline', async () => {
    const relay = new FakeRelay();
    const identities = new Map<string, DeviceIdentity>();
    const issuer = createDevice(provider, { domainId: relay.domainId, deviceId: 'trust-local-signer' });
    const alpha = createTestPeer(relay, 'device-alpha', identities, issuer);
    const beta = createTestPeer(relay, 'device-beta', identities, issuer);
    alpha.peer.start();
    beta.peer.start();
    try {
      await alpha.peer.openSession('device-beta', { timeoutMs: 5000 });
      await waitFor(() => beta.manifests.length > 0, 5000, 'manifest exchange');

      // Kill every WS; envelopes submitted meanwhile land in the offline queue.
      relay.killSockets();
      await alpha.peer.sendPayload('device-beta', 'text', utf8Encode('{"text":"while offline"}'));
      await waitFor(() => beta.received.some((m) => m.text.includes('while offline')), 5000, 'delivery after reconnect');
    } finally {
      alpha.peer.stop();
      beta.peer.stop();
    }
  });

  it('queues outbound envelopes while the relay is unreachable and flushes on recovery', async () => {
    const relay = new FakeRelay();
    const identities = new Map<string, DeviceIdentity>();
    const issuer = createDevice(provider, { domainId: relay.domainId, deviceId: 'trust-local-signer' });
    const alpha = createTestPeer(relay, 'device-alpha', identities, issuer);
    const beta = createTestPeer(relay, 'device-beta', identities, issuer);
    alpha.peer.start();
    beta.peer.start();
    try {
      await alpha.peer.openSession('device-beta', { timeoutMs: 5000 });
      relay.offline = true;
      await alpha.peer.sendPayload('device-beta', 'text', utf8Encode('{"text":"queued"}'));
      expect(alpha.peer.pendingOutbound).toBe(1);
      relay.offline = false;
      await alpha.peer.flushQueue();
      expect(alpha.peer.pendingOutbound).toBe(0);
      await waitFor(() => beta.received.some((m) => m.text.includes('queued')), 5000, 'queued delivery');
    } finally {
      alpha.peer.stop();
      beta.peer.stop();
    }
  });

  it('rejects replayed envelopes with ISCPENV002', async () => {
    const relay = new FakeRelay();
    const identities = new Map<string, DeviceIdentity>();
    const issuer = createDevice(provider, { domainId: relay.domainId, deviceId: 'trust-local-signer' });
    const alpha = createTestPeer(relay, 'device-alpha', identities, issuer);
    const beta = createTestPeer(relay, 'device-beta', identities, issuer);
    alpha.peer.start();
    beta.peer.start();
    try {
      await alpha.peer.openSession('device-beta', { timeoutMs: 5000 });
      await alpha.peer.sendPayload('device-beta', 'text', utf8Encode('{"text":"once"}'));
      await waitFor(() => beta.received.length === 1, 5000, 'first delivery');
      const delivered = relay.submitted.find((e) => e.payload_type === 'text');
      expect(delivered).toBeDefined();
      relay.redeliver(delivered!);
      await waitFor(() => beta.errors.some((e) => e instanceof IscpError && e.code === 'ISCPENV002'), 5000, 'replay rejection');
      expect(beta.received.length).toBe(1);
    } finally {
      alpha.peer.stop();
      beta.peer.stop();
    }
  });

  it('closeSession rejects pending openSession waiters (retryable) and drops the session entry', async () => {
    const relay = new FakeRelay();
    const identities = new Map<string, DeviceIdentity>();
    const issuer = createDevice(provider, { domainId: relay.domainId, deviceId: 'trust-local-signer' });
    let identityResolutions = 0;
    const alpha = createTestPeer(relay, 'device-alpha', identities, issuer);
    const beta = createTestPeer(relay, 'device-beta', identities, issuer);
    void beta; // identity registered; the peer never comes online
    const countingPeer = new IscpPeer({
      device: alpha.device,
      grant: makeGrant(issuer, alpha.device, relay.relayId),
      relayDescriptor: relayDescriptor(relay),
      credentials: relay.issueCredentials('device-alpha'),
      resolvePeerIdentity: async (id) => {
        identityResolutions += 1;
        return identities.get(id)!;
      },
      manifest: { device: 'device-alpha' },
      provider,
      wsFactory: relay.wsFactory,
      fetchImpl: relay.fetchImpl,
    });
    countingPeer.start();
    try {
      await waitFor(() => countingPeer.connectionState === 'READY', 5000, 'alpha READY');
      const pending = countingPeer.openSession('device-beta', { timeoutMs: 60_000 });
      pending.catch(() => { }); // observed below
      // Wait until the hello envelope actually reached the relay (the session
      // entry and its ready-waiter are registered right after submission).
      await waitFor(() => relay.submitted.some((e) => e.payload_type === SESSION_HELLO_TYPE), 5000, 'first hello sent');
      await new Promise((resolve) => setTimeout(resolve, 20));
      expect(identityResolutions).toBe(1);

      countingPeer.closeSession('device-beta');
      const error = await pending.catch((e: unknown) => e);
      expect(error).toBeInstanceOf(IscpError);
      expect((error as IscpError).code).toBe('ISCPSESSION001');
      expect((error as IscpError).retryable).toBe(true);

      // The session entry is gone: a fresh openSession re-resolves the peer
      // identity and sends a NEW hello. Without closeSession it would keep
      // waiting on the stale session (the SDK never re-sends Hello).
      const second = countingPeer.openSession('device-beta', { timeoutMs: 250 });
      const secondError = await second.catch((e: unknown) => e);
      expect(identityResolutions).toBe(2);
      expect(secondError).toBeInstanceOf(IscpError);
      expect((secondError as IscpError).retryable).toBe(true); // timed out again — peer still offline
    } finally {
      countingPeer.stop();
    }
  });

  it('closeSession on an unknown peer is a no-op', () => {
    const relay = new FakeRelay();
    const identities = new Map<string, DeviceIdentity>();
    const issuer = createDevice(provider, { domainId: relay.domainId, deviceId: 'trust-local-signer' });
    const alpha = createTestPeer(relay, 'device-alpha', identities, issuer);
    expect(() => alpha.peer.closeSession('device-never-seen')).not.toThrow();
  });

  it('bounds offline initial Hellos with short TTL and exposes lifecycle metrics', async () => {
    const relay = new FakeRelay();
    const identities = new Map<string, DeviceIdentity>();
    const issuer = createDevice(provider, { domainId: relay.domainId, deviceId: 'trust-local-signer' });
    const alpha = createTestPeer(relay, 'device-alpha', identities, issuer, { handshakeTTLSeconds: 35 });
    createTestPeer(relay, 'device-beta', identities, issuer); // identity only; phone remains offline
    alpha.peer.start();
    try {
      await waitFor(() => alpha.peer.connectionState === 'READY', 5000, 'alpha READY');
      const first = alpha.peer.openSession('device-beta', { timeoutMs: 60_000 });
      first.catch(() => { });
      await waitFor(
        () => relay.submitted.filter((e) => e.payload_type === SESSION_HELLO_TYPE).length === 1,
        5000,
        'first short-lived hello',
      );

      const coalesced = alpha.peer.openSession('device-beta', { timeoutMs: 60_000 });
      coalesced.catch(() => { });
      await waitFor(
        () => alpha.sessionDiagnostics.some((event) => event.event === 'hello_coalesced'),
        5000,
        'coalesced metric',
      );
      alpha.peer.closeSession('device-beta');
      await expect(first).rejects.toMatchObject({ retryable: true });
      await expect(coalesced).rejects.toMatchObject({ retryable: true });

      const second = alpha.peer.openSession('device-beta', { timeoutMs: 60_000 });
      second.catch(() => { });
      await waitFor(
        () => relay.submitted.filter((e) => e.payload_type === SESSION_HELLO_TYPE).length === 2,
        5000,
        'replacement short-lived hello',
      );
      const hellos = relay.submitted.filter((e) => e.payload_type === SESSION_HELLO_TYPE);
      expect(hellos.every((hello) => hello.route.ttl_seconds === 35)).toBe(true);
      expect(alpha.sessionDiagnostics.some((event) => event.event === 'hello_attempt')).toBe(true);
      expect(alpha.sessionDiagnostics.some((event) => event.event === 'hello_superseded')).toBe(true);
      expect(alpha.sessionDiagnostics
        .filter((event) => event.event === 'hello_attempt')
        .at(-1)).toMatchObject({ attempt: 2, pendingCount: 2 });
      expect(alpha.peer.pendingHelloCount('device-beta')).toBeLessThanOrEqual(2);
      alpha.peer.closeSession('device-beta');
      await expect(second).rejects.toMatchObject({ retryable: true });
    } finally {
      alpha.peer.stop();
    }
  });

  it('converges on one session when a peer drains competing hellos from before and after closeSession', async () => {
    const relay = new FakeRelay();
    const identities = new Map<string, DeviceIdentity>();
    const issuer = createDevice(provider, { domainId: relay.domainId, deviceId: 'trust-local-signer' });
    const alpha = createTestPeer(relay, 'device-alpha', identities, issuer);
    const beta = createTestPeer(relay, 'device-beta', identities, issuer);
    alpha.peer.start();
    try {
      await waitFor(() => alpha.peer.connectionState === 'READY', 5000, 'alpha READY');

      // Hello #1 queues at the relay while beta is offline; alpha gives up on it.
      const first = alpha.peer.openSession('device-beta', { timeoutMs: 60_000 });
      first.catch(() => { });
      await waitFor(() => relay.submitted.filter((e) => e.payload_type === SESSION_HELLO_TYPE).length === 1, 5000, 'first hello queued');
      alpha.peer.closeSession('device-beta');
      await expect(first).rejects.toMatchObject({ retryable: true });

      // Hello #2 (fresh session id) queues behind the abandoned hello #1.
      const second = alpha.peer.openSession('device-beta', { timeoutMs: 5000 });
      await waitFor(() => relay.submitted.filter((e) => e.payload_type === SESSION_HELLO_TYPE).length === 2, 5000, 'second hello queued');

      // Beta comes online and drains BOTH hellos. Without a deterministic
      // tie-break both peers keep deleting and re-adopting the two session
      // ids at microtask speed — an unbounded hello/ready storm.
      beta.peer.start();
      expect(await second).toMatchObject({ device: 'device-beta' });
      await waitFor(() => beta.manifests.length > 0, 5000, 'beta receives alpha manifest');

      // The surviving session carries payloads.
      await alpha.peer.sendPayload('device-beta', 'text', utf8Encode('{"text":"after competing hellos"}'));
      await waitFor(() => beta.received.length > 0, 5000, 'payload after convergence');

      // Bounded handshake traffic: alpha sends hello S1, hello S2, ready S2;
      // beta answers each drained hello with at most hello+ready. Anything
      // beyond that means the competing-session livelock is back.
      expect(relay.submitted.filter((e) => e.payload_type === SESSION_HELLO_TYPE).length).toBeLessThanOrEqual(4);
      expect(relay.submitted.filter((e) => e.payload_type === SESSION_READY_TYPE).length).toBeLessThanOrEqual(3);
      expect(alpha.errors).toEqual([]);
      expect(beta.errors).toEqual([]);
    } finally {
      alpha.peer.stop();
      beta.peer.stop();
    }
  });

  it('resolves a dual-initiator race deterministically (lower device id wins)', async () => {
    const relay = new FakeRelay();
    const identities = new Map<string, DeviceIdentity>();
    const issuer = createDevice(provider, { domainId: relay.domainId, deviceId: 'trust-local-signer' });
    const alpha = createTestPeer(relay, 'device-alpha', identities, issuer);
    const beta = createTestPeer(relay, 'device-beta', identities, issuer);
    alpha.peer.start();
    beta.peer.start();
    try {
      await waitFor(() => alpha.peer.connectionState === 'READY' && beta.peer.connectionState === 'READY', 5000, 'both READY');

      // Both sides dial each other before either hello lands: two initiator
      // sessions with different ids for the same pair. The tie-break must
      // keep exactly one (the lower device id's session) on BOTH sides.
      const fromAlpha = alpha.peer.openSession('device-beta', { timeoutMs: 5000 });
      const fromBeta = beta.peer.openSession('device-alpha', { timeoutMs: 5000 });
      expect(await fromAlpha).toMatchObject({ device: 'device-beta' });
      expect(await fromBeta).toMatchObject({ device: 'device-alpha' });

      // Payloads flow both ways over the surviving session.
      await alpha.peer.sendPayload('device-beta', 'text', utf8Encode('{"text":"alpha->beta"}'));
      await beta.peer.sendPayload('device-alpha', 'text', utf8Encode('{"text":"beta->alpha"}'));
      await waitFor(() => beta.received.length > 0 && alpha.received.length > 0, 5000, 'payloads both ways');

      // Two initial hellos + at most one responder hello for the winning
      // session; more means both sessions stayed alive or the storm is back.
      expect(relay.submitted.filter((e) => e.payload_type === SESSION_HELLO_TYPE).length).toBeLessThanOrEqual(3);
      expect(relay.submitted.filter((e) => e.payload_type === SESSION_READY_TYPE).length).toBeLessThanOrEqual(2);
      expect(alpha.errors).toEqual([]);
      expect(beta.errors).toEqual([]);
    } finally {
      alpha.peer.stop();
      beta.peer.stop();
    }
  });

  it('rotates credentials when the relay rejects the access token', async () => {
    const relay = new FakeRelay();
    const identities = new Map<string, DeviceIdentity>();
    const issuer = createDevice(provider, { domainId: relay.domainId, deviceId: 'trust-local-signer' });
    const alpha = createTestPeer(relay, 'device-alpha', identities, issuer);
    const beta = createTestPeer(relay, 'device-beta', identities, issuer);
    // Invalidate alpha's access token by issuing (and discarding) — instead,
    // construct a peer with a bogus access token but valid refresh token.
    const credentials = relay.issueCredentials('device-alpha');
    const rotated: string[] = [];
    const peer = new IscpPeer({
      device: alpha.device,
      grant: makeGrant(issuer, alpha.device, relay.relayId),
      relayDescriptor: relayDescriptor(relay),
      credentials: { accessToken: 'bogus-token', refreshToken: credentials.refreshToken },
      resolvePeerIdentity: async (id) => identities.get(id)!,
      manifest: { device: 'device-alpha' },
      provider,
      wsFactory: relay.wsFactory,
      fetchImpl: relay.fetchImpl,
      onCredentialsRotated: (c) => rotated.push(c.accessToken),
    });
    beta.peer.start();
    peer.start();
    try {
      await peer.openSession('device-beta', { timeoutMs: 5000 });
      expect(rotated.length).toBeGreaterThan(0);
    } finally {
      peer.stop();
      beta.peer.stop();
    }
  });

  it('passes the full wire credentials (expiry metadata) to onCredentialsRotated', async () => {
    // OPS 2026-08-18 §8.2.4: persisting only token strings leaves local
    // expiry metadata stale; the callback must carry the server facts.
    const relay = new FakeRelay();
    const identities = new Map<string, DeviceIdentity>();
    const issuer = createDevice(provider, { domainId: relay.domainId, deviceId: 'trust-local-signer' });
    const alpha = createTestPeer(relay, 'device-alpha', identities, issuer);
    const beta = createTestPeer(relay, 'device-beta', identities, issuer);
    const credentials = relay.issueCredentials('device-alpha');
    const rotated: Array<{ access?: { expires_at: string }; refresh?: { expires_at: string } }> = [];
    const peer = new IscpPeer({
      device: alpha.device,
      grant: makeGrant(issuer, alpha.device, relay.relayId),
      relayDescriptor: relayDescriptor(relay),
      credentials: { accessToken: 'bogus-token', refreshToken: credentials.refreshToken },
      resolvePeerIdentity: async (id) => identities.get(id)!,
      manifest: { device: 'device-alpha' },
      provider,
      wsFactory: relay.wsFactory,
      fetchImpl: relay.fetchImpl,
      onCredentialsRotated: (c) => rotated.push(c),
    });
    beta.peer.start();
    peer.start();
    try {
      await peer.openSession('device-beta', { timeoutMs: 5000 });
      expect(rotated.length).toBeGreaterThan(0);
      expect(rotated[0]!.access?.expires_at).toBeTruthy();
      expect(rotated[0]!.refresh?.expires_at).toBeTruthy();
    } finally {
      peer.stop();
      beta.peer.stop();
    }
  });

  it('escalates a terminal refresh failure to the recovery hook instead of failing the send', async () => {
    // The refresh bearer is dead (expired past its TTL / revoked chain): the
    // rotation path can never succeed again. With a recovery hook wired
    // (device-key PoP + valid grant, InfinimeshCloud §11), the peer resumes
    // with the recovered pair; the hook owns persistence, so the rotation
    // callback does not re-fire.
    const relay = new FakeRelay();
    const identities = new Map<string, DeviceIdentity>();
    const issuer = createDevice(provider, { domainId: relay.domainId, deviceId: 'trust-local-signer' });
    const alpha = createTestPeer(relay, 'device-alpha', identities, issuer);
    const beta = createTestPeer(relay, 'device-beta', identities, issuer);
    const recovered = relay.issueCredentials('device-alpha');
    let recoveries = 0;
    const rotated: string[] = [];
    const peer = new IscpPeer({
      device: alpha.device,
      grant: makeGrant(issuer, alpha.device, relay.relayId),
      relayDescriptor: relayDescriptor(relay),
      credentials: { accessToken: 'bogus-token', refreshToken: 'bogus-refresh' },
      resolvePeerIdentity: async (id) => identities.get(id)!,
      manifest: { device: 'device-alpha' },
      provider,
      wsFactory: relay.wsFactory,
      fetchImpl: relay.fetchImpl,
      onCredentialsRotated: (c) => rotated.push(c.accessToken),
      recoverCredentials: async () => {
        recoveries += 1;
        return recovered;
      },
    });
    beta.peer.start();
    peer.start();
    try {
      await peer.openSession('device-beta', { timeoutMs: 5000 });
      expect(recoveries).toBe(1);
      expect(rotated).toEqual([]);
    } finally {
      peer.stop();
      beta.peer.stop();
    }
  });
});
