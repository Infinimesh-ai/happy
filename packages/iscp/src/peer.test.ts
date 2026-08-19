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

function makeGrant(issuer: Device, subject: Device, relayId: string): TrustGrant {
  const unsigned = {
    type: TRUST_GRANT_TYPE,
    grant_id: `grant-${subject.identity.device_id}`,
    issuer: issuer.identity.device_id,
    subject_device_id: subject.identity.device_id,
    audience: 'happy-domain',
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
}

function createTestPeer(relay: FakeRelay, deviceId: string, identities: Map<string, DeviceIdentity>, issuer: Device): TestPeer {
  const device = createDevice(provider, { domainId: relay.domainId, deviceId });
  identities.set(deviceId, device.identity);
  const credentials = relay.issueCredentials(deviceId);
  const result: TestPeer = { device, peer: undefined as unknown as IscpPeer, received: [], errors: [], manifests: [] };
  result.peer = new IscpPeer({
    device,
    grant: makeGrant(issuer, device, relay.relayId),
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
    onError: (error) => {
      result.errors.push(error);
    },
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
