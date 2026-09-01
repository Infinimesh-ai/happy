/**
 * Cross-language wire-contract tests for the trust read plane
 * (InfinimeshCloud docs/30-delivery/20-trust-wire-contract.md).
 *
 * The "managed" fixtures below are the production-shaped golden bodies also
 * pinned server-side by the Cloud's internal/app/trustapi/wire_contract_test.go;
 * the "reference" fixtures mirror the upstream ISCP trust-root reference
 * implementation. One parser must accept both — editing either fixture
 * without the counterpart repo is a cross-repo breaking change.
 */

import { describe, expect, it } from 'vitest';

import { createNobleProvider } from './crypto/noble';
import { TrustRootClient } from './trustRoot';

const provider = createNobleProvider();

function stubFetch(routes: Record<string, unknown>, calls: string[]) {
  return async (url: string) => {
    calls.push(url);
    const body = routes[new URL(url).pathname];
    if (body === undefined) {
      return { ok: false, status: 404, json: async (): Promise<unknown> => ({}), text: async () => '' };
    }
    return { ok: true, status: 200, json: async (): Promise<unknown> => body, text: async () => JSON.stringify(body) };
  };
}

function managedClient(routes: Record<string, unknown>, calls: string[]) {
  return new TrustRootClient({
    baseUrl: 'https://iscp.cloud.test',
    trustRootId: 'trust-root-cn-east-1',
    domainId: 'dom_prod',
    provider,
    fetchImpl: stubFetch(routes, calls),
  });
}

function referenceClient(routes: Record<string, unknown>, calls: string[]) {
  return new TrustRootClient({
    baseUrl: 'http://localhost:18081',
    trustRootId: 'trust-root-local',
    provider,
    fetchImpl: stubFetch(routes, calls),
  });
}

const cloudPublicKey = { kty: 'Ed25519', use: 'identity-signature', kid: 'kid-happy', public: 'pk_base64url' };

/** Managed Cloud device status: flat record + canonical nested identity. */
const cloudDeviceStatus = {
  identity: {
    type: 'iscp.device.identity.v2',
    domain_id: 'dom_prod',
    device_id: 'dev_happy1',
    public_key: cloudPublicKey,
    created_at: '2026-08-01T08:30:00Z',
  },
  domain_id: 'dom_prod',
  device_id: 'dev_happy1',
  status: 'trusted',
  public_key: cloudPublicKey,
  device_record_version: 1,
  revocation_epoch: 0,
};

/** Managed Cloud stored signed grant, re-emitted verbatim by grant status. */
const cloudGrant = {
  type: 'iscp.trust_grant.v2',
  grant_id: 'grant_happy1',
  issuer: 'trust-root-cn-east-1',
  subject_device_id: 'dev_happy1',
  audience: 'dev_phone1',
  confirmation_thumbprint: 'thumb_happy_1',
  permissions: ['session.open'],
  not_before: '2026-08-01T08:30:00Z',
  expires_at: '2026-09-01T08:30:00Z',
  revocation_epoch: 0,
  signature: { alg: 'Ed25519', kid: 'trust-kid', value: 'sig_base64url' },
};

describe('trust read plane wire contract (managed Cloud shapes)', () => {
  it('deviceStatus parses the Cloud superset record and sends domain_id', async () => {
    const calls: string[] = [];
    const client = managedClient({ '/v2/trust/devices/status': cloudDeviceStatus }, calls);
    const record = await client.deviceStatus('dev_happy1');
    expect(record.identity.device_id).toBe('dev_happy1');
    expect(record.identity.domain_id).toBe('dom_prod');
    expect(record.identity.public_key).toEqual(cloudPublicKey);
    expect(record.status).toBe('trusted');
    expect(record.revocation_epoch).toBe(0);
    const url = new URL(calls[0]!);
    expect(url.searchParams.get('device_id')).toBe('dev_happy1');
    expect(url.searchParams.get('domain_id')).toBe('dom_prod');
  });

  it('deviceStatus still rejects a flat record without the canonical identity', async () => {
    const { identity: _identity, ...flatOnly } = cloudDeviceStatus;
    const client = managedClient({ '/v2/trust/devices/status': flatOnly }, []);
    await expect(client.deviceStatus('dev_happy1')).rejects.toThrowError();
  });

  it('grantStatus unwraps the Cloud {grant,status} envelope and sends domain_id', async () => {
    const calls: string[] = [];
    const client = managedClient({ '/v2/trust/grants/status': { grant: cloudGrant, status: 'active' } }, calls);
    const grant = await client.grantStatus('grant_happy1');
    expect(grant).toEqual(cloudGrant);
    const url = new URL(calls[0]!);
    expect(url.searchParams.get('grant_id')).toBe('grant_happy1');
    expect(url.searchParams.get('domain_id')).toBe('dom_prod');
  });

  it('grantStatus unwraps expired and revoked envelopes to the same grant', async () => {
    for (const status of ['expired', 'revoked']) {
      const client = managedClient({ '/v2/trust/grants/status': { grant: cloudGrant, status } }, []);
      expect(await client.grantStatus('grant_happy1')).toEqual(cloudGrant);
    }
  });

  it('grantStatus rejects unknown envelopes instead of guessing', async () => {
    const client = managedClient({ '/v2/trust/grants/status': { data: cloudGrant } }, []);
    await expect(client.grantStatus('grant_happy1')).rejects.toThrowError();
  });

  it('revocations normalizes the Cloud items list to a device epoch map', async () => {
    const calls: string[] = [];
    const client = managedClient({
      '/v2/trust/revocations': {
        items: [
          { revocation_id: 'rev_1', domain_id: 'dom_prod', device_id: 'dev_happy1', reason_code: 'device_compromised', effective_at: '2026-08-01T08:30:00Z' },
          { revocation_id: 'rev_2', domain_id: 'dom_prod', grant_id: 'grant_happy1', reason_code: 'grant_rotated', effective_at: '2026-08-01T08:30:00Z' },
        ],
      },
    }, calls);
    // The grant-only entry must not fabricate a device epoch.
    expect(await client.revocations()).toEqual({ dev_happy1: 1 });
    expect(new URL(calls[0]!).searchParams.get('domain_id')).toBe('dom_prod');
  });

  it('revocations returns an empty map for an empty Cloud list', async () => {
    const client = managedClient({ '/v2/trust/revocations': { items: [] } }, []);
    expect(await client.revocations()).toEqual({});
  });
});

describe('trust read plane wire contract (ISCP reference shapes)', () => {
  it('deviceStatus parses the reference nested-identity record without a domain query', async () => {
    const calls: string[] = [];
    const client = referenceClient({
      '/v2/trust/devices/status': {
        identity: cloudDeviceStatus.identity,
        status: 'authorized',
        device_record_version: 2,
        revocation_epoch: 0,
      },
    }, calls);
    const record = await client.deviceStatus('dev_happy1');
    expect(record.status).toBe('authorized');
    expect(new URL(calls[0]!).searchParams.has('domain_id')).toBe(false);
  });

  // ISCP v0.2: the reference implementation emits the same normative typed
  // shapes as the Cloud; the pre-v0.2 bare grant and epoch map are rejected
  // rather than silently bridged.
  it('grantStatus accepts the v0.2 typed envelope and rejects the pre-v0.2 bare grant', async () => {
    const typed = referenceClient({ '/v2/trust/grants/status': { type: 'iscp.trust.grant_status.v2', grant: cloudGrant, status: 'active' } }, []);
    expect(await typed.grantStatus('grant_happy1')).toEqual(cloudGrant);
    const bare = referenceClient({ '/v2/trust/grants/status': cloudGrant }, []);
    await expect(bare.grantStatus('grant_happy1')).rejects.toThrowError();
  });

  it('revocations rejects the pre-v0.2 epoch map', async () => {
    const client = referenceClient({ '/v2/trust/revocations': { dev_a: 2, dev_b: 1 } }, []);
    await expect(client.revocations()).rejects.toThrowError();
  });

  it('revocations follows next_cursor pages to exhaustion', async () => {
    const calls: string[] = [];
    const pages = [
      {
        type: 'iscp.trust.revocations.v2',
        items: [{ revocation_id: 'rev_1', domain_id: 'dom_prod', device_id: 'dev_a', reason_code: 'device_compromised', effective_at: '2026-08-01T08:30:00Z' }],
        next_cursor: 'cursor_page2',
      },
      {
        type: 'iscp.trust.revocations.v2',
        items: [{ revocation_id: 'rev_2', domain_id: 'dom_prod', device_id: 'dev_b', reason_code: 'device_lost', effective_at: '2026-08-01T09:30:00Z' }],
      },
    ];
    const client = new TrustRootClient({
      baseUrl: 'http://localhost:18081',
      trustRootId: 'trust-root-local',
      provider,
      fetchImpl: async (url: string) => {
        calls.push(url);
        const body = pages[calls.length - 1];
        return { ok: true, status: 200, json: async (): Promise<unknown> => body, text: async () => JSON.stringify(body) };
      },
    });
    expect(await client.revocations()).toEqual({ dev_a: 1, dev_b: 1 });
    expect(calls).toHaveLength(2);
    expect(calls[1]!.endsWith('?cursor=cursor_page2')).toBe(true);
  });
});
