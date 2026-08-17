/**
 * v2 background auto-renewal client (Infinimesh Cloud, frozen contract
 * InfinimeshCloud docs/10-design/12-managed-provisioning.md §10.4):
 * request-body contract, proof binding (audience = relay, challenge = the
 * MANDATORY Idempotency-Key), response parsing, Cloud stable error reasons,
 * Retry-After surfacing, verbatim proof reuse, and the deliberate absence of
 * any hidden retry (the daemon scheduler owns the ladder).
 */

import { describe, expect, it } from 'vitest';

import { createNobleProvider } from '../crypto/noble';
import { rfc3339Seconds } from '../encoding';
import { IscpError } from '../errors';
import { createDevice, createDeviceProof, verifyDeviceProof, type Device } from '../identity';
import { signObject } from '../signing';
import { TRUST_GRANT_TYPE, type DeviceProof, type TrustGrant } from '../schemas';
import { RelayHttpClient, type FetchLike } from './http';

const provider = createNobleProvider();
const RELAY_ID = 'relay-prod-cn-east-1';
const DOMAIN_ID = 'dom_test';
const KEY = 'idem_unguessable_1';

const trustSigner = createDevice(provider, { domainId: DOMAIN_ID, deviceId: 'trust-root-cn-east-1' });

function makeGrant(subjectDeviceId: string, confirmationThumbprint: string): TrustGrant {
  const now = Date.now();
  const unsigned = {
    type: TRUST_GRANT_TYPE,
    grant_id: 'grant_auto_renewed_1',
    issuer: 'trust-root-cn-east-1',
    subject_device_id: subjectDeviceId,
    audience: 'dev_phone_1',
    confirmation_thumbprint: confirmationThumbprint,
    permissions: ['text'],
    relay_constraints: [RELAY_ID],
    not_before: rfc3339Seconds(new Date(now - 60 * 1000)),
    expires_at: rfc3339Seconds(new Date(now + 7 * 86_400 * 1000)),
    revocation_epoch: 0,
  };
  return signObject(provider, TRUST_GRANT_TYPE, unsigned, trustSigner.privateKey, trustSigner.identity.public_key.kid) as TrustGrant;
}

function okBody(device: Device) {
  return {
    data: { device_id: device.identity.device_id, domain_id: DOMAIN_ID },
    grant: makeGrant(device.identity.device_id, device.identity.public_key.kid),
  };
}

function jsonResponse(status: number, body: unknown, headers?: Record<string, string>) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
    text: async () => JSON.stringify(body),
    headers: { get: (name: string) => headers?.[name.toLowerCase()] ?? null },
  };
}

interface Captured {
  url: string;
  headers: Record<string, string>;
  body: Record<string, unknown>;
}

function client(fetchImpl: FetchLike): RelayHttpClient {
  return new RelayHttpClient({ baseUrl: 'https://iscp.example', relayId: RELAY_ID, provider, fetchImpl });
}

function enrolledDevice(): Device {
  return createDevice(provider, { domainId: DOMAIN_ID, deviceId: 'dev_official_1' });
}

describe('autoRenewGrant', () => {
  it('sends the frozen v2 contract body with challenge = the Idempotency-Key and no renewal_id', async () => {
    const device = enrolledDevice();
    const captured: Captured[] = [];
    const relay = client(async (url, init) => {
      captured.push({ url, headers: init?.headers ?? {}, body: JSON.parse(init?.body ?? '{}') as Record<string, unknown> });
      return jsonResponse(201, okBody(device));
    });

    const result = await relay.autoRenewGrant(device, { idempotencyKey: KEY });

    expect(captured).toHaveLength(1);
    const request = captured[0]!;
    expect(request.url).toBe('https://iscp.example/v2/relay/devices/auto-renew-grant');
    expect(Object.keys(request.body).sort()).toEqual(['identity', 'identity_proof']);
    expect(request.body.identity).toEqual(device.identity);
    expect(request.headers['Idempotency-Key']).toBe(KEY);

    const proof = request.body.identity_proof as DeviceProof;
    expect(proof.audience).toBe(RELAY_ID);
    expect(proof.challenge).toBe(KEY);
    // The proof must verify against the submitted identity (server-side gate).
    verifyDeviceProof(provider, device.identity, proof, { audience: RELAY_ID, challenge: KEY });

    expect(result.data.device_id).toBe(device.identity.device_id);
    expect(result.grant.grant_id).toBe('grant_auto_renewed_1');
    expect(result.grant.type).toBe(TRUST_GRANT_TYPE);
  });

  it('resends a caller-supplied proof verbatim (unknown-outcome retry mode)', async () => {
    const device = enrolledDevice();
    const original = createDeviceProof(provider, device, { audience: RELAY_ID, challenge: KEY });
    const captured: Captured[] = [];
    const relay = client(async (url, init) => {
      captured.push({ url, headers: init?.headers ?? {}, body: JSON.parse(init?.body ?? '{}') as Record<string, unknown> });
      return jsonResponse(201, okBody(device));
    });

    await relay.autoRenewGrant(device, { idempotencyKey: KEY, proof: original });
    expect(captured[0]!.body.identity_proof).toEqual(original);
    expect(captured[0]!.headers['Idempotency-Key']).toBe(KEY);
  });

  it('refuses an empty idempotency key locally (the key is the proof challenge)', async () => {
    const device = enrolledDevice();
    let calls = 0;
    const relay = client(async () => {
      calls += 1;
      return jsonResponse(201, okBody(device));
    });
    await expect(relay.autoRenewGrant(device, { idempotencyKey: '' })).rejects.toThrowError(/idempotency key/);
    expect(calls).toBe(0);
  });

  it('rejects a 201 response missing the grant', async () => {
    const device = enrolledDevice();
    const relay = client(async () => {
      const { grant: _grant, ...withoutGrant } = okBody(device);
      return jsonResponse(201, withoutGrant);
    });
    await expect(relay.autoRenewGrant(device, { idempotencyKey: KEY })).rejects.toThrowError(/did not return a trust grant/);
  });

  const errorCases: Array<{ status: number; reason: string }> = [
    { status: 400, reason: 'idempotency_key_required' },
    { status: 403, reason: 'auto_renewal_disabled' },
    { status: 401, reason: 'device_proof_invalid' },
    { status: 409, reason: 'proof_replay_detected' },
    { status: 404, reason: 'renewal_authorization_not_found' },
    { status: 403, reason: 'renewal_authorization_revoked' },
    { status: 410, reason: 'renewal_authorization_expired' },
    { status: 409, reason: 'renewal_identity_conflict' },
    { status: 403, reason: 'device_revoked' },
    { status: 403, reason: 'grant_audience_not_active' },
    { status: 429, reason: 'renewal_not_yet_eligible' },
    { status: 403, reason: 'require_mfa' },
    { status: 429, reason: 'rate_limited' },
  ];
  for (const { status, reason } of errorCases) {
    it(`surfaces the Cloud stable reason ${reason} (${status})`, async () => {
      const device = enrolledDevice();
      const relay = client(async () => jsonResponse(status, {
        error: { code: 'err', message: `auto-renewal rejected: ${reason}`, reason, request_id: 'req_1', details: {} },
      }));
      const error = await relay.autoRenewGrant(device, { idempotencyKey: KEY }).catch((e: unknown) => e);
      expect(error).toBeInstanceOf(IscpError);
      expect((error as IscpError).details?.reason).toBe(reason);
      expect((error as IscpError).details?.httpStatus).toBe(String(status));
      expect((error as IscpError).message).toContain(String(status));
    });
  }

  it('surfaces Retry-After seconds on the 429 gates', async () => {
    const device = enrolledDevice();
    const relay = client(async () => jsonResponse(
      429,
      { error: { code: 'too_many', message: 'not yet eligible', reason: 'renewal_not_yet_eligible', request_id: 'req_1', details: {} } },
      { 'retry-after': '1800' },
    ));
    const error = await relay.autoRenewGrant(device, { idempotencyKey: KEY }).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(IscpError);
    expect((error as IscpError).details?.reason).toBe('renewal_not_yet_eligible');
    expect((error as IscpError).details?.retryAfterSeconds).toBe('1800');
  });

  it('does NOT hide network failures behind an automatic retry — the scheduler owns the ladder', async () => {
    const device = enrolledDevice();
    let calls = 0;
    const relay = client(async () => {
      calls += 1;
      throw new Error('socket hang up');
    });
    await expect(relay.autoRenewGrant(device, { idempotencyKey: KEY })).rejects.toThrowError(/socket hang up/);
    expect(calls).toBe(1);
  });
});
