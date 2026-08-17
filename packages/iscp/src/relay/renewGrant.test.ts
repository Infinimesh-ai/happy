/**
 * v2 grant renewal client (Infinimesh Cloud, frozen contract OPS 2026-08-17
 * §4.3): request-body contract, proof binding (audience = relay,
 * challenge = renewal_id), response parsing, Cloud error reasons, and
 * Idempotency-Key reuse across the network-failure retry.
 */

import { describe, expect, it } from 'vitest';

import { createNobleProvider } from '../crypto/noble';
import { rfc3339Seconds } from '../encoding';
import { IscpError } from '../errors';
import { createDevice, verifyDeviceProof, type Device } from '../identity';
import { signObject } from '../signing';
import { TRUST_GRANT_TYPE, type DeviceProof, type TrustGrant } from '../schemas';
import { RelayHttpClient, type FetchLike } from './http';

const provider = createNobleProvider();
const RELAY_ID = 'relay-prod-cn-east-1';
const DOMAIN_ID = 'dom_test';
const RENEWAL_ID = 'ren_abc123';

const trustSigner = createDevice(provider, { domainId: DOMAIN_ID, deviceId: 'trust-root-cn-east-1' });

function makeGrant(subjectDeviceId: string, confirmationThumbprint: string): TrustGrant {
  const now = Date.now();
  const unsigned = {
    type: TRUST_GRANT_TYPE,
    grant_id: 'grant_renewed_1',
    issuer: 'trust-root-cn-east-1',
    subject_device_id: subjectDeviceId,
    audience: 'dev_phone_1',
    confirmation_thumbprint: confirmationThumbprint,
    permissions: ['text'],
    relay_constraints: [RELAY_ID],
    not_before: rfc3339Seconds(new Date(now - 60 * 1000)),
    expires_at: rfc3339Seconds(new Date(now + 3600 * 1000)),
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

function jsonResponse(status: number, body: unknown) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
    text: async () => JSON.stringify(body),
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

describe('renewGrant', () => {
  it('sends the frozen v2 contract body and a proof bound to relay + renewal_id', async () => {
    const device = enrolledDevice();
    const captured: Captured[] = [];
    const relay = client(async (url, init) => {
      captured.push({ url, headers: init?.headers ?? {}, body: JSON.parse(init?.body ?? '{}') as Record<string, unknown> });
      return jsonResponse(201, okBody(device));
    });

    const result = await relay.renewGrant(device, RENEWAL_ID);

    expect(captured).toHaveLength(1);
    const request = captured[0]!;
    expect(request.url).toBe('https://iscp.example/v2/relay/devices/renew-grant');
    expect(Object.keys(request.body).sort()).toEqual(['identity', 'identity_proof', 'renewal_id']);
    expect(request.body.renewal_id).toBe(RENEWAL_ID);
    expect(request.body.identity).toEqual(device.identity);

    const proof = request.body.identity_proof as DeviceProof;
    expect(proof.audience).toBe(RELAY_ID);
    expect(proof.challenge).toBe(RENEWAL_ID);
    // The proof must verify against the submitted identity (server-side gate).
    verifyDeviceProof(provider, device.identity, proof, { audience: RELAY_ID, challenge: RENEWAL_ID });

    expect(typeof request.headers['Idempotency-Key']).toBe('string');
    expect(request.headers['Idempotency-Key']!.length).toBeGreaterThan(0);

    expect(result.data.device_id).toBe(device.identity.device_id);
    expect(result.data.domain_id).toBe(DOMAIN_ID);
    expect(result.grant.grant_id).toBe('grant_renewed_1');
    expect(result.grant.type).toBe(TRUST_GRANT_TYPE);
  });

  it('rejects a 201 response missing the grant', async () => {
    const device = enrolledDevice();
    const relay = client(async () => {
      const { grant: _grant, ...withoutGrant } = okBody(device);
      return jsonResponse(201, withoutGrant);
    });
    await expect(relay.renewGrant(device, RENEWAL_ID)).rejects.toThrowError(/did not return a trust grant/);
  });

  const errorCases: Array<{ status: number; reason: string }> = [
    { status: 404, reason: 'renewal_not_found' },
    { status: 410, reason: 'renewal_expired' },
    { status: 410, reason: 'renewal_consumed' },
    { status: 403, reason: 'renewal_device_mismatch' },
    { status: 409, reason: 'renewal_identity_conflict' },
    { status: 403, reason: 'device_revoked' },
    { status: 401, reason: 'device_proof_invalid' },
    { status: 409, reason: 'proof_replay_detected' },
  ];
  for (const { status, reason } of errorCases) {
    it(`surfaces the Cloud stable reason ${reason} (${status})`, async () => {
      const device = enrolledDevice();
      const relay = client(async () => jsonResponse(status, {
        error: { code: 'err', message: `renewal rejected: ${reason}`, reason, request_id: 'req_1', details: {} },
      }));
      const error = await relay.renewGrant(device, RENEWAL_ID).catch((e: unknown) => e);
      expect(error).toBeInstanceOf(IscpError);
      expect((error as IscpError).details?.reason).toBe(reason);
      expect((error as IscpError).message).toContain(String(status));
    });
  }

  it('retries once after a network failure, reusing the same body and Idempotency-Key', async () => {
    const device = enrolledDevice();
    const captured: Captured[] = [];
    let calls = 0;
    const relay = client(async (url, init) => {
      calls += 1;
      captured.push({ url, headers: init?.headers ?? {}, body: JSON.parse(init?.body ?? '{}') as Record<string, unknown> });
      if (calls === 1) throw new Error('socket hang up');
      return jsonResponse(201, okBody(device));
    });

    const result = await relay.renewGrant(device, RENEWAL_ID);
    expect(calls).toBe(2);
    expect(captured[0]!.headers['Idempotency-Key']).toBe(captured[1]!.headers['Idempotency-Key']);
    // Identical replay body: same proof nonce, so the Cloud idempotency layer
    // can replay the stored 201 instead of re-executing the renewal.
    expect(captured[0]!.body).toEqual(captured[1]!.body);
    expect(result.grant.grant_id).toBe('grant_renewed_1');
  });

  it('honors an explicitly supplied Idempotency-Key', async () => {
    const device = enrolledDevice();
    const captured: Captured[] = [];
    const relay = client(async (url, init) => {
      captured.push({ url, headers: init?.headers ?? {}, body: JSON.parse(init?.body ?? '{}') as Record<string, unknown> });
      return jsonResponse(201, okBody(device));
    });
    await relay.renewGrant(device, RENEWAL_ID, { idempotencyKey: 'caller-key-1' });
    expect(captured[0]!.headers['Idempotency-Key']).toBe('caller-key-1');
  });
});
