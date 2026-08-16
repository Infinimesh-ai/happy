/**
 * v2 signed-ticket registration client (Infinimesh Cloud managed
 * provisioning, OPS 2026-08-16 §5.5): request-body contract, response
 * parsing, Cloud error surfaces, and Idempotency-Key reuse across the
 * network-failure retry.
 */

import { describe, expect, it } from 'vitest';

import { createNobleProvider } from '../crypto/noble';
import { rfc3339Seconds } from '../encoding';
import { IscpError } from '../errors';
import { createDevice, verifyDeviceProof, type Device } from '../identity';
import { signObject } from '../signing';
import { signPairingTicket } from '../provisioning/pairingTicket';
import {
  PAIRING_TICKET_TYPE,
  TRUST_GRANT_TYPE,
  type DeviceProof,
  type PairingTicket,
  type TrustGrant,
} from '../schemas';
import { RelayHttpClient, type FetchLike } from './http';

const provider = createNobleProvider();
const RELAY_ID = 'relay-prod-cn-east-1';
const DOMAIN_ID = 'dom_test';

const issuer = createDevice(provider, { domainId: DOMAIN_ID, deviceId: 'trust-root-signer' });
const trustSigner = createDevice(provider, { domainId: DOMAIN_ID, deviceId: 'trust-root-cn-east-1' });

function makeTicket(): PairingTicket {
  const now = Date.now();
  return signPairingTicket(provider, issuer, {
    ticket_id: 'tick_abc123',
    domain_id: DOMAIN_ID,
    relay_id: RELAY_ID,
    trust_root_id: 'trust-root-cn-east-1',
    max_uses: 1,
    issued_at: rfc3339Seconds(new Date(now)),
    expires_at: rfc3339Seconds(new Date(now + 5 * 60 * 1000)),
  });
}

function makeGrant(subjectDeviceId: string, confirmationThumbprint: string): TrustGrant {
  const now = Date.now();
  const unsigned = {
    type: TRUST_GRANT_TYPE,
    grant_id: 'grant_1',
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
    data: {
      device_id: 'dev_official_1',
      domain_id: DOMAIN_ID,
      device_type: 'service_agent',
      device_role: 'member_device',
      trust_state: 'authorized',
    },
    access: { domain_id: DOMAIN_ID, device_id: 'dev_official_1', token: 'acc_tok', expires_at: rfc3339Seconds(new Date(Date.now() + 900_000)) },
    refresh: { domain_id: DOMAIN_ID, device_id: 'dev_official_1', token: 'ref_tok', expires_at: rfc3339Seconds(new Date(Date.now() + 86_400_000)) },
    grant: makeGrant('dev_official_1', device.identity.public_key.kid),
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

describe('registerWithSignedTicket', () => {
  it('sends the exact v2 contract body and a proof bound to relay + ticket_id', async () => {
    const device = createDevice(provider, { domainId: DOMAIN_ID, deviceId: 'happy-cli-temp' });
    const ticket = makeTicket();
    const captured: Captured[] = [];
    const relay = client(async (url, init) => {
      captured.push({ url, headers: init?.headers ?? {}, body: JSON.parse(init?.body ?? '{}') as Record<string, unknown> });
      return jsonResponse(201, okBody(device));
    });

    const result = await relay.registerWithSignedTicket(device, ticket, {
      displayName: 'Happy Agent',
      metadata: { product_kind: 'happy' },
    });

    expect(captured).toHaveLength(1);
    const request = captured[0]!;
    expect(request.url).toBe('https://iscp.example/v2/relay/devices/register-with-ticket');

    // Full signed ticket + identity + identity_proof; nothing that would
    // fight the server-side enrollee sidecar shape.
    expect(request.body.ticket).toEqual(ticket);
    expect(request.body.identity).toEqual(device.identity);
    expect(request.body.display_name).toBe('Happy Agent');
    expect(request.body.metadata).toEqual({ product_kind: 'happy' });
    expect(request.body).not.toHaveProperty('device_type');
    expect(request.body).not.toHaveProperty('device_role');
    expect(request.body).not.toHaveProperty('max_uses');
    expect(request.body).not.toHaveProperty('ticket_id');
    expect(request.body).not.toHaveProperty('proof');

    const proof = request.body.identity_proof as DeviceProof;
    expect(proof.audience).toBe(RELAY_ID);
    expect(proof.challenge).toBe(ticket.ticket_id);
    // The proof must verify against the submitted identity (server-side gate).
    verifyDeviceProof(provider, device.identity, proof, { audience: RELAY_ID, challenge: ticket.ticket_id });

    expect(typeof request.headers['Idempotency-Key']).toBe('string');
    expect(request.headers['Idempotency-Key']!.length).toBeGreaterThan(0);

    expect(result.data.device_id).toBe('dev_official_1');
    expect(result.data.domain_id).toBe(DOMAIN_ID);
    expect(result.access.token).toBe('acc_tok');
    expect(result.refresh.token).toBe('ref_tok');
    expect(result.grant.grant_id).toBe('grant_1');
    expect(result.grant.type).toBe(TRUST_GRANT_TYPE);
  });

  it('never sends legacy pairing_code fields and omits display_name/metadata when unset', async () => {
    const device = createDevice(provider, { domainId: DOMAIN_ID, deviceId: 'happy-cli-temp' });
    const captured: Captured[] = [];
    const relay = client(async (url, init) => {
      captured.push({ url, headers: init?.headers ?? {}, body: JSON.parse(init?.body ?? '{}') as Record<string, unknown> });
      return jsonResponse(201, okBody(device));
    });
    await relay.registerWithSignedTicket(device, makeTicket());
    const body = captured[0]!.body;
    expect(Object.keys(body).sort()).toEqual(['identity', 'identity_proof', 'ticket']);
    expect((body.ticket as PairingTicket).type).toBe(PAIRING_TICKET_TYPE);
  });

  it('rejects a 201 response missing the grant', async () => {
    const device = createDevice(provider, { domainId: DOMAIN_ID, deviceId: 'happy-cli-temp' });
    const relay = client(async () => {
      const { grant: _grant, ...withoutGrant } = okBody(device);
      return jsonResponse(201, withoutGrant);
    });
    await expect(relay.registerWithSignedTicket(device, makeTicket())).rejects.toThrowError(/did not return a trust grant/);
  });

  it('surfaces the Cloud stable reason for ticket_consumed (410) and device_proof_invalid (401)', async () => {
    const device = createDevice(provider, { domainId: DOMAIN_ID, deviceId: 'happy-cli-temp' });
    const consumed = client(async () => jsonResponse(410, {
      error: { code: 'not_found', message: 'provisioning ticket consumed or expired', reason: 'ticket_consumed', request_id: 'req_1', details: {} },
    }));
    const consumedError = await consumed.registerWithSignedTicket(device, makeTicket()).catch((e: unknown) => e);
    expect(consumedError).toBeInstanceOf(IscpError);
    expect((consumedError as IscpError).details?.reason).toBe('ticket_consumed');
    expect((consumedError as IscpError).message).toContain('410');

    const badProof = client(async () => jsonResponse(401, {
      error: { code: 'unauthorized', message: 'identity possession proof invalid', reason: 'device_proof_invalid', request_id: 'req_2', details: {} },
    }));
    const proofError = await badProof.registerWithSignedTicket(device, makeTicket()).catch((e: unknown) => e);
    expect(proofError).toBeInstanceOf(IscpError);
    expect((proofError as IscpError).details?.reason).toBe('device_proof_invalid');
  });

  it('surfaces proof_replay_detected (409)', async () => {
    const device = createDevice(provider, { domainId: DOMAIN_ID, deviceId: 'happy-cli-temp' });
    const relay = client(async () => jsonResponse(409, {
      error: { code: 'conflict', message: 'device proof replay', reason: 'proof_replay_detected', request_id: 'req_3', details: {} },
    }));
    const error = await relay.registerWithSignedTicket(device, makeTicket()).catch((e: unknown) => e);
    expect((error as IscpError).details?.reason).toBe('proof_replay_detected');
  });

  it('retries once after a network failure, reusing the same body and Idempotency-Key', async () => {
    const device = createDevice(provider, { domainId: DOMAIN_ID, deviceId: 'happy-cli-temp' });
    const captured: Captured[] = [];
    let calls = 0;
    const relay = client(async (url, init) => {
      calls += 1;
      captured.push({ url, headers: init?.headers ?? {}, body: JSON.parse(init?.body ?? '{}') as Record<string, unknown> });
      if (calls === 1) throw new Error('socket hang up');
      return jsonResponse(201, okBody(device));
    });

    const result = await relay.registerWithSignedTicket(device, makeTicket());
    expect(calls).toBe(2);
    expect(captured[0]!.headers['Idempotency-Key']).toBe(captured[1]!.headers['Idempotency-Key']);
    // Identical replay body: same proof nonce, so the Cloud idempotency layer
    // can replay the stored 201 instead of re-executing the registration.
    expect(captured[0]!.body).toEqual(captured[1]!.body);
    expect(result.data.device_id).toBe('dev_official_1');
  });

  it('honors an explicitly supplied Idempotency-Key', async () => {
    const device = createDevice(provider, { domainId: DOMAIN_ID, deviceId: 'happy-cli-temp' });
    const captured: Captured[] = [];
    const relay = client(async (url, init) => {
      captured.push({ url, headers: init?.headers ?? {}, body: JSON.parse(init?.body ?? '{}') as Record<string, unknown> });
      return jsonResponse(201, okBody(device));
    });
    await relay.registerWithSignedTicket(device, makeTicket(), { idempotencyKey: 'caller-key-1' });
    expect(captured[0]!.headers['Idempotency-Key']).toBe('caller-key-1');
  });
});
