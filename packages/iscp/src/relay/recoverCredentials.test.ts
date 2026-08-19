/**
 * Existing-device credential recovery client (Infinimesh Cloud frozen
 * contract, InfinimeshCloud docs/10-design/12-managed-provisioning.md §11;
 * ISCP#11 upstream): request-body contract, proof binding
 * (challenge = Idempotency-Key \0 wrap key), sealed-response opening against
 * a faithful server-side sealer, tamper fail-closed, metadata cross-check,
 * stable Cloud error reasons, and the deliberate absence of any hidden retry.
 */

import { describe, expect, it } from 'vitest';

import { createNobleProvider } from '../crypto/noble';
import { X25519PublicKey } from '../crypto/provider';
import { fromBase64Url, toBase64Url, utf8Encode } from '../encoding';
import { IscpError } from '../errors';
import { createDevice, verifyDeviceProof, type Device } from '../identity';
import type { DeviceProof } from '../schemas';
import { RelayHttpClient, type FetchLike } from './http';
import {
  CREDENTIAL_RECOVERY_WRAPPED_TYPE,
  assertRecoveredPairMatchesMetadata,
  generateRecoveryWrapKey,
  openRecoveredCredentials,
  recoveryChallenge,
  type WrappedRecoveredCredentials,
} from './recoverCredentials';

const provider = createNobleProvider();
const RELAY_ID = 'relay-prod-cn-east-1';
const DOMAIN_ID = 'dom_test';
const KEY = 'idem_recover_unguessable_1';

function enrolledDevice(): Device {
  return createDevice(provider, { domainId: DOMAIN_ID, deviceId: 'dev_official_1' });
}

function client(fetchImpl: FetchLike): RelayHttpClient {
  return new RelayHttpClient({ baseUrl: 'https://iscp.example', relayId: RELAY_ID, provider, fetchImpl });
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

/**
 * Faithful mirror of the Cloud's §11.4 sealer (internal/relay/recovery.go):
 * X25519 with a fresh server ephemeral key, HKDF-SHA256 over
 * transcript ‖ clientPub ‖ serverPub with empty salt, ChaCha20-Poly1305 with
 * the transcript as AAD.
 */
function sealPair(
  wrapPublicKey: string,
  identity: { domainId: string; deviceId: string; thumbprint: string },
  pair: unknown,
): WrappedRecoveredCredentials {
  const clientPub = new X25519PublicKey(fromBase64Url(wrapPublicKey));
  const server = provider.generateSessionKeyPair();
  const secret = provider.sharedSecret(server.privateKey, clientPub);
  const transcript = utf8Encode(`iscp/v2/relay/credential-recovery\0${identity.domainId}\0${identity.deviceId}\0${identity.thumbprint}`);
  const info = new Uint8Array(transcript.length + 64);
  info.set(transcript, 0);
  info.set(clientPub.bytes, transcript.length);
  info.set(server.publicKey.bytes, transcript.length + 32);
  const key = provider.hkdfSha256(secret, new Uint8Array(0), info, 32);
  const nonce = provider.randomBytes(12);
  const ciphertext = provider.seal(key, nonce, utf8Encode(JSON.stringify(pair)), transcript);
  return {
    type: CREDENTIAL_RECOVERY_WRAPPED_TYPE,
    ciphersuite: 'ISCP_V2_X25519_HKDF_SHA256_CHACHA20POLY1305',
    recovery_public_key: wrapPublicKey,
    server_public_key: toBase64Url(server.publicKey.bytes),
    nonce: toBase64Url(nonce),
    ciphertext: toBase64Url(ciphertext),
  };
}

function tokenPair(device: Device) {
  const now = new Date();
  const later = new Date(now.getTime() + 900_000);
  const common = { domain_id: DOMAIN_ID, device_id: device.identity.device_id, issued_at: now.toISOString() };
  return {
    access: { ...common, credential_id: 'cred_a1', token: 'rac_recovered_access', expires_at: later.toISOString() },
    refresh: { ...common, credential_id: 'cred_r1', token: 'rrc_recovered_refresh', expires_at: new Date(now.getTime() + 86_400_000).toISOString(), rotation_counter: 3 },
  };
}

function metadataOf(pair: ReturnType<typeof tokenPair>) {
  const strip = ({ token: _token, ...rest }: { token: string } & Record<string, unknown>) => rest;
  return { access: strip(pair.access), refresh: strip(pair.refresh) };
}

describe('recoverCredentials', () => {
  it('sends the frozen §11 body with challenge = key \\0 wrap key and parses the sealed 201', async () => {
    const device = enrolledDevice();
    const wrap = generateRecoveryWrapKey(provider);
    const pair = tokenPair(device);
    const captured: Array<{ url: string; headers: Record<string, string>; body: Record<string, unknown> }> = [];
    const relay = client(async (url, init) => {
      const body = JSON.parse(init?.body ?? '{}') as Record<string, unknown>;
      captured.push({ url, headers: init?.headers ?? {}, body });
      const wrapKey = (body.recovery_wrap_key as { public: string }).public;
      return jsonResponse(201, {
        data: { device_id: device.identity.device_id, domain_id: DOMAIN_ID },
        ...metadataOf(pair),
        credentials_wrapped: sealPair(wrapKey, {
          domainId: DOMAIN_ID,
          deviceId: device.identity.device_id,
          thumbprint: device.identity.public_key.kid,
        }, pair),
      });
    });

    const recovery = await relay.recoverCredentials(device, { idempotencyKey: KEY, wrapPublicKey: wrap.publicKey });

    expect(captured).toHaveLength(1);
    expect(captured[0]!.url).toBe('https://iscp.example/v2/relay/devices/recover-credentials');
    expect(captured[0]!.headers['Idempotency-Key']).toBe(KEY);
    expect(captured[0]!.body.recovery_wrap_key).toEqual({ kty: 'X25519', public: wrap.publicKey });
    // The possession proof binds the attempt AND the delivery target.
    const proof = captured[0]!.body.identity_proof as DeviceProof;
    expect(() => verifyDeviceProof(provider, device.identity, proof, {
      audience: RELAY_ID,
      challenge: recoveryChallenge(KEY, wrap.publicKey),
    })).not.toThrow();
    // Cleartext carries no tokens; the sealed blob opens to the full pair.
    expect(JSON.stringify(recovery)).not.toContain('rac_');
    expect(JSON.stringify(recovery)).not.toContain('rrc_');
    const opened = openRecoveredCredentials(provider, {
      wrapPrivateKey: wrap.privateKey,
      wrapPublicKey: wrap.publicKey,
      wrapped: recovery.credentials_wrapped,
      domainId: DOMAIN_ID,
      deviceId: device.identity.device_id,
      thumbprint: device.identity.public_key.kid,
    });
    expect(opened.access.token).toBe('rac_recovered_access');
    expect(opened.refresh.token).toBe('rrc_recovered_refresh');
    expect(opened.refresh.rotation_counter).toBe(3);
    expect(() => assertRecoveredPairMatchesMetadata(opened, recovery)).not.toThrow();
  });

  it('reuses a caller-provided proof verbatim for unknown-outcome retries', async () => {
    const device = enrolledDevice();
    const wrap = generateRecoveryWrapKey(provider);
    const pair = tokenPair(device);
    const proofs: DeviceProof[] = [];
    const relay = client(async (_url, init) => {
      const body = JSON.parse(init?.body ?? '{}') as { identity_proof: DeviceProof; recovery_wrap_key: { public: string } };
      proofs.push(body.identity_proof);
      return jsonResponse(201, {
        data: { device_id: device.identity.device_id, domain_id: DOMAIN_ID },
        ...metadataOf(pair),
        credentials_wrapped: sealPair(body.recovery_wrap_key.public, {
          domainId: DOMAIN_ID,
          deviceId: device.identity.device_id,
          thumbprint: device.identity.public_key.kid,
        }, pair),
      });
    });
    const first = await relay.recoverCredentials(device, { idempotencyKey: KEY, wrapPublicKey: wrap.publicKey });
    expect(first.access.credential_id).toBe('cred_a1');
    await relay.recoverCredentials(device, { idempotencyKey: KEY, wrapPublicKey: wrap.publicKey, proof: proofs[0]! });
    expect(proofs).toHaveLength(2);
    expect(proofs[1]).toEqual(proofs[0]);
  });

  it('rejects an empty idempotency key or wrap key without any network call', async () => {
    const device = enrolledDevice();
    let calls = 0;
    const relay = client(async () => {
      calls += 1;
      return jsonResponse(500, {});
    });
    await expect(relay.recoverCredentials(device, { idempotencyKey: '', wrapPublicKey: 'x' })).rejects.toThrow(/idempotency key/);
    await expect(relay.recoverCredentials(device, { idempotencyKey: KEY, wrapPublicKey: '' })).rejects.toThrow(/wrap public key/);
    expect(calls).toBe(0);
  });

  it('surfaces the stable Cloud reason on rejection', async () => {
    const device = enrolledDevice();
    const wrap = generateRecoveryWrapKey(provider);
    const relay = client(async () => jsonResponse(410, {
      error: { code: 'not_found', message: 'latest trust grant is expired', reason: 'recovery_grant_expired', request_id: 'req_1' },
    }));
    const error = await relay.recoverCredentials(device, { idempotencyKey: KEY, wrapPublicKey: wrap.publicKey }).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(IscpError);
    expect((error as IscpError).details?.reason).toBe('recovery_grant_expired');
    expect((error as IscpError).details?.httpStatus).toBe('410');
  });

  describe('openRecoveredCredentials fail-closed matrix', () => {
    const device = enrolledDevice();
    const wrap = generateRecoveryWrapKey(provider);
    const pair = tokenPair(device);
    const identity = { domainId: DOMAIN_ID, deviceId: device.identity.device_id, thumbprint: device.identity.public_key.kid };
    const wrapped = sealPair(wrap.publicKey, identity, pair);
    const open = (blob: WrappedRecoveredCredentials, ident = identity, priv = wrap.privateKey, pub = wrap.publicKey) =>
      openRecoveredCredentials(provider, {
        wrapPrivateKey: priv,
        wrapPublicKey: pub,
        wrapped: blob,
        domainId: ident.domainId,
        deviceId: ident.deviceId,
        thumbprint: ident.thumbprint,
      });

    it('opens the untampered blob', () => {
      expect(open(wrapped).access.token).toBe('rac_recovered_access');
    });
    it('rejects a tampered ciphertext', () => {
      const raw = fromBase64Url(wrapped.ciphertext);
      raw[0]! ^= 0xff;
      expect(() => open({ ...wrapped, ciphertext: toBase64Url(raw) })).toThrow();
    });
    it('rejects a tampered nonce', () => {
      const raw = fromBase64Url(wrapped.nonce);
      raw[0]! ^= 0xff;
      expect(() => open({ ...wrapped, nonce: toBase64Url(raw) })).toThrow();
    });
    it('is transcript-bound: a different device or thumbprint fails authentication', () => {
      expect(() => open(wrapped, { ...identity, deviceId: 'dev_other' })).toThrow();
      expect(() => open(wrapped, { ...identity, thumbprint: 'thumb_other' })).toThrow();
    });
    it('rejects a blob sealed to a different wrap key', () => {
      const other = generateRecoveryWrapKey(provider);
      expect(() => open(wrapped, identity, other.privateKey, other.publicKey)).toThrow(/different wrap key/);
      // Matching echo but wrong private key: AEAD authentication fails.
      const forged = sealPair(other.publicKey, identity, pair);
      expect(() => open({ ...forged, recovery_public_key: wrap.publicKey }, identity)).toThrow();
    });
    it('rejects a wrong type or ciphersuite at the schema layer', () => {
      expect(() => open({ ...wrapped, type: 'iscp.other.v2' as never })).toThrow();
      expect(() => open({ ...wrapped, ciphersuite: 'NULL' as never })).toThrow();
    });
    it('cross-checks credential ids against the response metadata', () => {
      const opened = open(wrapped);
      expect(() => assertRecoveredPairMatchesMetadata(opened, {
        access: { ...metadataOf(pair).access, credential_id: 'cred_other' } as never,
        refresh: metadataOf(pair).refresh as never,
      })).toThrow(/do not match/);
    });
  });
});
