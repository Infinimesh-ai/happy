/**
 * ISCP v0.2 cross-implementation vectors (test/vectors/v02.json, generated
 * from the pinned Go SDK): pairing ticket v3 with grant role invariants, the
 * codified session reopen/close control frames, and the credential recovery
 * sealing format. Byte-compatibility here is what lets the Go sparkclaw
 * bridge, this TS stack, and the Swift JingSi stack interoperate.
 */

import { describe, expect, it } from 'vitest';

import { createNobleProvider } from '../crypto/noble';
import { X25519PrivateKey } from '../crypto/provider';
import { fromHex } from '../encoding';
import { IscpErrorCodes } from '../errors';
import { WrappedRecoveredCredentialsSchema, openRecoveredCredentials, recoveryChallenge } from '../relay/recoverCredentials';
import { bindGrantRoles, verifyPairingTicketV3 } from '../provisioning';
import { verifyObjectSignature } from '../signing';
import {
  SESSION_CLOSE_TYPE,
  SESSION_REOPEN_TYPE,
  SessionCloseSchema,
  SessionReopenSchema,
  type DeviceIdentity,
  type PairingTicketV3,
  type SessionClose,
  type SessionReopen,
} from '../schemas';
import { loadVectors, type VectorMeta } from './vectors';

interface V02Vectors {
  meta: VectorMeta;
  issuer: { seed_hex: string; identity: DeviceIdentity };
  phone: { seed_hex: string; identity: DeviceIdentity };
  agent: { seed_hex: string; identity: DeviceIdentity };
  ticket_v3: {
    ticket: PairingTicketV3;
    verify_at: string;
    grant_role_bindings: {
      subject_device_id: string;
      confirmation_thumbprint: string;
      audience: string;
      permissions: string[];
      relay_id: string;
    };
    audience_reversal_consumer: string;
  };
  session_reopen: { frame: SessionReopen; verify_at: string };
  session_close: { frame: SessionClose; verify_at: string };
  credential_recovery: {
    wrap_private_hex: string;
    wrap_public: string;
    transcript: { domain_id: string; device_id: string; thumbprint: string };
    wrapped: unknown;
    plaintext_hex: string;
    challenge_sample: { idempotency_key: string; wrap_public: string; challenge: string };
  };
}

const provider = createNobleProvider();
const vectors = loadVectors<V02Vectors>('v02.json');

describe('pairing ticket v3 conformance', () => {
  const verifyAt = new Date(vectors.ticket_v3.verify_at);

  it('verifies the Go-signed v3 ticket byte-for-byte', () => {
    verifyPairingTicketV3(provider, vectors.ticket_v3.ticket, vectors.issuer.identity.public_key.public, verifyAt);
  });

  it('rejects a tampered grant binding', () => {
    const tampered = { ...vectors.ticket_v3.ticket, grant_audience: 'attacker' };
    expect(() => verifyPairingTicketV3(provider, tampered, vectors.issuer.identity.public_key.public, verifyAt)).toThrowError();
  });

  it('derives the same grant role bindings as the Go SDK', () => {
    const bindings = bindGrantRoles(provider, vectors.ticket_v3.ticket, vectors.agent.identity);
    expect(bindings.subjectDeviceId).toBe(vectors.ticket_v3.grant_role_bindings.subject_device_id);
    expect(bindings.confirmationThumbprint).toBe(vectors.ticket_v3.grant_role_bindings.confirmation_thumbprint);
    expect(bindings.audience).toBe(vectors.ticket_v3.grant_role_bindings.audience);
    expect(bindings.permissions).toEqual(vectors.ticket_v3.grant_role_bindings.permissions);
    expect(bindings.relayId).toBe(vectors.ticket_v3.grant_role_bindings.relay_id);
  });

  it('rejects the audience-reversal consumer', () => {
    expect(vectors.phone.identity.device_id).toBe(vectors.ticket_v3.audience_reversal_consumer);
    expect(() => bindGrantRoles(provider, vectors.ticket_v3.ticket, vectors.phone.identity)).toThrowError();
  });
});

describe('session control frame conformance', () => {
  it('parses and verifies the Go-signed reopen frame', () => {
    const frame = SessionReopenSchema.parse(vectors.session_reopen.frame);
    verifyObjectSignature(provider, SESSION_REOPEN_TYPE, frame, vectors.phone.identity.public_key.public, IscpErrorCodes.TrustInvalid, 'reopen signature failed');
  });

  it('parses and verifies the Go-signed close frame', () => {
    const frame = SessionCloseSchema.parse(vectors.session_close.frame);
    verifyObjectSignature(provider, SESSION_CLOSE_TYPE, frame, vectors.agent.identity.public_key.public, IscpErrorCodes.TrustInvalid, 'close signature failed');
  });

  it('rejects a tampered cause', () => {
    const tampered = SessionReopenSchema.parse({ ...vectors.session_reopen.frame, cause: 'foreground_recovery' });
    expect(() => verifyObjectSignature(provider, SESSION_REOPEN_TYPE, tampered, vectors.phone.identity.public_key.public, IscpErrorCodes.TrustInvalid, 'reopen signature failed')).toThrowError();
  });
});

describe('credential recovery sealing conformance', () => {
  const rec = vectors.credential_recovery;

  it('opens the Go-sealed credential pair', () => {
    const pair = openRecoveredCredentials(provider, {
      wrapPrivateKey: new X25519PrivateKey(fromHex(rec.wrap_private_hex)),
      wrapPublicKey: rec.wrap_public,
      wrapped: WrappedRecoveredCredentialsSchema.parse(rec.wrapped),
      domainId: rec.transcript.domain_id,
      deviceId: rec.transcript.device_id,
      thumbprint: rec.transcript.thumbprint,
    });
    const expected = JSON.parse(new TextDecoder().decode(fromHex(rec.plaintext_hex))) as { access: { token: string }; refresh: { token: string } };
    expect(pair.access.token).toBe(expected.access.token);
    expect(pair.refresh.token).toBe(expected.refresh.token);
  });

  it('fails closed when the blob is bound to another identity', () => {
    expect(() => openRecoveredCredentials(provider, {
      wrapPrivateKey: new X25519PrivateKey(fromHex(rec.wrap_private_hex)),
      wrapPublicKey: rec.wrap_public,
      wrapped: WrappedRecoveredCredentialsSchema.parse(rec.wrapped),
      domainId: rec.transcript.domain_id,
      deviceId: 'other-device',
      thumbprint: rec.transcript.thumbprint,
    })).toThrowError();
  });

  it('matches the Go challenge concatenation rule', () => {
    expect(recoveryChallenge(rec.challenge_sample.idempotency_key, rec.challenge_sample.wrap_public)).toBe(rec.challenge_sample.challenge);
  });
});
