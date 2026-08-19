/**
 * Existing-device relay credential recovery — client side of the frozen
 * Infinimesh Cloud contract (docs/10-design/12-managed-provisioning.md §11;
 * upstream protocol gap filed as Infinimesh-ai/ISCP#11).
 *
 * A device whose refresh bearer reached a terminal state (expired past the
 * 24h TTL, revoked chain, lost local state) recovers a fresh access/refresh
 * pair with a possession proof over its enrolled key plus a currently valid
 * Trust Grant. No OAuth bearer, no old refresh bearer, no new device, no key
 * change — and on ANY failure the caller must never fall back to
 * enroll/replace.
 *
 * Token plaintext travels only inside `credentials_wrapped`, sealed to a
 * per-attempt X25519 wrap key:
 *
 *   secret     = X25519(wrap_private, server_ephemeral_public)
 *   transcript = "iscp/v2/relay/credential-recovery" \0 domain \0 device \0 thumbprint
 *   key        = HKDF-SHA256(secret, salt = ∅, info = transcript ‖ client_pub ‖ server_pub, 32)
 *   plaintext  = ChaCha20-Poly1305.open(key, nonce, ciphertext, aad = transcript)
 *
 * The proof challenge binds both the attempt and the delivery target:
 * `<Idempotency-Key> \0 <wrap public key (base64url)>` — swapping the wrap
 * key invalidates the signature. Unknown-outcome retries MUST resend the
 * same key, wrap key, and proof verbatim; the Cloud replays the stored
 * response (ciphertext only), which the persisted wrap private key opens.
 */

import { fromBase64Url, toBase64Url, utf8Encode } from '../encoding';
import { IscpErrorCodes, iscpError } from '../errors';
import type { CryptoProvider, X25519PrivateKey } from '../crypto/provider';
import { CIPHERSUITE_V2, X25519PublicKey } from '../crypto/provider';
import * as z from 'zod';

export const CREDENTIAL_RECOVERY_WRAPPED_TYPE = 'iscp.relay.credential_recovery.wrapped.v2';

const RECOVERY_TRANSCRIPT_LABEL = 'iscp/v2/relay/credential-recovery';

/** Sealed-response blob (frozen §11.4 wire shape). Safe to persist verbatim. */
export const WrappedRecoveredCredentialsSchema = z.object({
  type: z.literal(CREDENTIAL_RECOVERY_WRAPPED_TYPE),
  ciphersuite: z.literal(CIPHERSUITE_V2),
  recovery_public_key: z.string().min(1),
  server_public_key: z.string().min(1),
  nonce: z.string().min(1),
  ciphertext: z.string().min(1),
});
export type WrappedRecoveredCredentials = z.infer<typeof WrappedRecoveredCredentialsSchema>;

/**
 * Cleartext, token-free credential metadata. Carries the full
 * issued/expires/rotation facts the client must persist so local state never
 * drifts from the server's actual expiry again (OPS 2026-08-18 §8.2.4).
 */
export const RecoveredCredentialMetadataSchema = z.looseObject({
  credential_id: z.string().min(1),
  domain_id: z.string().min(1),
  device_id: z.string().min(1),
  issued_at: z.string().min(1),
  expires_at: z.string().min(1),
  rotation_counter: z.number().int().optional(),
  audience: z.string().optional(),
  scope: z.array(z.string()).optional(),
});
export type RecoveredCredentialMetadata = z.infer<typeof RecoveredCredentialMetadataSchema>;

/** One sealed credential as opened from the ciphertext (token present). */
export const RecoveredTokenSchema = z.looseObject({
  credential_id: z.string().min(1),
  token: z.string().min(1),
  domain_id: z.string().min(1),
  device_id: z.string().min(1),
  issued_at: z.string().min(1),
  expires_at: z.string().min(1),
  rotation_counter: z.number().int().optional(),
});
export type RecoveredToken = z.infer<typeof RecoveredTokenSchema>;

export const RecoveredCredentialPairSchema = z.object({
  access: RecoveredTokenSchema,
  refresh: RecoveredTokenSchema,
});
export type RecoveredCredentialPair = z.infer<typeof RecoveredCredentialPairSchema>;

/**
 * Possession-proof challenge for credential recovery: the Idempotency-Key
 * plus the wrap key the credentials will be sealed to.
 */
export function recoveryChallenge(idempotencyKey: string, wrapPublicKey: string): string {
  return `${idempotencyKey}\0${wrapPublicKey}`;
}

/** Fresh per-attempt X25519 wrap key pair; the private key never travels. */
export function generateRecoveryWrapKey(provider: CryptoProvider): { privateKey: X25519PrivateKey; publicKey: string } {
  const pair = provider.generateSessionKeyPair();
  return { privateKey: pair.privateKey, publicKey: toBase64Url(pair.publicKey.bytes) };
}

function recoveryTranscript(domainId: string, deviceId: string, thumbprint: string): Uint8Array {
  return utf8Encode(`${RECOVERY_TRANSCRIPT_LABEL}\0${domainId}\0${deviceId}\0${thumbprint}`);
}

/**
 * Open the sealed credential pair. Fail-closed on any mismatch: wrong type
 * or ciphersuite, a wrap-key echo that differs from ours, AEAD
 * authentication failure (tampered ciphertext/nonce, wrong identity
 * binding), or a plaintext that does not carry both tokens.
 */
export function openRecoveredCredentials(
  provider: CryptoProvider,
  opts: {
    wrapPrivateKey: X25519PrivateKey;
    /** The base64url wrap public key exactly as sent in the request. */
    wrapPublicKey: string;
    wrapped: WrappedRecoveredCredentials;
    domainId: string;
    deviceId: string;
    /** The enrolled key thumbprint (device identity kid). */
    thumbprint: string;
  },
): RecoveredCredentialPair {
  const wrapped = WrappedRecoveredCredentialsSchema.parse(opts.wrapped);
  if (wrapped.recovery_public_key !== opts.wrapPublicKey) {
    throw iscpError(IscpErrorCodes.AccessInvalid, 'recovered credentials are sealed to a different wrap key');
  }
  const serverPublic = new X25519PublicKey(fromBase64Url(wrapped.server_public_key));
  const secret = provider.sharedSecret(opts.wrapPrivateKey, serverPublic);
  const transcript = recoveryTranscript(opts.domainId, opts.deviceId, opts.thumbprint);
  const clientPublic = fromBase64Url(opts.wrapPublicKey);
  const info = new Uint8Array(transcript.length + clientPublic.length + serverPublic.bytes.length);
  info.set(transcript, 0);
  info.set(clientPublic, transcript.length);
  info.set(serverPublic.bytes, transcript.length + clientPublic.length);
  const key = provider.hkdfSha256(secret, new Uint8Array(0), info, 32);
  const plaintext = provider.open(key, fromBase64Url(wrapped.nonce), fromBase64Url(wrapped.ciphertext), transcript);
  const pair = RecoveredCredentialPairSchema.parse(JSON.parse(new TextDecoder().decode(plaintext)));
  if (pair.access.token === '' || pair.refresh.token === '') {
    throw iscpError(IscpErrorCodes.AccessInvalid, 'recovered credential pair is missing tokens');
  }
  return pair;
}

/**
 * Cross-check the opened pair against the cleartext metadata: the sealed
 * tokens must belong to exactly the credentials the response announced.
 */
export function assertRecoveredPairMatchesMetadata(
  pair: RecoveredCredentialPair,
  metadata: { access: RecoveredCredentialMetadata; refresh: RecoveredCredentialMetadata },
): void {
  if (pair.access.credential_id !== metadata.access.credential_id ||
    pair.refresh.credential_id !== metadata.refresh.credential_id) {
    throw iscpError(IscpErrorCodes.AccessInvalid, 'recovered credential ids do not match the response metadata');
  }
}
