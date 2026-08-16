/** Pairing Ticket sign/verify (spec/provisioning.md). Short TTL, limited use. */

import * as z from 'zod';

import { fromBase64Url, parseRfc3339, toBase64Url, utf8Decode, utf8Encode } from '../encoding';
import { IscpErrorCodes, iscpError } from '../errors';
import type { Device } from '../identity';
import { signObject, verifyObjectSignature } from '../signing';
import type { CryptoProvider } from '../crypto/provider';
import { PAIRING_TICKET_TYPE, PairingTicketSchema, type PairingTicket } from '../schemas';

export function signPairingTicket(
  provider: CryptoProvider,
  issuer: Device,
  ticket: Omit<PairingTicket, 'type' | 'signature'>,
): PairingTicket {
  const unsigned = { ...ticket, type: PAIRING_TICKET_TYPE };
  return signObject(provider, PAIRING_TICKET_TYPE, unsigned, issuer.privateKey, issuer.identity.public_key.kid) as PairingTicket;
}

export function verifyPairingTicket(
  provider: CryptoProvider,
  ticket: PairingTicket,
  issuerPublicKeyBase64Url: string,
  now: Date = new Date(),
): void {
  const parsed = PairingTicketSchema.parse(ticket);
  const nowMs = now.getTime();
  if (nowMs < parseRfc3339(parsed.issued_at).getTime() || nowMs >= parseRfc3339(parsed.expires_at).getTime()) {
    throw iscpError(IscpErrorCodes.ProvisionInvalid, 'pairing ticket expired');
  }
  verifyObjectSignature(provider, PAIRING_TICKET_TYPE, parsed, issuerPublicKeyBase64Url, IscpErrorCodes.ProvisionInvalid, 'pairing ticket signature failed');
}

/**
 * Encode/decode a ticket for QR/deep-link transport
 * (happy://iscp-enroll?ticket=...): unpadded base64url over the ticket JSON.
 */
export function encodeTicketForTransport(ticket: PairingTicket): string {
  return toBase64Url(utf8Encode(JSON.stringify(ticket)));
}

export function decodeTicketFromTransport(encoded: string): PairingTicket {
  let parsed: unknown;
  try {
    parsed = JSON.parse(utf8Decode(fromBase64Url(encoded)));
  } catch (cause) {
    throw iscpError(IscpErrorCodes.ProvisionInvalid, 'invalid ticket encoding', { cause });
  }
  return PairingTicketSchema.parse(parsed);
}

// ---------------------------------------------------------------------------
// Enrollment transport wrapper (Infinimesh Cloud managed provisioning, OPS
// 2026-08-16 §5.5; format aligned with JingSi-iOS + Cloud Console).
//
// Console / JingSi emit base64url(JSON) of an object that wraps the signed
// ticket with routing hints (deep link: happy://iscp-enroll?payload=...).
// The wrapper is transport-only: it never alters the signed ticket and
// carries no token, credential, or private key.
// ---------------------------------------------------------------------------

/**
 * `{"version":1,"ticket":<signed PairingTicket>,"expected_audience_phone_id":
 * "dev_...","display_name":"..."}`. `version` is optional on parse and
 * unknown fields are stripped, not rejected, so older/newer emitters keep
 * decoding; detection is by the `ticket` field (bare tickets carry
 * `ticket_id` at the top level instead).
 */
export const EnrollmentWrapperSchema = z.object({
  version: z.literal(1).optional(),
  ticket: PairingTicketSchema,
  expected_audience_phone_id: z.string().min(1).optional(),
  display_name: z.string().min(1).optional(),
});
export type EnrollmentWrapper = z.infer<typeof EnrollmentWrapperSchema>;

/** Decoded enrollment transport payload: the signed ticket plus wrapper hints. */
export interface EnrollmentTransportPayload {
  ticket: PairingTicket;
  /** The phone device id the issued grant's audience must match, when known. */
  expectedAudiencePhoneId?: string;
  displayName?: string;
  /** True when the input was the Console/JingSi wrapper (vs a bare ticket). */
  fromWrapper?: boolean;
}

/** True when a decoded JSON object should be treated as an enrollment wrapper. */
export function isEnrollmentWrapper(value: unknown): boolean {
  if (typeof value !== 'object' || value === null) return false;
  return 'ticket' in (value as Record<string, unknown>);
}

/** Parse an already-decoded JSON object: wrapper (has `ticket`) or bare signed ticket (has `ticket_id`). */
export function enrollmentPayloadFromObject(value: unknown): EnrollmentTransportPayload {
  if (isEnrollmentWrapper(value)) {
    const wrapper = EnrollmentWrapperSchema.parse(value);
    return {
      ticket: wrapper.ticket,
      fromWrapper: true,
      ...(wrapper.expected_audience_phone_id !== undefined ? { expectedAudiencePhoneId: wrapper.expected_audience_phone_id } : {}),
      ...(wrapper.display_name !== undefined ? { displayName: wrapper.display_name } : {}),
    };
  }
  return { ticket: PairingTicketSchema.parse(value) };
}

/**
 * Decode a QR/deep-link/copy-paste enrollment payload: base64url(JSON) of
 * either the wrapper or a bare signed ticket (encodeTicketForTransport).
 */
export function decodeEnrollmentFromTransport(encoded: string): EnrollmentTransportPayload {
  let parsed: unknown;
  try {
    parsed = JSON.parse(utf8Decode(fromBase64Url(encoded)));
  } catch (cause) {
    throw iscpError(IscpErrorCodes.ProvisionInvalid, 'invalid enrollment payload encoding', { cause });
  }
  return enrollmentPayloadFromObject(parsed);
}

/** Encode a wrapper for transport (used by fixtures/tests; production wrappers come from Console/JingSi). */
export function encodeEnrollmentWrapperForTransport(payload: EnrollmentTransportPayload): string {
  const wrapper: EnrollmentWrapper = {
    version: 1,
    ticket: payload.ticket,
    ...(payload.expectedAudiencePhoneId !== undefined ? { expected_audience_phone_id: payload.expectedAudiencePhoneId } : {}),
    ...(payload.displayName !== undefined ? { display_name: payload.displayName } : {}),
  };
  return toBase64Url(utf8Encode(JSON.stringify(wrapper)));
}
