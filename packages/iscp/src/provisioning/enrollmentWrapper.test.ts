/**
 * Enrollment transport wrapper (Infinimesh Cloud managed provisioning,
 * OPS 2026-08-16 §5.5, format aligned with JingSi-iOS + Cloud Console):
 * base64url(JSON) `{"version":1,"ticket":...,"expected_audience_phone_id":
 * ...,"display_name":...}`, backward compatible with the bare-ticket
 * transport encoding (detected by top-level `ticket_id`).
 */

import { describe, expect, it } from 'vitest';

import { loadVectors, type VectorMeta } from '../conformance/vectors';
import { toBase64Url, utf8Encode } from '../encoding';
import { IscpError } from '../errors';
import type { DeviceIdentity, PairingTicket } from '../schemas';
import {
  decodeEnrollmentFromTransport,
  encodeEnrollmentWrapperForTransport,
  encodeTicketForTransport,
  enrollmentPayloadFromObject,
  isEnrollmentWrapper,
} from './pairingTicket';

interface ProvisioningVectors {
  meta: VectorMeta;
  issuer: { seed_hex: string; identity: DeviceIdentity };
  ticket: PairingTicket;
}

const vectors = loadVectors<ProvisioningVectors>('provisioning.json');
const ticket = vectors.ticket;

describe('enrollment wrapper transport', () => {
  it('round-trips a full wrapper (ticket untouched, hints preserved)', () => {
    const encoded = encodeEnrollmentWrapperForTransport({
      ticket,
      expectedAudiencePhoneId: 'dev_phone_123',
      displayName: 'Chiiz workstation',
    });
    const payload = decodeEnrollmentFromTransport(encoded);
    expect(payload.ticket).toEqual(ticket);
    expect(payload.expectedAudiencePhoneId).toBe('dev_phone_123');
    expect(payload.displayName).toBe('Chiiz workstation');
    expect(payload.fromWrapper).toBe(true);
  });

  it('encodes the JingSi/Console field names: version, no kind', () => {
    const encoded = encodeEnrollmentWrapperForTransport({ ticket, expectedAudiencePhoneId: 'dev_p', displayName: 'd' });
    const raw = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8')) as Record<string, unknown>;
    expect(Object.keys(raw).sort()).toEqual(['display_name', 'expected_audience_phone_id', 'ticket', 'version']);
    expect(raw.version).toBe(1);
  });

  it('decodes a wrapper without optional hints', () => {
    const encoded = toBase64Url(utf8Encode(JSON.stringify({ version: 1, ticket })));
    const payload = decodeEnrollmentFromTransport(encoded);
    expect(payload.ticket).toEqual(ticket);
    expect(payload.expectedAudiencePhoneId).toBeUndefined();
    expect(payload.displayName).toBeUndefined();
    expect(payload.fromWrapper).toBe(true);
  });

  it('treats any object with a ticket field as a wrapper (even without version)', () => {
    const encoded = toBase64Url(utf8Encode(JSON.stringify({ ticket, expected_audience_phone_id: 'dev_p' })));
    const payload = decodeEnrollmentFromTransport(encoded);
    expect(payload.ticket).toEqual(ticket);
    expect(payload.expectedAudiencePhoneId).toBe('dev_p');
  });

  it('tolerates unknown wrapper fields (forward compatibility)', () => {
    const encoded = toBase64Url(utf8Encode(JSON.stringify({
      version: 1, ticket, future_field: { nested: true }, kind: 'legacy_marker',
    })));
    expect(decodeEnrollmentFromTransport(encoded).ticket).toEqual(ticket);
  });

  it('still decodes the legacy bare-ticket transport encoding (top-level ticket_id)', () => {
    const payload = decodeEnrollmentFromTransport(encodeTicketForTransport(ticket));
    expect(payload.ticket).toEqual(ticket);
    expect(payload.expectedAudiencePhoneId).toBeUndefined();
    expect(payload.displayName).toBeUndefined();
    expect(payload.fromWrapper).toBeUndefined();
  });

  it('parses wrapper and bare-ticket JSON objects directly', () => {
    expect(enrollmentPayloadFromObject({ ticket }).ticket).toEqual(ticket);
    expect(enrollmentPayloadFromObject(ticket).ticket).toEqual(ticket);
    expect(isEnrollmentWrapper({ ticket })).toBe(true);
    expect(isEnrollmentWrapper(ticket)).toBe(false);
  });

  it('rejects garbage encodings', () => {
    expect(() => decodeEnrollmentFromTransport('%%not-base64url%%')).toThrowError(IscpError);
    expect(() => decodeEnrollmentFromTransport(toBase64Url(utf8Encode('not json')))).toThrowError(IscpError);
  });

  it('rejects a wrapper whose ticket does not match the schema', () => {
    const { signature: _sig, ...missingSignature } = ticket;
    const encoded = toBase64Url(utf8Encode(JSON.stringify({ version: 1, ticket: missingSignature })));
    expect(() => decodeEnrollmentFromTransport(encoded)).toThrowError();
  });
});
