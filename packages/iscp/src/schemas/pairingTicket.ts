import * as z from 'zod';
import { Rfc3339Schema, SignatureSchema } from './common';

// $id: https://schemas.iscp.dev/json/pairing_ticket.v2.json

export const PAIRING_TICKET_TYPE = 'iscp.pairing_ticket.v2';

/** Short TTL, limited use, signed by issuer (spec/provisioning.md). */
export const PairingTicketSchema = z.strictObject({
  type: z.literal(PAIRING_TICKET_TYPE),
  ticket_id: z.string().min(1),
  domain_id: z.string().min(1),
  relay_id: z.string().min(1),
  trust_root_id: z.string().min(1),
  max_uses: z.number().int().min(1),
  issued_at: Rfc3339Schema,
  expires_at: Rfc3339Schema,
  signature: SignatureSchema,
});
export type PairingTicket = z.infer<typeof PairingTicketSchema>;

// $id: https://schemas.iscp.dev/json/pairing_ticket.v3.json

export const PAIRING_TICKET_V3_TYPE = 'iscp.pairing_ticket.v3';

/**
 * ISCP v0.2 ticket (spec/provisioning.md): additionally binds the enrollment
 * purpose, the intended consumer role, the inviting controller
 * (grant_audience), and the grant constraints into the signed object, so a
 * ticket issued for one enrollment direction cannot be consumed in the other.
 */
export const PairingTicketV3Schema = z.strictObject({
  type: z.literal(PAIRING_TICKET_V3_TYPE),
  ticket_id: z.string().min(1),
  domain_id: z.string().min(1),
  relay_id: z.string().min(1),
  trust_root_id: z.string().min(1),
  purpose: z.literal('invite'),
  consumer_role: z.string().min(1),
  grant_audience: z.string().min(1),
  grant_permissions: z.array(z.string().min(1)).min(1),
  grant_ttl_seconds: z.number().int().min(1).optional(),
  max_uses: z.number().int().min(1),
  issued_at: Rfc3339Schema,
  expires_at: Rfc3339Schema,
  signature: SignatureSchema,
});
export type PairingTicketV3 = z.infer<typeof PairingTicketV3Schema>;

/** Either ticket version; discriminated by the `type` field. */
export const AnyPairingTicketSchema = z.discriminatedUnion('type', [PairingTicketSchema, PairingTicketV3Schema]);
export type AnyPairingTicket = z.infer<typeof AnyPairingTicketSchema>;
