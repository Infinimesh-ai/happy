import * as z from 'zod';

import { Rfc3339Schema, SignatureSchema } from './common';

/**
 * Optional deliberate session teardown (ISCP v0.2 spec/session.md,
 * schemas/json/session.close.v1.json). Envelope-shaped transport like the
 * reopen frame; receivers that verify a close MUST tear down the named
 * session, but MUST NOT require one to recover from a vanished peer.
 */
export const SESSION_CLOSE_TYPE = 'iscp.session.close.v1';

export const SessionCloseReasonSchema = z.enum([
  'shutdown',
  'superseded',
  'revoked',
  'error',
]);
export type SessionCloseReason = z.infer<typeof SessionCloseReasonSchema>;

export const SessionCloseSchema = z.strictObject({
  type: z.literal(SESSION_CLOSE_TYPE),
  session_id: z.string().min(1),
  domain_id: z.string().min(1),
  device_id: z.string().min(1),
  peer_device_id: z.string().min(1),
  relay_id: z.string().min(1),
  reason: SessionCloseReasonSchema,
  issued_at: Rfc3339Schema,
  expires_at: Rfc3339Schema,
  nonce: z.string().min(16),
  signature: SignatureSchema,
});
export type SessionClose = z.infer<typeof SessionCloseSchema>;
