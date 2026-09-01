import * as z from 'zod';

import { Rfc3339Schema, SignatureSchema } from './common';

/**
 * Authenticated session-reopen control frame. Originally a Happy-layer
 * convention, codified as normative in ISCP v0.2 (spec/session.md,
 * schemas/json/session.reopen.v1.json).
 *
 * This is intentionally not a Session Hello: responder-only phones do not
 * possess the Happy grant id. The phone signs a short-lived request with its
 * durable device identity; the grant-authorized Happy initiator validates it
 * and creates the fresh Hello/transcript.
 */
export const SESSION_REOPEN_TYPE = 'iscp.session.reopen.v1';

export const SessionReopenCauseSchema = z.enum([
  'runtime_started',
  'foreground_recovery',
]);
export type SessionReopenCause = z.infer<typeof SessionReopenCauseSchema>;

export const SessionReopenSchema = z.strictObject({
  type: z.literal(SESSION_REOPEN_TYPE),
  request_id: z.string().min(1),
  domain_id: z.string().min(1),
  device_id: z.string().min(1),
  peer_device_id: z.string().min(1),
  relay_id: z.string().min(1),
  cause: SessionReopenCauseSchema,
  issued_at: Rfc3339Schema,
  expires_at: Rfc3339Schema,
  nonce: z.string().min(16),
  signature: SignatureSchema,
});
export type SessionReopen = z.infer<typeof SessionReopenSchema>;
