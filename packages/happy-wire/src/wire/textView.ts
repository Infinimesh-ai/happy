import * as z from 'zod';
import { sessionEnvelopeSchema } from '../sessionProtocol';
import { UserMessageSchema } from '../legacyProtocol';

/**
 * happy/phone-text-view.v3 — the versioned phone-facing projection of a
 * session's history (OPS 2026-08-18 §10.16).
 *
 * The daemon event log stores Happy's internal session protocol verbatim
 * (turn/service/usage/ready envelopes). That protocol is frozen with a
 * "consumers must normalize, do not add new consumers" contract — so a peer
 * whose Trust Grant only carries the `text` permission must never see it.
 * This module defines what such a peer IS allowed to see (plain user/agent
 * text bubbles plus redacted approval lifecycle cards) and the single pure
 * projector that both messages.pull and live happy/wire-event.v1 pushes go
 * through.
 *
 * Fail-closed by construction: anything the projector does not positively
 * recognize as visible text is dropped with a machine-readable kind/reason —
 * never stringified into a fake chat message. Projection output is validated
 * against PhoneTextViewBodySchema at the responder edge as well.
 */

export const PHONE_TEXT_VIEW_PROTOCOL = 'happy/phone-text-view.v3';

/**
 * A grant permission that authorizes the raw internal session protocol.
 * Today no production grant carries it (phones are enrolled with ['text']);
 * the official Happy app's ISCP transport is the intended future holder.
 * Anything else — including unknown future permissions — projects to the
 * text view (fail-closed).
 */
export const RAW_SESSION_PROTOCOL_PERMISSION = 'happy.raw-session';

export type WireHistoryView = 'raw' | 'text';

export function wireViewForPermissions(permissions: readonly string[]): WireHistoryView {
  return permissions.includes(RAW_SESSION_PROTOCOL_PERMISSION) ? 'raw' : 'text';
}

export const PhoneTextViewUserBodySchema = z.object({
  role: z.literal('user'),
  content: z.object({ type: z.literal('text'), text: z.string().min(1) }),
  /** Preserved from the originating send so optimistic bubbles reconcile. */
  localKey: z.string().optional(),
});
export type PhoneTextViewUserBody = z.infer<typeof PhoneTextViewUserBodySchema>;

export const PhoneTextViewApprovalStatusSchema = z.enum(['pending', 'approved', 'denied', 'cancelled']);
export type PhoneTextViewApprovalStatus = z.infer<typeof PhoneTextViewApprovalStatusSchema>;

export const PhoneTextViewApprovalIdSchema = z.string().uuid();

export const PhoneTextViewAgentContentSchema = z.discriminatedUnion('type', [
  z.object({ type: z.literal('text'), text: z.string().min(1) }),
  z.object({
    type: z.literal('approval-reset'),
    reason: z.literal('agent-restarted'),
  }),
  z.object({
    type: z.literal('approval'),
    approvalId: PhoneTextViewApprovalIdSchema,
    toolName: z.string().min(1).max(160),
    status: PhoneTextViewApprovalStatusSchema,
    /** Legacy commands keep build 19 usable while v3 clients roll out. */
    approveCommand: z.literal('/approve').optional(),
    denyCommand: z.literal('/deny').optional(),
    /** v3 commands bind the action to one opaque, session-local approval. */
    targetedApproveCommand: z.string().min(1).max(64).optional(),
    targetedDenyCommand: z.string().min(1).max(64).optional(),
  }).superRefine((content, ctx) => {
    const commands = [
      content.approveCommand,
      content.denyCommand,
      content.targetedApproveCommand,
      content.targetedDenyCommand,
    ];
    const hasCommands = commands.every((command) => command !== undefined);
    if (content.status === 'pending') {
      if (!hasCommands) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'pending approvals require all commands' });
      }
      if (content.targetedApproveCommand !== `/approve ${content.approvalId}`) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'approve command must match approvalId' });
      }
      if (content.targetedDenyCommand !== `/deny ${content.approvalId}`) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'deny command must match approvalId' });
      }
    }
    if (content.status !== 'pending' && commands.some((command) => command !== undefined)) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'completed approvals cannot carry commands' });
    }
  }),
]);
export type PhoneTextViewAgentContent = z.infer<typeof PhoneTextViewAgentContentSchema>;

export const PhoneTextViewAgentBodySchema = z.object({
  role: z.literal('agent'),
  content: PhoneTextViewAgentContentSchema,
});
export type PhoneTextViewAgentBody = z.infer<typeof PhoneTextViewAgentBodySchema>;

export const PhoneTextViewBodySchema = z.discriminatedUnion('role', [
  PhoneTextViewUserBodySchema,
  PhoneTextViewAgentBodySchema,
]);
export type PhoneTextViewBody = z.infer<typeof PhoneTextViewBodySchema>;

/**
 * Result of projecting one raw event-log body. `kind` is a stable input
 * classification for diagnostics (logged without the body); exactly one of
 * emit/drop applies.
 */
export type PhoneTextViewProjection =
  | { emit: PhoneTextViewBody; kind: string }
  | { emit: null; kind: string; dropReason: string };

const RawSessionMessageSchema = z.object({
  role: z.literal('session'),
  content: sessionEnvelopeSchema,
});

const RawLegacyAgentMessageSchema = z.object({
  role: z.literal('agent'),
  content: z.object({ type: z.string() }).passthrough(),
});

/**
 * Daemon-local control record emitted only by an ISCP session process. It is
 * never written to the legacy Happy server. The record deliberately carries
 * no provider arguments or call id. `approvalId` is a freshly generated,
 * opaque correlation token with no provider semantics: a text grant may
 * learn which card is waiting and answer exactly that card, but cannot inspect
 * the internal agent-state protocol.
 */
export const RawPhoneApprovalBodySchema = z.object({
  role: z.literal('happy-control'),
  content: z.object({
    type: z.literal('approval'),
    approvalId: PhoneTextViewApprovalIdSchema,
    toolName: z.string().min(1).max(160),
    status: PhoneTextViewApprovalStatusSchema,
  }),
});
export type RawPhoneApprovalBody = z.infer<typeof RawPhoneApprovalBodySchema>;

export const RawPhoneApprovalResetBodySchema = z.object({
  role: z.literal('happy-control'),
  content: z.object({
    type: z.literal('approval-reset'),
    reason: z.literal('agent-restarted'),
  }),
});

function drop(kind: string, dropReason: string): PhoneTextViewProjection {
  return { emit: null, kind, dropReason };
}

/**
 * Pure projector: internal event-log body → phone text view body (or a
 * classified drop). Both history pulls and live pushes MUST use this — the
 * two paths sharing one projector is a frozen contract requirement.
 */
export function projectPhoneTextView(rawBody: unknown): PhoneTextViewProjection {
  const user = UserMessageSchema.safeParse(rawBody);
  if (user.success) {
    if (user.data.content.text === '') return drop('user-text', 'empty text');
    return {
      kind: 'user-text',
      emit: {
        role: 'user',
        content: { type: 'text', text: user.data.content.text },
        ...(user.data.localKey !== undefined ? { localKey: user.data.localKey } : {}),
      },
    };
  }

  const approval = RawPhoneApprovalBodySchema.safeParse(rawBody);
  if (approval.success) {
    const { approvalId, toolName, status } = approval.data.content;
    return {
      kind: `phone-approval-${status}`,
      emit: {
        role: 'agent',
        content: {
          type: 'approval',
          approvalId,
          toolName,
          status,
          ...(status === 'pending'
            ? {
                approveCommand: '/approve' as const,
                denyCommand: '/deny' as const,
                targetedApproveCommand: `/approve ${approvalId}`,
                targetedDenyCommand: `/deny ${approvalId}`,
              }
            : {}),
        },
      },
    };
  }

  const approvalReset = RawPhoneApprovalResetBodySchema.safeParse(rawBody);
  if (approvalReset.success) {
    return {
      kind: 'phone-approval-reset',
      emit: {
        role: 'agent',
        content: { type: 'approval-reset', reason: 'agent-restarted' },
      },
    };
  }

  const session = RawSessionMessageSchema.safeParse(rawBody);
  if (session.success) {
    const envelope = session.data.content;
    const kind = `session-${envelope.ev.t}`;
    // Includes failed/cancelled turn-ends and non-empty service text: if the
    // product ever needs those on the phone they must travel as an explicit,
    // separately versioned status event — never disguised as an agent reply.
    if (envelope.ev.t !== 'text') return drop(kind, 'internal protocol event');
    if (envelope.role !== 'agent') {
      // User text authority is the ingested send (same localId); an envelope
      // echo would duplicate the bubble.
      return drop('session-user-text', 'user echo — send is authoritative');
    }
    if (envelope.ev.thinking === true) return drop('session-thinking', 'thinking text');
    if (envelope.subagent !== undefined) return drop('session-subagent-text', 'subagent internal text');
    if (envelope.ev.text === '') return drop(kind, 'empty text');
    return { kind, emit: { role: 'agent', content: { type: 'text', text: envelope.ev.text } } };
  }

  const legacy = RawLegacyAgentMessageSchema.safeParse(rawBody);
  if (legacy.success) {
    // 'event' (ready), 'output', 'codex', 'acp', …: pre-envelope internal
    // agent formats. Never chat content.
    return drop(`legacy-agent-${legacy.data.content.type}`, 'legacy internal agent message');
  }

  return drop('unknown', 'unrecognized event-log body');
}
