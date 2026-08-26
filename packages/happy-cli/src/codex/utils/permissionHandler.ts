/**
 * Codex Permission Handler
 *
 * Handles tool permission requests and responses for Codex sessions.
 * Extends BasePermissionHandler with Codex-specific configuration.
 */

import { logger } from "@/ui/logger";
import { ApiSessionClient } from "@/api/apiSession";
import type { AgentState } from "@/api/types";
import { createEnvelope } from '@slopus/happy-wire';
import {
    BasePermissionHandler,
    PermissionResult,
    PendingRequest
} from '@/utils/BasePermissionHandler';

// Re-export types for backwards compatibility
export type { PermissionResult, PendingRequest };

/**
 * Codex-specific permission handler.
 */
export class CodexPermissionHandler extends BasePermissionHandler {
    private readonly announceTextApprovals: boolean;

    // Exact tool names that should always be auto-approved. Include the bare
    // form (used by Codex elicitation messages like `tool "change_title"`)
    // and the MCP-qualified form for defense in depth.
    private static readonly ALWAYS_AUTO_APPROVE_NAMES: ReadonlySet<string> = new Set([
        'change_title',
        'mcp__happy__change_title',
    ]);

    // Tool-call IDs that should auto-approve when they exactly match one of
    // these values or start with `<name>-` (e.g. `change_title-1765385846663`).
    // Substring matching was a bypass vector — any tool whose ID happened to
    // contain `change_title` as a substring would be silently approved.
    private static readonly ALWAYS_AUTO_APPROVE_ID_PREFIXES: readonly string[] = [
        'change_title',
    ];

    constructor(session: ApiSessionClient, options?: { announceTextApprovals?: boolean }) {
        super(session);
        this.announceTextApprovals = options?.announceTextApprovals === true;
    }

    protected getLogPrefix(): string {
        return '[Codex]';
    }

    private shouldAutoApprove(toolName: string, toolCallId: string): boolean {
        if (CodexPermissionHandler.ALWAYS_AUTO_APPROVE_NAMES.has(toolName)) {
            return true;
        }

        const toolCallIdSegments = toolCallId.split(':');

        for (const prefix of CodexPermissionHandler.ALWAYS_AUTO_APPROVE_ID_PREFIXES) {
            if (
                toolCallIdSegments.some((segment) => (
                    segment === prefix || segment.startsWith(`${prefix}-`)
                ))
            ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Handle a tool permission request
     * @param toolCallId - The unique ID of the tool call
     * @param toolName - The name of the tool being called
     * @param input - The input parameters for the tool
     * @returns Promise resolving to permission result
     */
    async handleToolCall(
        toolCallId: string,
        toolName: string,
        input: unknown
    ): Promise<PermissionResult> {
        if (this.shouldAutoApprove(toolName, toolCallId)) {
            logger.debug(`${this.getLogPrefix()} Auto-approving tool ${toolName} (${toolCallId})`);

            this.session.updateAgentState((currentState) => ({
                ...currentState,
                completedRequests: {
                    ...currentState.completedRequests,
                    [toolCallId]: {
                        tool: toolName,
                        arguments: input,
                        createdAt: Date.now(),
                        completedAt: Date.now(),
                        status: 'approved',
                        decision: 'approved',
                    },
                },
            } satisfies AgentState));

            return { decision: 'approved' };
        }

        return new Promise<PermissionResult>((resolve, reject) => {
            // Store the pending request
            this.pendingRequests.set(toolCallId, {
                resolve,
                reject,
                toolName,
                input
            });

            // Update agent state with pending request
            this.addPendingRequestToState(toolCallId, toolName, input);

            if (this.announceTextApprovals) {
                this.sendTextNotice(
                    `Codex is waiting for approval to use ${toolName}. `
                    + 'Reply /approve (允许) to continue or /deny (拒绝) to reject.'
                );
            }

            logger.debug(`${this.getLogPrefix()} Permission request sent for tool: ${toolName} (${toolCallId})`);
        });
    }

    /**
     * Resolve the oldest pending approval from an exact text command.
     * This is enabled only for ISCP text-only sessions, whose grant cannot
     * receive the raw agent-state approval card used by the official app.
     */
    tryHandleTextPermissionResponse(text: string): boolean {
        if (!this.announceTextApprovals) {
            return false;
        }

        const normalized = text.trim().toLocaleLowerCase('en-US');
        const approve = new Set(['/approve', 'approve', '允许', '同意', '批准']);
        const deny = new Set(['/deny', 'deny', '拒绝', '不允许']);
        if (!approve.has(normalized) && !deny.has(normalized)) {
            return false;
        }

        const oldest = this.pendingRequests.entries().next().value as
            | [string, PendingRequest]
            | undefined;
        if (!oldest) {
            return false;
        }

        const [id, pending] = oldest;
        const approved = approve.has(normalized);
        const handled = this.resolvePermissionResponse({
            id,
            approved,
            decision: approved ? 'approved' : 'denied',
        });
        if (!handled) {
            return false;
        }

        this.sendTextNotice(
            approved
                ? `Approved ${pending.toolName}. Codex is continuing.`
                : `Denied ${pending.toolName}. Codex will continue without it.`
        );
        return true;
    }

    private sendTextNotice(text: string): void {
        this.session.sendSessionProtocolMessage(createEnvelope('agent', {
            t: 'text',
            text,
        }));
    }
}
