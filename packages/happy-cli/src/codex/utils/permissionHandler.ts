/**
 * Codex Permission Handler
 *
 * Handles tool permission requests and responses for Codex sessions.
 * Extends BasePermissionHandler with Codex-specific configuration.
 */

import { logger } from "@/ui/logger";
import { ApiSessionClient } from "@/api/apiSession";
import type { AgentState } from "@/api/types";
import { randomUUID } from 'node:crypto';
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
    private readonly textApprovals = new Map<string, { requestId: string; toolName: string }>();
    private readonly recentlyResolvedTextApprovals = new Map<string, true>();
    private static readonly RESOLVED_LEDGER_LIMIT = 128;

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
                const approvalId = randomUUID().toLocaleLowerCase('en-US');
                this.textApprovals.set(approvalId, { requestId: toolCallId, toolName });
                this.session.sendPhoneApproval(approvalId, toolName, 'pending');
            }

            logger.debug(`${this.getLogPrefix()} Permission request sent for tool: ${toolName} (${toolCallId})`);
        });
    }

    /**
     * Resolve an exact pending approval from an authenticated text command.
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
        const targeted = /^\/(approve|deny) ([0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$/.exec(normalized);
        if (targeted) {
            const approved = targeted[1] === 'approve';
            const approvalId = targeted[2];
            const request = this.textApprovals.get(approvalId);
            if (!request) {
                // A duplicate, stale, or unknown but well-formed control
                // command is still control-plane input. Never forward it to
                // Codex as a new user prompt.
                logger.debug(`${this.getLogPrefix()} Ignoring resolved or unknown text approval ${approvalId}`);
                return true;
            }
            return this.resolveTextApproval(approvalId, request, approved);
        }

        // Consume malformed approval-shaped slash commands too. This keeps a
        // typo or a replay from becoming model-visible conversation content.
        if (/^\/(?:approve|deny)(?:\s|$)/.test(normalized)) {
            logger.debug(`${this.getLogPrefix()} Ignoring malformed text approval command`);
            return true;
        }

        if (!approve.has(normalized) && !deny.has(normalized)) {
            return false;
        }

        // Compatibility for build 18/19: exact legacy commands still resolve
        // the oldest request. With no request they are idempotent no-ops,
        // never ordinary messages that trigger "无需重复批准" replies.
        const oldest = this.textApprovals.entries().next().value as
            | [string, { requestId: string; toolName: string }]
            | undefined;
        if (!oldest) {
            return true;
        }

        const [approvalId, request] = oldest;
        const approved = approve.has(normalized);
        return this.resolveTextApproval(approvalId, request, approved);
    }

    private resolveTextApproval(
        approvalId: string,
        request: { requestId: string; toolName: string },
        approved: boolean,
    ): boolean {
        const handled = this.resolvePermissionResponse({
            id: request.requestId,
            approved,
            decision: approved ? 'approved' : 'denied',
        });
        if (!handled) {
            this.textApprovals.delete(approvalId);
            this.rememberResolvedTextApproval(approvalId);
            return true;
        }

        this.textApprovals.delete(approvalId);
        this.rememberResolvedTextApproval(approvalId);
        this.session.sendPhoneApproval(approvalId, request.toolName, approved ? 'approved' : 'denied');
        return true;
    }

    private rememberResolvedTextApproval(approvalId: string): void {
        this.recentlyResolvedTextApprovals.delete(approvalId);
        this.recentlyResolvedTextApprovals.set(approvalId, true);
        while (this.recentlyResolvedTextApprovals.size > CodexPermissionHandler.RESOLVED_LEDGER_LIMIT) {
            const oldest = this.recentlyResolvedTextApprovals.keys().next().value as string | undefined;
            if (oldest === undefined) break;
            this.recentlyResolvedTextApprovals.delete(oldest);
        }
    }

    private cancelTextApprovals(): void {
        for (const [approvalId, request] of this.textApprovals) {
            this.session.sendPhoneApproval(approvalId, request.toolName, 'cancelled');
            this.rememberResolvedTextApproval(approvalId);
        }
        this.textApprovals.clear();
    }

    override abortAll(): void {
        this.cancelTextApprovals();
        super.abortAll();
    }

    override reset(reason: string = 'Session reset'): void {
        this.cancelTextApprovals();
        super.reset(reason);
    }
}
