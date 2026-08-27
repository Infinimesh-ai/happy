import { describe, expect, it, vi } from 'vitest';
import { projectPhoneTextView } from '@slopus/happy-wire';
import { CodexPermissionHandler } from '../utils/permissionHandler';

vi.mock('@/ui/logger', () => ({
    logger: {
        debug: vi.fn(),
    },
}));

function createSessionMock() {
    let state: Record<string, any> = {};

    return {
        session: {
            rpcHandlerManager: {
                registerHandler: vi.fn(),
            },
            updateAgentState: vi.fn((updater: (currentState: Record<string, any>) => Record<string, any>) => {
                state = updater(state);
                return state;
            }),
            sendSessionProtocolMessage: vi.fn(),
            sendPhoneApproval: vi.fn((_approvalId: string, _toolName: string, _status: string) => true),
        },
        getState: () => state,
    };
}

describe('CodexPermissionHandler', () => {
    it('auto-approves the safe change_title tool', async () => {
        const { session, getState } = createSessionMock();
        const handler = new CodexPermissionHandler(session as any);

        const result = await handler.handleToolCall(
            'call_change_title_123',
            'change_title',
            { title: 'Greeting' },
        );

        expect(result).toEqual({ decision: 'approved' });
        expect(getState().completedRequests.call_change_title_123).toMatchObject({
            tool: 'change_title',
            arguments: { title: 'Greeting' },
            status: 'approved',
            decision: 'approved',
        });
    });

    it('keeps non-safe tools pending for user approval', async () => {
        const { session, getState } = createSessionMock();
        const handler = new CodexPermissionHandler(session as any);

        const pending = handler.handleToolCall(
            'call_exec_123',
            'Bash',
            { command: 'pwd' },
        );

        expect(getState().requests.call_exec_123).toMatchObject({
            tool: 'Bash',
            arguments: { command: 'pwd' },
        });

        handler.abortAll();

        await expect(pending).resolves.toEqual({ decision: 'abort' });
    });

    it('makes ISCP text-only approval visible and accepts an explicit text approval', async () => {
        const { session, getState } = createSessionMock();
        const handler = new CodexPermissionHandler(session as any, {
            announceTextApprovals: true,
        });

        const pending = handler.handleToolCall(
            'call_exec_123',
            'CodexBash',
            { command: 'curl https://example.com' },
        );

        const approvalId = vi.mocked(session.sendPhoneApproval).mock.calls[0][0] as string;
        expect(approvalId).toMatch(/^[0-9a-f-]{36}$/);
        expect(session.sendPhoneApproval).toHaveBeenCalledWith(approvalId, 'CodexBash', 'pending');
        expect(projectPhoneTextView({
            role: 'happy-control',
            content: { type: 'approval', approvalId, toolName: 'CodexBash', status: 'pending' },
        })).toMatchObject({
            kind: 'phone-approval-pending',
            emit: {
                role: 'agent',
                content: {
                    type: 'approval',
                    approvalId,
                    toolName: 'CodexBash',
                    status: 'pending',
                    approveCommand: '/approve',
                    denyCommand: '/deny',
                    targetedApproveCommand: `/approve ${approvalId}`,
                    targetedDenyCommand: `/deny ${approvalId}`,
                },
            },
        });
        expect(JSON.stringify(vi.mocked(session.sendPhoneApproval).mock.calls)).not.toContain('https://example.com');

        expect(handler.tryHandleTextPermissionResponse(`/approve ${approvalId}`)).toBe(true);
        await expect(pending).resolves.toEqual({ decision: 'approved' });
        expect(getState().requests).toEqual({});
        expect(getState().completedRequests.call_exec_123).toMatchObject({
            status: 'approved',
            decision: 'approved',
        });
        expect(session.sendPhoneApproval).toHaveBeenLastCalledWith(approvalId, 'CodexBash', 'approved');
    });

    it('rejects an ISCP text-only approval with an explicit deny command', async () => {
        const { session, getState } = createSessionMock();
        const handler = new CodexPermissionHandler(session as any, {
            announceTextApprovals: true,
        });
        const pending = handler.handleToolCall('call_exec_123', 'CodexBash', { command: 'pwd' });

        const approvalId = vi.mocked(session.sendPhoneApproval).mock.calls[0][0] as string;
        expect(handler.tryHandleTextPermissionResponse(`/deny ${approvalId}`)).toBe(true);
        await expect(pending).resolves.toEqual({ decision: 'denied' });
        expect(getState().completedRequests.call_exec_123).toMatchObject({
            status: 'denied',
            decision: 'denied',
        });
        expect(session.sendPhoneApproval).toHaveBeenLastCalledWith(approvalId, 'CodexBash', 'denied');
    });

    it('resolves concurrent same-tool approvals by opaque id instead of map order', async () => {
        const { session } = createSessionMock();
        const handler = new CodexPermissionHandler(session as any, { announceTextApprovals: true });
        const first = handler.handleToolCall('call_first', 'CodexBash', { command: 'first' });
        const second = handler.handleToolCall('call_second', 'CodexBash', { command: 'second' });
        const firstId = vi.mocked(session.sendPhoneApproval).mock.calls[0][0] as string;
        const secondId = vi.mocked(session.sendPhoneApproval).mock.calls[1][0] as string;

        expect(handler.tryHandleTextPermissionResponse(`/approve ${secondId}`)).toBe(true);
        await expect(second).resolves.toEqual({ decision: 'approved' });
        expect(handler.tryHandleTextPermissionResponse(`/deny ${firstId}`)).toBe(true);
        await expect(first).resolves.toEqual({ decision: 'denied' });
        expect(session.sendPhoneApproval).toHaveBeenNthCalledWith(3, secondId, 'CodexBash', 'approved');
        expect(session.sendPhoneApproval).toHaveBeenNthCalledWith(4, firstId, 'CodexBash', 'denied');
    });

    it('consumes duplicate, stale, malformed, and empty legacy approval commands as no-ops', async () => {
        const { session } = createSessionMock();
        const handler = new CodexPermissionHandler(session as any, { announceTextApprovals: true });
        const pending = handler.handleToolCall('call_exec_123', 'CodexBash', { command: 'pwd' });
        const approvalId = vi.mocked(session.sendPhoneApproval).mock.calls[0][0] as string;

        expect(handler.tryHandleTextPermissionResponse(`/approve ${approvalId}`)).toBe(true);
        await expect(pending).resolves.toEqual({ decision: 'approved' });
        expect(handler.tryHandleTextPermissionResponse(`/approve ${approvalId}`)).toBe(true);
        expect(handler.tryHandleTextPermissionResponse('/approve')).toBe(true);
        expect(handler.tryHandleTextPermissionResponse('/deny not-a-valid-id')).toBe(true);
        expect(handler.tryHandleTextPermissionResponse('普通对话')).toBe(false);
        expect(session.sendPhoneApproval).toHaveBeenCalledTimes(2);
    });

    it('emits cancelled lifecycle records when a pending turn is aborted', async () => {
        const { session } = createSessionMock();
        const handler = new CodexPermissionHandler(session as any, { announceTextApprovals: true });
        const pending = handler.handleToolCall('call_exec_123', 'CodexBash', { command: 'pwd' });
        const approvalId = vi.mocked(session.sendPhoneApproval).mock.calls[0][0] as string;

        handler.abortAll();

        await expect(pending).resolves.toEqual({ decision: 'abort' });
        expect(session.sendPhoneApproval).toHaveBeenLastCalledWith(approvalId, 'CodexBash', 'cancelled');
        expect(handler.tryHandleTextPermissionResponse(`/approve ${approvalId}`)).toBe(true);
    });

    it('does not consume ordinary text or enable text approval outside ISCP-only mode', async () => {
        const { session } = createSessionMock();
        const handler = new CodexPermissionHandler(session as any);
        const pending = handler.handleToolCall('call_exec_123', 'CodexBash', { command: 'pwd' });

        expect(handler.tryHandleTextPermissionResponse('hello')).toBe(false);
        expect(handler.tryHandleTextPermissionResponse('/approve')).toBe(false);
        expect(session.sendPhoneApproval).not.toHaveBeenCalled();

        handler.abortAll();
        await expect(pending).resolves.toEqual({ decision: 'abort' });
    });

    it('does NOT auto-approve a crafted tool name containing change_title as substring', async () => {
        const { session } = createSessionMock();
        const handler = new CodexPermissionHandler(session as any);

        const pending = handler.handleToolCall(
            'call_malicious_1',
            'change_title_and_run_command',
            { title: 'pwn', cmd: 'rm -rf /' },
        );

        // Should remain pending (not auto-approved) — resolve via abort to clean up.
        handler.abortAll();
        await expect(pending).resolves.toEqual({ decision: 'abort' });
    });

    it('does NOT auto-approve a tool whose ID merely contains change_title as substring', async () => {
        const { session } = createSessionMock();
        const handler = new CodexPermissionHandler(session as any);

        // ID like `x_change_title_y` — old substring check would match, new prefix check must not.
        const pending = handler.handleToolCall(
            'x_change_title_y',
            'ExecCommand',
            { command: 'rm -rf /' },
        );

        handler.abortAll();
        await expect(pending).resolves.toEqual({ decision: 'abort' });
    });

    it('auto-approves change_title tool call by Gemini-style ID (change_title-<timestamp>)', async () => {
        const { session } = createSessionMock();
        const handler = new CodexPermissionHandler(session as any);

        const result = await handler.handleToolCall(
            'change_title-1765385846663',
            'other',
            { title: 'Greeting' },
        );

        expect(result).toEqual({ decision: 'approved' });
    });

    it('auto-approves change_title-prefixed IDs after Codex thread scoping', async () => {
        const { session, getState } = createSessionMock();
        const handler = new CodexPermissionHandler(session as any);

        const result = await handler.handleToolCall(
            'thread-1:change_title-1765385846663',
            'other',
            { title: 'Greeting' },
        );

        expect(result).toEqual({ decision: 'approved' });
        expect(getState().completedRequests['thread-1:change_title-1765385846663']).toMatchObject({
            status: 'approved',
        });
    });
});
