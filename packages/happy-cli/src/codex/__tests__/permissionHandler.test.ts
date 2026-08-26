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

        expect(session.sendSessionProtocolMessage).toHaveBeenCalledTimes(1);
        const approvalPrompt = vi.mocked(session.sendSessionProtocolMessage).mock.calls[0][0];
        expect(projectPhoneTextView({ role: 'session', content: approvalPrompt })).toMatchObject({
            kind: 'session-text',
            emit: {
                role: 'agent',
                content: {
                    type: 'text',
                    text: expect.stringContaining('/approve'),
                },
            },
        });
        expect(JSON.stringify(approvalPrompt)).not.toContain('https://example.com');

        expect(handler.tryHandleTextPermissionResponse('允许')).toBe(true);
        await expect(pending).resolves.toEqual({ decision: 'approved' });
        expect(getState().requests).toEqual({});
        expect(getState().completedRequests.call_exec_123).toMatchObject({
            status: 'approved',
            decision: 'approved',
        });
        expect(session.sendSessionProtocolMessage).toHaveBeenCalledTimes(2);
    });

    it('rejects an ISCP text-only approval with an explicit deny command', async () => {
        const { session, getState } = createSessionMock();
        const handler = new CodexPermissionHandler(session as any, {
            announceTextApprovals: true,
        });
        const pending = handler.handleToolCall('call_exec_123', 'CodexBash', { command: 'pwd' });

        expect(handler.tryHandleTextPermissionResponse('/deny')).toBe(true);
        await expect(pending).resolves.toEqual({ decision: 'denied' });
        expect(getState().completedRequests.call_exec_123).toMatchObject({
            status: 'denied',
            decision: 'denied',
        });
    });

    it('does not consume ordinary text or enable text approval outside ISCP-only mode', async () => {
        const { session } = createSessionMock();
        const handler = new CodexPermissionHandler(session as any);
        const pending = handler.handleToolCall('call_exec_123', 'CodexBash', { command: 'pwd' });

        expect(handler.tryHandleTextPermissionResponse('hello')).toBe(false);
        expect(handler.tryHandleTextPermissionResponse('/approve')).toBe(false);
        expect(session.sendSessionProtocolMessage).not.toHaveBeenCalled();

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
