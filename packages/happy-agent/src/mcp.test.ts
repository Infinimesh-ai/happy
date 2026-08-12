import { mkdtempSync, rmSync, statSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { Config } from './config';
import type { DecryptedMachine, DecryptedMessage, DecryptedSession } from './api';
import type { SpawnMachineSessionResult } from './machineRpc';
import {
    createBridgeMcpServer,
    createDefaultDeps,
    loadOrCreateBridgeToken,
    startBridgeMcpServer,
    type BridgeServerHandle,
    type McpBridgeDeps,
} from './mcp';

const encryption = { key: new Uint8Array(32), variant: 'dataKey' as const };

function makeSession(id: string, overrides: Partial<DecryptedSession> = {}): DecryptedSession {
    return {
        id,
        seq: 1,
        createdAt: 1000,
        updatedAt: 2000,
        active: true,
        activeAt: 2000,
        metadata: { path: '/home/user/project', host: 'workstation', machineId: 'machine-1' },
        agentState: null,
        dataEncryptionKey: 'unused',
        encryption,
        ...overrides,
    };
}

function makeMachine(id: string, overrides: Partial<DecryptedMachine> = {}): DecryptedMachine {
    return {
        id,
        seq: 1,
        createdAt: 1000,
        updatedAt: 2000,
        active: true,
        activeAt: 2000,
        metadata: { host: 'workstation', homeDir: '/home/user' },
        metadataVersion: 1,
        daemonState: null,
        daemonStateVersion: 0,
        dataEncryptionKey: 'unused',
        encryption,
        ...overrides,
    };
}

type Call = { tool: string; args: unknown };

function makeDeps(calls: Call[]): McpBridgeDeps {
    return {
        listMachines: async () => [makeMachine('machine-1'), makeMachine('machine-2', { active: false })],
        listSessions: async () => [makeSession('session-aaa'), makeSession('session-bbb', { active: false })],
        getSessionMessages: async (session): Promise<DecryptedMessage[]> => [
            { id: 'm1', seq: 1, content: { role: 'user', content: { type: 'text', text: `hello ${session.id}` } }, localId: null, createdAt: 1, updatedAt: 1 },
            { id: 'm2', seq: 2, content: { role: 'agent', content: { type: 'text', text: 'hi' } }, localId: null, createdAt: 2, updatedAt: 2 },
        ],
        spawnSession: async (machine, opts): Promise<SpawnMachineSessionResult> => {
            calls.push({ tool: 'spawnSession', args: { machineId: machine.id, ...opts } });
            return { type: 'success', sessionId: 'new-session-id' };
        },
        sendMessage: async (session, text, permissionMode) => {
            calls.push({ tool: 'sendMessage', args: { sessionId: session.id, text, permissionMode } });
        },
        stopSession: async (session) => {
            calls.push({ tool: 'stopSession', args: { sessionId: session.id } });
        },
        waitForIdle: async (session, timeoutMs) => {
            calls.push({ tool: 'waitForIdle', args: { sessionId: session.id, timeoutMs } });
        },
    };
}

describe('bridge mcp server', () => {
    const calls: Call[] = [];
    let handle: BridgeServerHandle;
    let rpcId = 0;

    beforeAll(async () => {
        handle = await startBridgeMcpServer({ host: '127.0.0.1', port: 0, authToken: 'test-bridge-token', deps: makeDeps(calls) });
    });

    afterAll(async () => {
        await handle.close();
    });

    async function rpc(method: string, params?: unknown, token: string | null = 'test-bridge-token') {
        const response = await fetch(handle.url, {
            method: 'POST',
            headers: {
                'content-type': 'application/json',
                accept: 'application/json, text/event-stream',
                ...(token === null ? {} : { authorization: `Bearer ${token}` }),
            },
            body: JSON.stringify({ jsonrpc: '2.0', id: ++rpcId, method, ...(params === undefined ? {} : { params }) }),
        });
        return response;
    }

    async function parseRpc(response: Response): Promise<{ result?: any; error?: any }> {
        const text = await response.text();
        // Streamable HTTP may answer as SSE; extract the data line in that case.
        const dataLine = text.split('\n').find(line => line.startsWith('data: '));
        return JSON.parse(dataLine ? dataLine.slice('data: '.length) : text);
    }

    async function callTool(name: string, args: Record<string, unknown>) {
        const response = await rpc('tools/call', { name, arguments: args });
        expect(response.status).toBe(200);
        const body = await parseRpc(response);
        return body.result as { content: { type: string; text: string }[]; isError: boolean };
    }

    it('rejects requests without the bearer token', async () => {
        const missing = await rpc('tools/list', undefined, null);
        expect(missing.status).toBe(401);
        const wrong = await rpc('tools/list', undefined, 'wrong-token');
        expect(wrong.status).toBe(401);
    });

    it('initializes and lists the bridge tools', async () => {
        const init = await rpc('initialize', {
            protocolVersion: '2025-06-18',
            capabilities: {},
            clientInfo: { name: 'sparkclaw-test', version: '0.0.1' },
        });
        expect(init.status).toBe(200);
        const initBody = await parseRpc(init);
        expect(initBody.result.serverInfo.name).toBe('happy-bridge');

        const list = await rpc('tools/list');
        const body = await parseRpc(list);
        const names = body.result.tools.map((t: { name: string }) => t.name);
        for (const expected of ['list_machines', 'list_sessions', 'get_session', 'get_session_messages', 'spawn_session', 'send_message', 'stop_session', 'wait_for_idle']) {
            expect(names).toContain(expected);
        }
    });

    it('lists machines and sessions without leaking encryption material', async () => {
        const machines = await callTool('list_machines', {});
        expect(machines.isError).toBe(false);
        const machinesPayload = JSON.parse(machines.content[0].text);
        expect(machinesPayload.machines.map((m: { id: string }) => m.id)).toEqual(['machine-1', 'machine-2']);
        expect(machines.content[0].text).not.toContain('encryption');
        expect(machines.content[0].text).not.toContain('dataEncryptionKey');

        const active = await callTool('list_sessions', { activeOnly: true });
        const sessionsPayload = JSON.parse(active.content[0].text);
        expect(sessionsPayload.sessions.map((s: { id: string }) => s.id)).toEqual(['session-aaa']);
        expect(active.content[0].text).not.toContain('encryption');
    });

    it('resolves sessions by unique prefix and errors on ambiguity', async () => {
        const found = await callTool('get_session', { sessionId: 'session-aaa' });
        expect(found.isError).toBe(false);

        const ambiguous = await callTool('get_session', { sessionId: 'session-' });
        expect(ambiguous.isError).toBe(true);
        expect(ambiguous.content[0].text).toContain('Ambiguous');

        const missing = await callTool('get_session', { sessionId: 'nope' });
        expect(missing.isError).toBe(true);
    });

    it('reads message history with a limit', async () => {
        const result = await callTool('get_session_messages', { sessionId: 'session-aaa', limit: 1 });
        const payload = JSON.parse(result.content[0].text);
        expect(payload.messages).toHaveLength(1);
        expect(payload.messages[0].id).toBe('m2');
    });

    it('spawns sessions, sends messages, stops and waits through the deps', async () => {
        calls.length = 0;

        const spawned = await callTool('spawn_session', { machineId: 'machine-1', directory: '/home/user/project', agent: 'claude' });
        expect(spawned.isError).toBe(false);
        expect(JSON.parse(spawned.content[0].text).sessionId).toBe('new-session-id');

        const sent = await callTool('send_message', { sessionId: 'session-aaa', text: 'run the tests' });
        expect(sent.isError).toBe(false);

        const stopped = await callTool('stop_session', { sessionId: 'session-bbb' });
        expect(stopped.isError).toBe(false);

        const waited = await callTool('wait_for_idle', { sessionId: 'session-aaa', timeoutSeconds: 60 });
        expect(waited.isError).toBe(false);

        expect(calls).toEqual([
            { tool: 'spawnSession', args: { machineId: 'machine-1', directory: '/home/user/project', agent: 'claude', approvedNewDirectoryCreation: undefined } },
            { tool: 'sendMessage', args: { sessionId: 'session-aaa', text: 'run the tests', permissionMode: undefined } },
            { tool: 'stopSession', args: { sessionId: 'session-bbb' } },
            { tool: 'waitForIdle', args: { sessionId: 'session-aaa', timeoutMs: 60_000 } },
        ]);
    });

    it('rejects invalid tool arguments', async () => {
        const response = await rpc('tools/call', { name: 'spawn_session', arguments: { machineId: 'machine-1' } });
        const body = await parseRpc(response);
        // Missing required `directory` — the SDK reports invalid params.
        expect(body.error ?? body.result?.isError).toBeTruthy();
    });
});

describe('bridge token persistence', () => {
    let dir: string;

    beforeAll(() => {
        dir = mkdtempSync(join(tmpdir(), 'happy-bridge-token-'));
    });

    afterAll(() => {
        rmSync(dir, { recursive: true, force: true });
    });

    it('creates a 0600 token file once and reuses it', () => {
        const config: Config = { serverUrl: 'https://example.com', homeDir: dir, credentialPath: join(dir, 'agent.key') };
        const first = loadOrCreateBridgeToken(config);
        const second = loadOrCreateBridgeToken(config);
        expect(first).toBe(second);
        expect(first.length).toBeGreaterThanOrEqual(40);
        const mode = statSync(join(dir, 'mcp.token')).mode & 0o777;
        expect(mode).toBe(0o600);
        expect(readFileSync(join(dir, 'mcp.token'), 'utf-8').trim()).toBe(first);
    });
});

describe('default deps wiring', () => {
    it('builds without touching the network', () => {
        const config: Config = { serverUrl: 'https://example.com', homeDir: '/tmp/nope', credentialPath: '/tmp/nope/agent.key' };
        const creds = {
            token: 'jwt',
            secret: new Uint8Array(32),
            contentKeyPair: { publicKey: new Uint8Array(32), secretKey: new Uint8Array(32) },
        };
        const deps = createDefaultDeps(config, creds);
        expect(Object.keys(deps).sort()).toEqual([
            'getSessionMessages', 'listMachines', 'listSessions', 'sendMessage', 'spawnSession', 'stopSession', 'waitForIdle',
        ]);
        // The MCP server itself constructs cleanly over the default deps.
        const mcp = createBridgeMcpServer(deps);
        expect(mcp).toBeDefined();
    });
});
