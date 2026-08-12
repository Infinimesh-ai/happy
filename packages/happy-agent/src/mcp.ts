/**
 * `happy-agent mcp` — the personal bridge MCP server.
 *
 * Exposes this account's Happy data and controls as MCP tools over Streamable
 * HTTP so an external personal assistant (e.g. SparkClaw) can list machines and
 * sessions, read decrypted session history, spawn new sessions and message
 * running ones. Everything decrypts locally with the agent.key master secret;
 * plaintext never leaves this process except to the connected MCP client.
 *
 * Stateless transport: each request gets a fresh McpServer + transport (MCP
 * SDK >=1.27 rejects reuse of an already-connected transport). Binds loopback
 * by default; every request must carry the bearer token generated on first run
 * (persisted at <homeDir>/mcp.token) unless auth is explicitly disabled.
 */
import { createServer, type Server, type IncomingMessage, type ServerResponse } from 'node:http';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import type { AddressInfo } from 'node:net';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { z } from 'zod';
import type { Config } from './config';
import type { Credentials } from './credentials';
import {
    listMachines,
    listSessions,
    getSessionMessages,
    type DecryptedMachine,
    type DecryptedMessage,
    type DecryptedSession,
} from './api';
import { spawnSessionOnMachine, type SpawnMachineSessionResult, type SupportedAgent } from './machineRpc';
import { SessionClient } from './session';
import { getRandomBytes } from './encryption';

const SUPPORTED_AGENTS: SupportedAgent[] = ['claude', 'codex', 'gemini', 'openclaw', 'agy'];

/**
 * Injectable backend so the HTTP/JSON-RPC layer is testable without a live
 * Happy server. The default implementation delegates to api.ts / machineRpc.ts
 * / SessionClient with the real config and credentials.
 */
export interface McpBridgeDeps {
    listMachines(): Promise<DecryptedMachine[]>;
    listSessions(): Promise<DecryptedSession[]>;
    getSessionMessages(session: DecryptedSession): Promise<DecryptedMessage[]>;
    spawnSession(machine: DecryptedMachine, opts: { directory: string; agent?: SupportedAgent; approvedNewDirectoryCreation?: boolean }): Promise<SpawnMachineSessionResult>;
    sendMessage(session: DecryptedSession, text: string, permissionMode?: string): Promise<void>;
    stopSession(session: DecryptedSession): Promise<void>;
    waitForIdle(session: DecryptedSession, timeoutMs: number): Promise<void>;
}

async function withSessionClient(config: Config, creds: Credentials, session: DecryptedSession, fn: (client: SessionClient) => Promise<void>): Promise<void> {
    const client = new SessionClient({
        sessionId: session.id,
        encryptionKey: session.encryption.key,
        encryptionVariant: session.encryption.variant,
        token: creds.token,
        serverUrl: config.serverUrl,
        initialAgentState: session.agentState ?? null,
    });
    try {
        await client.waitForConnect();
        await fn(client);
    } finally {
        client.close();
    }
}

export function createDefaultDeps(config: Config, creds: Credentials): McpBridgeDeps {
    return {
        listMachines: () => listMachines(config, creds),
        listSessions: () => listSessions(config, creds),
        getSessionMessages: (session) => getSessionMessages(config, creds, session.id, session.encryption),
        spawnSession: (machine, opts) => spawnSessionOnMachine(config, machine, creds.token, opts),
        sendMessage: (session, text, permissionMode) => withSessionClient(config, creds, session, async (client) => {
            client.sendMessage(text, permissionMode ? { permissionMode } : undefined);
            // Allow the Socket.IO event to flush before closing.
            await new Promise(resolve => setTimeout(resolve, 500));
        }),
        stopSession: (session) => withSessionClient(config, creds, session, async (client) => {
            client.sendStop();
            await new Promise(resolve => setTimeout(resolve, 500));
        }),
        waitForIdle: (session, timeoutMs) => withSessionClient(config, creds, session, async (client) => {
            await client.waitForIdle(timeoutMs);
        }),
    };
}

// --- DTOs: strip encryption material before anything reaches the MCP client ---

function machineDto(machine: DecryptedMachine) {
    return {
        id: machine.id,
        active: machine.active,
        activeAt: machine.activeAt,
        createdAt: machine.createdAt,
        metadata: machine.metadata,
        daemonState: machine.daemonState,
    };
}

function sessionDto(session: DecryptedSession) {
    return {
        id: session.id,
        active: session.active,
        activeAt: session.activeAt,
        createdAt: session.createdAt,
        updatedAt: session.updatedAt,
        metadata: session.metadata,
        agentState: session.agentState,
    };
}

function resolveByPrefix<T extends { id: string }>(items: T[], value: string, label: string): T {
    const matches = items.filter(item => item.id.startsWith(value));
    if (matches.length === 0) {
        throw new Error(`No ${label} found matching "${value}"`);
    }
    if (matches.length > 1) {
        throw new Error(`Ambiguous ${label} "${value}" matches ${matches.length} records. Be more specific.`);
    }
    return matches[0];
}

function ok(value: unknown) {
    return { content: [{ type: 'text' as const, text: typeof value === 'string' ? value : JSON.stringify(value, null, 2) }], isError: false };
}

function fail(error: unknown) {
    return { content: [{ type: 'text' as const, text: error instanceof Error ? error.message : String(error) }], isError: true };
}

export function createBridgeMcpServer(deps: McpBridgeDeps): McpServer {
    const mcp = new McpServer({ name: 'happy-bridge', version: '1.0.0' });

    mcp.registerTool('list_machines', {
        title: 'List machines',
        description: 'List the machines enrolled in this Happy account with decrypted metadata (host, home directory) and daemon liveness. Use a machine id with spawn_session.',
        inputSchema: {
            activeOnly: z.boolean().optional().describe('Only machines with a live daemon'),
        },
    }, async (args) => {
        try {
            const machines = await deps.listMachines();
            const filtered = args.activeOnly ? machines.filter(m => m.active) : machines;
            return ok({ machines: filtered.map(machineDto) });
        } catch (error) {
            return fail(error);
        }
    });

    mcp.registerTool('list_sessions', {
        title: 'List sessions',
        description: 'List this account\'s coding-agent sessions, decrypted: working directory, host, machineId, summary and live agent state. Most recently updated first.',
        inputSchema: {
            activeOnly: z.boolean().optional().describe('Only sessions that are currently connected'),
        },
    }, async (args) => {
        try {
            const sessions = await deps.listSessions();
            const filtered = args.activeOnly ? sessions.filter(s => s.active) : sessions;
            return ok({ sessions: filtered.map(sessionDto) });
        } catch (error) {
            return fail(error);
        }
    });

    mcp.registerTool('get_session', {
        title: 'Get session',
        description: 'Fetch one session by id (or unambiguous id prefix): decrypted metadata and agent state.',
        inputSchema: {
            sessionId: z.string().min(1).describe('Session id or unique prefix'),
        },
    }, async (args) => {
        try {
            const session = resolveByPrefix(await deps.listSessions(), args.sessionId, 'session');
            return ok({ session: sessionDto(session) });
        } catch (error) {
            return fail(error);
        }
    });

    mcp.registerTool('get_session_messages', {
        title: 'Get session messages',
        description: 'Read a session\'s message history, decrypted locally, oldest first. Returns at most `limit` of the newest messages (default 50). Message contents are agent transcripts and may be long.',
        inputSchema: {
            sessionId: z.string().min(1).describe('Session id or unique prefix'),
            limit: z.number().int().min(1).max(500).optional().describe('Max messages to return, default 50'),
        },
    }, async (args) => {
        try {
            const session = resolveByPrefix(await deps.listSessions(), args.sessionId, 'session');
            const messages = await deps.getSessionMessages(session);
            messages.sort((a, b) => a.createdAt - b.createdAt);
            return ok({ messages: messages.slice(-(args.limit ?? 50)) });
        } catch (error) {
            return fail(error);
        }
    });

    mcp.registerTool('spawn_session', {
        title: 'Spawn session',
        description: 'Start a new coding-agent session in a directory on one of the machines (the machine\'s daemon must be online). Returns the new session id. Base relative paths on the machine\'s homeDir from list_machines.',
        inputSchema: {
            machineId: z.string().min(1).describe('Machine id or unique prefix from list_machines'),
            directory: z.string().min(1).describe('Absolute working directory on that machine'),
            agent: z.enum(SUPPORTED_AGENTS).optional().describe('Agent to start; machine default when omitted'),
            allowDirectoryCreation: z.boolean().optional().describe('Create the directory if it does not exist'),
        },
    }, async (args) => {
        try {
            const machine = resolveByPrefix(await deps.listMachines(), args.machineId, 'machine');
            const result = await deps.spawnSession(machine, {
                directory: args.directory,
                agent: args.agent,
                approvedNewDirectoryCreation: args.allowDirectoryCreation,
            });
            if (result.type === 'success') {
                return ok({ machineId: machine.id, directory: args.directory, sessionId: result.sessionId });
            }
            if (result.type === 'requestToApproveDirectoryCreation') {
                return fail(new Error(`Directory '${result.directory}' does not exist. Retry with allowDirectoryCreation: true.`));
            }
            return fail(new Error(result.errorMessage));
        } catch (error) {
            return fail(error);
        }
    });

    mcp.registerTool('send_message', {
        title: 'Send message',
        description: 'Send a user message into an existing session. The session\'s agent picks it up as if the owner typed it. Use wait_for_idle afterwards to await the reply.',
        inputSchema: {
            sessionId: z.string().min(1).describe('Session id or unique prefix'),
            text: z.string().min(1).describe('The message to send'),
            permissionMode: z.string().optional().describe('Optional permission mode override, e.g. "yolo"'),
        },
    }, async (args) => {
        try {
            const session = resolveByPrefix(await deps.listSessions(), args.sessionId, 'session');
            await deps.sendMessage(session, args.text, args.permissionMode);
            return ok({ sessionId: session.id, sent: true });
        } catch (error) {
            return fail(error);
        }
    });

    mcp.registerTool('stop_session', {
        title: 'Stop session',
        description: 'Ask the session\'s agent to stop its current turn.',
        inputSchema: {
            sessionId: z.string().min(1).describe('Session id or unique prefix'),
        },
    }, async (args) => {
        try {
            const session = resolveByPrefix(await deps.listSessions(), args.sessionId, 'session');
            await deps.stopSession(session);
            return ok({ sessionId: session.id, stopped: true });
        } catch (error) {
            return fail(error);
        }
    });

    mcp.registerTool('wait_for_idle', {
        title: 'Wait for idle',
        description: 'Block until the session\'s agent finishes its current work (or the timeout elapses). Combine with send_message for a request/response round trip.',
        inputSchema: {
            sessionId: z.string().min(1).describe('Session id or unique prefix'),
            timeoutSeconds: z.number().int().min(1).max(3600).optional().describe('Timeout, default 300'),
        },
    }, async (args) => {
        try {
            const session = resolveByPrefix(await deps.listSessions(), args.sessionId, 'session');
            await deps.waitForIdle(session, (args.timeoutSeconds ?? 300) * 1000);
            return ok({ sessionId: session.id, idle: true });
        } catch (error) {
            return fail(error);
        }
    });

    return mcp;
}

// --- Bearer token persistence ---

export function loadOrCreateBridgeToken(config: Config): string {
    const tokenPath = join(config.homeDir, 'mcp.token');
    try {
        const existing = readFileSync(tokenPath, 'utf-8').trim();
        if (existing.length > 0) return existing;
    } catch {
        // fall through to create
    }
    const token = Buffer.from(getRandomBytes(32)).toString('base64url');
    mkdirSync(dirname(tokenPath), { recursive: true });
    writeFileSync(tokenPath, `${token}\n`, { mode: 0o600 });
    return token;
}

// --- HTTP server ---

export interface BridgeServerOptions {
    host: string;
    port: number;
    /** Bearer token every request must present; null disables auth. */
    authToken: string | null;
    deps: McpBridgeDeps;
}

export interface BridgeServerHandle {
    url: string;
    port: number;
    close(): Promise<void>;
}

export async function startBridgeMcpServer(options: BridgeServerOptions): Promise<BridgeServerHandle> {
    const server: Server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
        if (options.authToken !== null) {
            const header = req.headers.authorization;
            if (header !== `Bearer ${options.authToken}`) {
                res.writeHead(401, { 'content-type': 'application/json' }).end(JSON.stringify({ error: 'Invalid bridge token' }));
                return;
            }
        }
        const mcp = createBridgeMcpServer(options.deps);
        try {
            const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
            await mcp.connect(transport);
            await transport.handleRequest(req, res);
            res.on('close', () => {
                transport.close();
                mcp.close();
            });
        } catch {
            if (!res.headersSent) {
                res.writeHead(500).end();
            }
            mcp.close();
        }
    });

    const port = await new Promise<number>((resolve, reject) => {
        server.once('error', reject);
        server.listen(options.port, options.host, () => {
            resolve((server.address() as AddressInfo).port);
        });
    });

    return {
        url: `http://${options.host}:${port}/`,
        port,
        close: () => new Promise<void>((resolve, reject) => server.close(err => err ? reject(err) : resolve())),
    };
}
