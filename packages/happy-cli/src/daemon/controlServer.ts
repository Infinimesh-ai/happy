/**
 * HTTP control server for daemon management
 * Provides endpoints for listing sessions, stopping sessions, and daemon shutdown
 */

import fastify, { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { serializerCompiler, validatorCompiler, ZodTypeProvider } from 'fastify-type-provider-zod';
import { logger } from '@/ui/logger';
import { Metadata } from '@/api/types';
import { decodeBase64 } from '@/api/encryption';
import { TrackedSession, SessionEncryptionData } from './types';
import { SpawnSessionOptions, SpawnSessionResult } from '@/modules/common/registerCommonHandlers';
import type { DaemonIscpService } from '@/iscp/daemonIscp';
import type { ProfilePeerStatus } from '@/iscp/sessionInitiator';

const ProfilePeerStatusSchema = z.object({
  profileId: z.string(),
  deviceId: z.string(),
  generation: z.number(),
  connectionState: z.string(),
  session: z.enum(['connecting', 'ready', 'authorization_expired', 'failed']),
  sessionDetail: z.string().optional(),
  peerDeviceId: z.string(),
});

export function startDaemonControlServer({
  getChildren,
  stopSession,
  spawnSession,
  requestShutdown,
  onHappySessionWebhook,
  iscp,
  reloadIscpPeers,
  getIscpPeerStatuses
}: {
  getChildren: () => TrackedSession[];
  stopSession: (sessionId: string) => boolean;
  spawnSession: (options: SpawnSessionOptions) => Promise<SpawnSessionResult>;
  requestShutdown: () => void;
  onHappySessionWebhook: (sessionId: string, metadata: Metadata, encryption?: SessionEncryptionData) => void;
  /** ISCP-mode ingestion (dual-stack). Absent when no ISCP profile is enrolled. */
  iscp?: DaemonIscpService;
  /** Hot-reload of ISCP peers (single-flight; wired to POST /iscp/reload). */
  reloadIscpPeers?: () => Promise<{ profiles: string[] }>;
  /** Per-profile transport + session diagnostics (GET /iscp/peer-status). */
  getIscpPeerStatuses?: () => ProfilePeerStatus[];
}): Promise<{ port: number; stop: () => Promise<void> }> {
  return new Promise((resolve) => {
    const app = fastify({
      logger: false // We use our own logger
    });

    // Set up Zod type provider
    app.setValidatorCompiler(validatorCompiler);
    app.setSerializerCompiler(serializerCompiler);
    const typed = app.withTypeProvider<ZodTypeProvider>();

    // Session reports itself after creation
    typed.post('/session-started', {
      schema: {
        body: z.object({
          sessionId: z.string(),
          metadata: z.any(),
          encryption: z.object({
            encryptionKey: z.string(),
            encryptionVariant: z.enum(['legacy', 'dataKey']),
            seq: z.number(),
            metadataVersion: z.number(),
            agentStateVersion: z.number(),
          }).optional()
        }),
        response: {
          200: z.object({
            status: z.literal('ok')
          })
        }
      }
    }, async (request) => {
      const { sessionId, metadata, encryption } = request.body;

      logger.debug(`[CONTROL SERVER] Session started: ${sessionId}`);

      let encryptionData: SessionEncryptionData | undefined;
      if (encryption) {
        encryptionData = {
          encryptionKey: decodeBase64(encryption.encryptionKey),
          encryptionVariant: encryption.encryptionVariant,
          seq: encryption.seq,
          metadataVersion: encryption.metadataVersion,
          agentStateVersion: encryption.agentStateVersion,
        };
      }

      onHappySessionWebhook(sessionId, metadata, encryptionData);

      return { status: 'ok' as const };
    });

    // List all tracked sessions
    typed.post('/list', {
      schema: {
        response: {
          200: z.object({
            children: z.array(z.object({
              startedBy: z.string(),
              happySessionId: z.string(),
              pid: z.number()
            }))
          })
        }
      }
    }, async () => {
      const children = getChildren();
      logger.debug(`[CONTROL SERVER] Listing ${children.length} sessions`);
      return { 
        children: children
          .filter(child => child.happySessionId !== undefined)
          .map(child => ({
            startedBy: child.startedBy,
            happySessionId: child.happySessionId!,
            pid: child.pid
          }))
      }
    });

    // Stop specific session
    typed.post('/stop-session', {
      schema: {
        body: z.object({
          sessionId: z.string()
        }),
        response: {
          200: z.object({
            success: z.boolean()
          })
        }
      }
    }, async (request) => {
      const { sessionId } = request.body;

      logger.debug(`[CONTROL SERVER] Stop session request: ${sessionId}`);
      const success = stopSession(sessionId);
      return { success };
    });

    // Spawn new session
    typed.post('/spawn-session', {
      schema: {
        body: z.object({
          directory: z.string(),
          sessionId: z.string().optional(),
          agent: z.enum(['claude', 'codex', 'gemini', 'openclaw', 'agy']).optional(),
          permissionMode: z.string().optional(),
          modelMode: z.string().optional(),
          effortLevel: z.string().optional(),
          environmentVariables: z.record(z.string(), z.string()).optional(),
        }),
        response: {
          200: z.object({
            success: z.boolean(),
            sessionId: z.string().optional(),
            approvedNewDirectoryCreation: z.boolean().optional()
          }),
          409: z.object({
            success: z.boolean(),
            requiresUserApproval: z.boolean().optional(),
            actionRequired: z.string().optional(),
            directory: z.string().optional()
          }),
          500: z.object({
            success: z.boolean(),
            error: z.string().optional()
          })
        }
      }
    }, async (request, reply) => {
      const { directory, sessionId, agent, permissionMode, modelMode, effortLevel, environmentVariables } = request.body;

      logger.debug(`[CONTROL SERVER] Spawn session request: dir=${directory}, sessionId=${sessionId || 'new'}, agent=${agent || 'default'}`);
      const result = await spawnSession({ directory, sessionId, agent, permissionMode, modelMode, effortLevel, environmentVariables });

      switch (result.type) {
        case 'success':
          // Check if sessionId exists, if not return error
          if (!result.sessionId) {
            reply.code(500);
            return {
              success: false,
              error: 'Failed to spawn session: no session ID returned'
            };
          }
          return {
            success: true,
            sessionId: result.sessionId,
            approvedNewDirectoryCreation: true
          };
        
        case 'requestToApproveDirectoryCreation':
          reply.code(409); // Conflict - user input needed
          return { 
            success: false,
            requiresUserApproval: true,
            actionRequired: 'CREATE_DIRECTORY',
            directory: result.directory
          };
        
        case 'error':
          reply.code(500);
          return { 
            success: false,
            error: result.errorMessage
          };
      }
    });

    // ISCP-mode session event ingestion (dual-stack): sessions spawned with
    // HAPPY_NETWORK_PROFILE post their history events here; the daemon event
    // log assigns monotonic seq and dedupes by localId.
    typed.post('/iscp/session-event', {
      schema: {
        body: z.object({
          profileId: z.string().min(1),
          sessionId: z.string().min(1),
          events: z.array(z.object({
            localId: z.string().optional(),
            body: z.unknown()
          })).min(1).max(200)
        }),
        response: {
          200: z.object({
            results: z.array(z.object({
              seq: z.number(),
              epoch: z.string(),
              deduped: z.boolean()
            }))
          }),
          503: z.object({
            error: z.string()
          })
        }
      }
    }, async (request, reply) => {
      if (!iscp) {
        reply.code(503);
        return { error: 'ISCP is not enabled on this daemon' };
      }
      const { profileId, sessionId, events } = request.body;
      const results = iscp.ingest(profileId, sessionId, events);
      logger.debug(`[CONTROL SERVER] ISCP ingested ${events.length} event(s) for ${sessionId} (last seq ${results[results.length - 1]?.seq})`);
      return { results };
    });

    // ISCP session RPC bridge registration: sessions report the localhost
    // port where they accept plaintext RPC (user-message delivery, session.rpc).
    typed.post('/iscp/session-rpc', {
      schema: {
        body: z.object({
          profileId: z.string().min(1),
          sessionId: z.string().min(1),
          port: z.number().int().min(1).max(65535)
        }),
        response: {
          200: z.object({ status: z.literal('ok') }),
          503: z.object({ error: z.string() })
        }
      }
    }, async (request, reply) => {
      if (!iscp) {
        reply.code(503);
        return { error: 'ISCP is not enabled on this daemon' };
      }
      const { profileId, sessionId, port } = request.body;
      iscp.registerSessionRpcPort(profileId, sessionId, port);
      logger.debug(`[CONTROL SERVER] ISCP session RPC registered: ${sessionId} → 127.0.0.1:${port}`);
      return { status: 'ok' as const };
    });

    // ISCP hot reload: rescan enrolled profiles and restart the peers.
    // Called by `happy iscp enroll` / `happy iscp renew` after a profile
    // change; single-flight semantics live in createIscpPeersController.
    typed.post('/iscp/reload', {
      schema: {
        response: {
          200: z.object({ profiles: z.array(z.string()) }),
          503: z.object({ error: z.string() })
        }
      }
    }, async (request, reply) => {
      if (!reloadIscpPeers) {
        reply.code(503);
        return { error: 'ISCP is not enabled on this daemon' };
      }
      const result = await reloadIscpPeers();
      logger.debug(`[CONTROL SERVER] ISCP peers reloaded (profiles: ${result.profiles.join(', ') || 'none'})`);
      return result;
    });

    // ISCP per-profile diagnostics: relay transport + E2E session state,
    // consumed by `happy iscp status --check` layers 5 and 6.
    typed.get('/iscp/peer-status', {
      schema: {
        response: {
          200: z.object({ profiles: z.array(ProfilePeerStatusSchema) }),
          503: z.object({ error: z.string() })
        }
      }
    }, async (request, reply) => {
      if (!getIscpPeerStatuses) {
        reply.code(503);
        return { error: 'ISCP is not enabled on this daemon' };
      }
      return { profiles: getIscpPeerStatuses() };
    });

    // Stop daemon
    typed.post('/stop', {
      schema: {
        response: {
          200: z.object({
            status: z.string()
          })
        }
      }
    }, async () => {
      logger.debug('[CONTROL SERVER] Stop daemon request received');

      // Give time for response to arrive
      setTimeout(() => {
        logger.debug('[CONTROL SERVER] Triggering daemon shutdown');
        requestShutdown();
      }, 50);

      return { status: 'stopping' };
    });

    app.listen({ port: 0, host: '127.0.0.1' }, (err, address) => {
      if (err) {
        logger.debug('[CONTROL SERVER] Failed to start:', err);
        throw err;
      }

      const port = parseInt(address.split(':').pop()!);
      logger.debug(`[CONTROL SERVER] Started on port ${port}`);

      resolve({
        port,
        stop: async () => {
          logger.debug('[CONTROL SERVER] Stopping server');
          await app.close();
          logger.debug('[CONTROL SERVER] Server stopped');
        }
      });
    });
  });
}
