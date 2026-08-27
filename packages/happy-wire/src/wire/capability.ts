import * as z from 'zod';
import { PHONE_TEXT_VIEW_PROTOCOL } from './textView';

/**
 * agent.capability.v1 — Happy-level convention layered on top of ISCP.
 * ISCP itself has no capability negotiation (its ciphersuite is a fixed
 * constant); this manifest is the first business payload exchanged after
 * session.ready, and gates every feature capability-first: a peer exposes a
 * capability only after seeing it in the manifest, never by assumption.
 */
export const AGENT_CAPABILITY_PROTOCOL = 'agent.capability.v1';
export const HAPPY_WIRE_PROTOCOL = 'happy-wire.v1';

export const AgentCapabilitySchema = z.object({
  id: z.enum([
    'agent.sessions',
    'agent.conversation',
    'agent.streaming',
    'agent.activities',
    'agent.approvals',
    'agent.workspace',
    'agent.files',
  ]),
  version: z.number().int().positive(),
});
export type AgentCapability = z.infer<typeof AgentCapabilitySchema>;

export const AgentCapabilityManifestSchema = z.object({
  product_kind: z.literal('happy'),
  device_type: z.literal('agent_runtime'),
  device_role: z.literal('owner_runtime'),
  runtime_kind: z.literal('happy-agent'),
  protocol_versions: z.array(z.string()).refine(
    (versions) => versions.includes(AGENT_CAPABILITY_PROTOCOL) && versions.includes(HAPPY_WIRE_PROTOCOL),
    { message: `protocol_versions must include ${AGENT_CAPABILITY_PROTOCOL} and ${HAPPY_WIRE_PROTOCOL}` },
  ),
  capabilities: z.array(AgentCapabilitySchema),
});
export type AgentCapabilityManifest = z.infer<typeof AgentCapabilityManifestSchema>;

export function defaultAgentCapabilityManifest(): AgentCapabilityManifest {
  return {
    product_kind: 'happy',
    device_type: 'agent_runtime',
    device_role: 'owner_runtime',
    runtime_kind: 'happy-agent',
    protocol_versions: [AGENT_CAPABILITY_PROTOCOL, HAPPY_WIRE_PROTOCOL, PHONE_TEXT_VIEW_PROTOCOL],
    capabilities: [
      { id: 'agent.sessions', version: 1 },
      { id: 'agent.conversation', version: 1 },
      { id: 'agent.streaming', version: 1 },
      { id: 'agent.activities', version: 1 },
      { id: 'agent.approvals', version: 1 },
      { id: 'agent.workspace', version: 1 },
      { id: 'agent.files', version: 1 },
    ],
  };
}
