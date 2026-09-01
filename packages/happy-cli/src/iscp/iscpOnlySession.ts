/**
 * Local session identity for ISCP-only mode (OPS 2026-08-26 §4.1): with no
 * Happy Server there is no server-issued session row, so the session id and
 * content key are minted locally. The id feeds the daemon event log, the
 * session RPC registry, and the /session-started webhook — all of which treat
 * ids as opaque strings. The key exists only so resume-in-place
 * (HAPPY_RECONNECT_*) and the daemon's persisted-session bookkeeping keep
 * their existing shape; no ISCP payload is ever encrypted with it
 * (iscp_session_v1 protects the relay leg, localhost hops are plaintext).
 */

import { randomBytes, randomUUID } from 'node:crypto'

import type { AgentState, Metadata, Session } from '@/api/types'

export function createIscpOnlySession(metadata: Metadata, state: AgentState): Session {
  return {
    id: randomUUID(),
    seq: 0,
    encryptionKey: new Uint8Array(randomBytes(32)),
    encryptionVariant: 'dataKey',
    metadata,
    metadataVersion: 0,
    agentState: state,
    agentStateVersion: 0,
  }
}
