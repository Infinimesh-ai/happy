/**
 * Trust Root client (spec/trust-root.md): device submit/authorize polling,
 * Trust Grant verification (remote and local), revocations feed, key
 * rotation state.
 *
 * Relay access is never trust authorization; grants come only from here.
 */

import * as z from 'zod';

import { parseRfc3339, toBase64Url } from './encoding';
import { IscpErrorCodes, iscpError, iscpErrorFromWire } from './errors';
import { createDeviceProof, type Device } from './identity';
import { verifyObjectSignature } from './signing';
import type { CryptoProvider } from './crypto/provider';
import type { FetchLike } from './relay/http';
import {
  DeviceIdentitySchema,
  SignedDescriptorSchema,
  TRUST_GRANT_TYPE,
  TrustGrantSchema,
  type SignedDescriptor,
  type TrustGrant,
  type TrustRootDescriptor,
} from './schemas';

/**
 * ISCP v0.2 normative read shapes (spec/trust-root.md,
 * schemas/json/trust.*.v2.json): the union parsing that once bridged the
 * reference implementation and managed Cloud deployments is gone — both now
 * emit these typed responses. The `type` discriminators are validated when
 * present but tolerated when absent so the migration window's untyped
 * emissions keep parsing.
 */
export const TrustDeviceRecordSchema = z.object({
  type: z.literal('iscp.trust.device_status.v2').optional(),
  identity: DeviceIdentitySchema,
  status: z.enum(['submitted', 'authorized', 'revoked']).or(z.string()),
  device_record_version: z.number().int().min(0),
  revocation_epoch: z.number().int().min(0),
});
export type TrustDeviceRecord = z.infer<typeof TrustDeviceRecordSchema>;

const GrantStatusEnvelopeSchema = z.object({
  type: z.literal('iscp.trust.grant_status.v2').optional(),
  grant: TrustGrantSchema,
  status: z.enum(['active', 'revoked', 'expired']),
});

const RevocationItemSchema = z.object({
  revocation_id: z.string().min(1),
  domain_id: z.string().min(1),
  device_id: z.string().min(1).optional(),
  grant_id: z.string().min(1).optional(),
  reason_code: z.string(),
  effective_at: z.string(),
});
const RevocationListSchema = z.object({
  type: z.literal('iscp.trust.revocations.v2').optional(),
  items: z.array(RevocationItemSchema),
  next_cursor: z.string().min(1).optional(),
});

export interface VerifyGrantOptions {
  audience: string;
  subjectDeviceId: string;
  confirmationThumbprint: string;
  permission: string;
  relayId?: string;
  currentRevocationEpoch?: number;
  now?: Date;
}

/**
 * Client-side Trust Grant verification mirroring the Go reference
 * (pkg/iscp/trust/trust.go VerifyGrant): validity window, audience, subject,
 * confirmation key thumbprint, permission, relay constraint, revocation
 * epoch, then the Ed25519 signature against the given trust root key.
 */
export function verifyGrant(
  provider: CryptoProvider,
  grant: TrustGrant,
  issuerPublicKeyBase64Url: string,
  opts: VerifyGrantOptions,
): void {
  const parsed = TrustGrantSchema.parse(grant);
  const now = (opts.now ?? new Date()).getTime();
  if (now < parseRfc3339(parsed.not_before).getTime() || now >= parseRfc3339(parsed.expires_at).getTime()) {
    throw iscpError(IscpErrorCodes.TrustInvalid, 'trust grant is not currently valid');
  }
  if (parsed.audience !== opts.audience) {
    throw iscpError(IscpErrorCodes.TrustInvalid, 'trust grant audience mismatch');
  }
  if (parsed.subject_device_id !== opts.subjectDeviceId) {
    throw iscpError(IscpErrorCodes.TrustInvalid, 'trust grant subject mismatch');
  }
  if (parsed.confirmation_thumbprint !== opts.confirmationThumbprint) {
    throw iscpError(IscpErrorCodes.TrustInvalid, 'trust grant confirmation mismatch');
  }
  if (!parsed.permissions.includes(opts.permission)) {
    throw iscpError(IscpErrorCodes.TrustInvalid, 'trust grant permission denied');
  }
  if (parsed.relay_constraints && parsed.relay_constraints.length > 0) {
    if (opts.relayId === undefined || !parsed.relay_constraints.includes(opts.relayId)) {
      throw iscpError(IscpErrorCodes.TrustInvalid, 'trust grant relay constraint mismatch');
    }
  }
  if (parsed.revocation_epoch < (opts.currentRevocationEpoch ?? 0)) {
    throw iscpError(IscpErrorCodes.TrustInvalid, 'trust grant has been revoked');
  }
  verifyObjectSignature(provider, TRUST_GRANT_TYPE, parsed, issuerPublicKeyBase64Url, IscpErrorCodes.TrustInvalid, 'trust grant signature verification failed');
}

/** Find the descriptor key a grant's signature kid refers to (revoked keys rejected). */
export function grantSigningKey(descriptor: TrustRootDescriptor, kid: string): string {
  const key = descriptor.keys.find((k) => k.kid === kid && k.state !== 'revoked' && k.state !== 'next');
  if (!key) {
    throw iscpError(IscpErrorCodes.TrustInvalid, 'trust grant signing key is unknown or not active');
  }
  return key.public;
}

async function parseError(response: { status: number; json(): Promise<unknown> }, context: string): Promise<never> {
  let wire: unknown;
  try {
    wire = await response.json();
  } catch {
    wire = undefined;
  }
  throw iscpErrorFromWire(wire, `${context} failed with status ${response.status}`);
}

export interface TrustRootClientOptions {
  baseUrl: string;
  trustRootId: string;
  provider: CryptoProvider;
  fetchImpl?: FetchLike;
  /** Operator credential; required by the production profile for authorize/revoke/rotate. */
  adminToken?: string;
  /**
   * Tenant domain for managed trust roots. Multi-tenant deployments
   * (Infinimesh Cloud) require it on every read query; the single-domain
   * reference implementation ignores it. Always set it for managed profiles —
   * the enrollment bundle carries the value.
   */
  domainId?: string;
  now?: () => Date;
}

export class TrustRootClient {
  private readonly baseUrl: string;
  private readonly trustRootId: string;
  private readonly provider: CryptoProvider;
  private readonly fetchImpl: FetchLike;
  private readonly adminToken?: string;
  private readonly domainId?: string;
  private readonly now: () => Date;

  constructor(opts: TrustRootClientOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/$/, '');
    this.trustRootId = opts.trustRootId;
    this.provider = opts.provider;
    this.fetchImpl = opts.fetchImpl ?? ((url, init) => fetch(url, init));
    this.adminToken = opts.adminToken;
    this.domainId = opts.domainId;
    this.now = opts.now ?? (() => new Date());
  }

  private domainQuery(prefix: '?' | '&'): string {
    return this.domainId === undefined ? '' : `${prefix}domain_id=${encodeURIComponent(this.domainId)}`;
  }

  /** GET /.well-known/iscp/trust-root */
  async fetchSignedDescriptor(): Promise<SignedDescriptor> {
    const response = await this.fetchImpl(`${this.baseUrl}/.well-known/iscp/trust-root`);
    if (!response.ok) await parseError(response, 'trust root discovery');
    const body = (await response.json()) as { descriptor?: unknown };
    return SignedDescriptorSchema.parse(body.descriptor);
  }

  /** POST /v2/trust/devices/submit — device submits its identity with a possession proof. */
  async submitDevice(device: Device, context?: Record<string, string>): Promise<TrustDeviceRecord> {
    const proof = createDeviceProof(this.provider, device, {
      audience: this.trustRootId,
      challenge: toBase64Url(this.provider.randomBytes(16)),
      now: this.now(),
    });
    const body = await this.post('/v2/trust/devices/submit', {
      identity: device.identity,
      proof,
      ...(context !== undefined ? { context } : {}),
    }, false, 'device submission');
    return TrustDeviceRecordSchema.parse(body);
  }

  /**
   * GET /v2/trust/devices/status?device_id=...[&domain_id=...]
   *
   * Managed Cloud responses are a superset of the reference shape (flat
   * compatibility fields beside the canonical nested `identity`); the
   * non-strict record schema accepts both.
   */
  async deviceStatus(deviceId: string): Promise<TrustDeviceRecord> {
    const response = await this.fetchImpl(`${this.baseUrl}/v2/trust/devices/status?device_id=${encodeURIComponent(deviceId)}${this.domainQuery('&')}`);
    if (!response.ok) await parseError(response, 'device status');
    return TrustDeviceRecordSchema.parse(await response.json());
  }

  /** Poll device status until it is authorized (or the timeout/abort fires). */
  async waitForAuthorization(deviceId: string, opts?: { intervalMs?: number; timeoutMs?: number; signal?: AbortSignal }): Promise<TrustDeviceRecord> {
    const intervalMs = opts?.intervalMs ?? 2000;
    const deadline = Date.now() + (opts?.timeoutMs ?? 5 * 60 * 1000);
    for (;;) {
      if (opts?.signal?.aborted) {
        throw iscpError(IscpErrorCodes.TrustInvalid, 'authorization polling aborted');
      }
      const record = await this.deviceStatus(deviceId);
      if (record.status === 'authorized') return record;
      if (record.status === 'revoked') {
        throw iscpError(IscpErrorCodes.TrustInvalid, 'device has been revoked');
      }
      if (Date.now() >= deadline) {
        throw iscpError(IscpErrorCodes.TrustInvalid, 'timed out waiting for device authorization', { retryable: true });
      }
      await new Promise((resolve) => setTimeout(resolve, intervalMs));
    }
  }

  /** POST /v2/trust/devices/authorize (admin) — authorizes a device and issues a Trust Grant. */
  async authorizeDevice(req: { deviceId: string; audience: string; permissions: string[]; relayId: string; ttlSeconds?: number }): Promise<{ device: TrustDeviceRecord; grant: TrustGrant }> {
    const body = await this.post('/v2/trust/devices/authorize', {
      device_id: req.deviceId,
      audience: req.audience,
      permissions: req.permissions,
      relay_id: req.relayId,
      ttl_seconds: req.ttlSeconds ?? 0,
    }, true, 'device authorization') as { device?: unknown; grant?: unknown };
    return {
      device: TrustDeviceRecordSchema.parse(body.device),
      grant: TrustGrantSchema.parse(body.grant),
    };
  }

  /** POST /v2/trust/devices/revoke (admin) — bumps the device revocation epoch. */
  async revokeDevice(deviceId: string, reason: string): Promise<TrustDeviceRecord> {
    const body = await this.post('/v2/trust/devices/revoke', { device_id: deviceId, reason }, true, 'device revocation');
    return TrustDeviceRecordSchema.parse(body);
  }

  /** POST /v2/trust/grants/verify — remote grant verification. Resolves false on 403. */
  async verifyGrantRemote(req: {
    grant: TrustGrant;
    audience: string;
    subjectDeviceId: string;
    confirmationThumbprint: string;
    permission: string;
    relayId: string;
  }): Promise<boolean> {
    const response = await this.fetchImpl(`${this.baseUrl}/v2/trust/grants/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant: req.grant,
        audience: req.audience,
        subject_device_id: req.subjectDeviceId,
        confirmation_thumbprint: req.confirmationThumbprint,
        permission: req.permission,
        relay_id: req.relayId,
      }),
    });
    if (response.status === 403) return false;
    if (!response.ok) await parseError(response, 'grant verification');
    return true;
  }

  /**
   * GET /v2/trust/grants/status?grant_id=...[&domain_id=...]
   *
   * ISCP v0.2 iscp.trust.grant_status.v2 envelope; the lifecycle status is
   * `active | revoked | expired` with revoked winning over expired.
   */
  async grantStatus(grantId: string): Promise<TrustGrant> {
    const response = await this.fetchImpl(`${this.baseUrl}/v2/trust/grants/status?grant_id=${encodeURIComponent(grantId)}${this.domainQuery('&')}`);
    if (!response.ok) await parseError(response, 'grant status');
    return GrantStatusEnvelopeSchema.parse(await response.json()).grant;
  }

  /**
   * GET /v2/trust/revocations[?domain_id=...&cursor=...] — device id →
   * revocation epoch, consumed as the ISCP v0.2 iscp.trust.revocations.v2
   * paginated feed. Pages are followed until next_cursor is absent (bounded);
   * managed device revocation is single-epoch, so a device-scoped item maps
   * to epoch 1; grant-only items do not raise a device epoch and are dropped
   * from this projection (grant lifecycle is read via grantStatus).
   */
  async revocations(): Promise<Record<string, number>> {
    const epochs: Record<string, number> = {};
    let cursor: string | undefined;
    // 64 pages × up-to-200 items bounds a hostile/looping feed without
    // truncating any realistic deployment.
    for (let page = 0; page < 64; page++) {
      const cursorQuery = cursor !== undefined ? `${this.domainId !== undefined ? '&' : '?'}cursor=${encodeURIComponent(cursor)}` : '';
      const response = await this.fetchImpl(`${this.baseUrl}/v2/trust/revocations${this.domainQuery('?')}${cursorQuery}`);
      if (!response.ok) await parseError(response, 'revocations feed');
      const body = RevocationListSchema.parse(await response.json());
      for (const item of body.items) {
        if (item.device_id !== undefined) {
          epochs[item.device_id] = Math.max(epochs[item.device_id] ?? 0, 1);
        }
      }
      if (body.next_cursor === undefined) return epochs;
      cursor = body.next_cursor;
    }
    throw iscpError(IscpErrorCodes.TrustInvalid, 'revocations feed did not terminate within the page bound', { retryable: true });
  }

  /** POST /v2/trust/keys/rotate (admin) — promotes the next signing key to active. */
  async rotateKeys(): Promise<{ activeKeyId: string }> {
    const body = await this.post('/v2/trust/keys/rotate', {}, true, 'key rotation') as { active_key_id?: unknown };
    if (typeof body.active_key_id !== 'string') {
      throw iscpError(IscpErrorCodes.TrustInvalid, 'key rotation did not return an active key id');
    }
    return { activeKeyId: body.active_key_id };
  }

  private async post(path: string, body: unknown, admin: boolean, context: string): Promise<unknown> {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (admin && this.adminToken !== undefined) {
      headers['X-ISCP-Admin-Token'] = this.adminToken;
    }
    const response = await this.fetchImpl(`${this.baseUrl}${path}`, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
    });
    if (!response.ok) await parseError(response, context);
    return response.json();
  }
}
