/**
 * Relay REST client (spec/relay.md, docs/api/openapi.yaml).
 *
 * Envelope submission always attaches the X-ISCP-Access-Proof
 * proof-of-possession header (required by the production profile, ignored by
 * local-lab). The PoP challenge binds method, path, and the SHA-256 of the
 * bearer access token:
 *
 *   iscp/v2/relay/access-proof \0 METHOD \0 PATH \0 base64url(sha256(token))
 */

import { toBase64Url, utf8Encode } from '../encoding';
import { IscpErrorCodes, iscpError, iscpErrorFromWire } from '../errors';
import { createDeviceProof, type Device } from '../identity';
import type { CryptoProvider } from '../crypto/provider';
import {
  DeliveryReceiptSchema,
  SignedDescriptorSchema,
  TrustGrantSchema,
  type DeliveryReceipt,
  type DeviceProof,
  type PairingTicket,
  type SecureEnvelope,
  type SignedDescriptor,
} from '../schemas';
import * as z from 'zod';

/** Access/refresh credential as issued by the reference relay. Tokens are bearer secrets — never log them. */
export const RelayCredentialSchema = z.object({
  domain_id: z.string(),
  device_id: z.string(),
  token: z.string().optional(),
  expires_at: z.string(),
  revoked: z.boolean().optional(),
});
export type RelayCredential = z.infer<typeof RelayCredentialSchema>;

export const RelayCredentialPairSchema = z.object({
  access: RelayCredentialSchema,
  refresh: RelayCredentialSchema,
});
export type RelayCredentialPair = z.infer<typeof RelayCredentialPairSchema>;

/** Device registry record returned by the Cloud's managed registration (`data`). */
export const RegisteredDeviceSchema = z.looseObject({
  device_id: z.string().min(1),
  domain_id: z.string().min(1),
  device_type: z.string().optional(),
  device_role: z.string().optional(),
  display_name: z.string().optional(),
  public_key_thumbprint: z.string().optional(),
});
export type RegisteredDevice = z.infer<typeof RegisteredDeviceSchema>;

/**
 * 201 response of the v2 signed-ticket registration
 * (InfinimeshCloud docs/10-design/12-managed-provisioning.md): the official
 * device record, both relay credentials, and the pre-authorized Trust Grant.
 */
export const SignedTicketRegistrationSchema = z.object({
  data: RegisteredDeviceSchema,
  access: RelayCredentialSchema,
  refresh: RelayCredentialSchema,
  grant: TrustGrantSchema,
});
export type SignedTicketRegistration = z.infer<typeof SignedTicketRegistrationSchema>;

/**
 * 201 response of the v2 grant renewal
 * (`POST /v2/relay/devices/renew-grant`): the device record and the freshly
 * signed Trust Grant. No credentials rotate on renewal.
 */
export const GrantRenewalSchema = z.object({
  data: RegisteredDeviceSchema,
  grant: TrustGrantSchema,
});
export type GrantRenewal = z.infer<typeof GrantRenewalSchema>;

export type FetchLike = (url: string, init?: {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
}) => Promise<{ ok: boolean; status: number; json(): Promise<unknown>; text(): Promise<string> }>;

export function accessProofChallenge(provider: CryptoProvider, method: string, path: string, accessToken: string): string {
  const tokenHash = toBase64Url(provider.sha256(utf8Encode(accessToken)));
  return ['iscp/v2/relay/access-proof', method.toUpperCase(), path, tokenHash].join('\0');
}

async function parseError(response: { status: number; json(): Promise<unknown>; text(): Promise<string> }, context: string): Promise<never> {
  let wire: unknown;
  try {
    wire = await response.json();
  } catch {
    wire = undefined;
  }
  // Infinimesh Cloud error envelope: { error: { code, message, reason, request_id } }.
  // Surface the stable machine reason (ticket_consumed, device_proof_invalid, ...)
  // so callers can react without string-matching human messages.
  if (typeof wire === 'object' && wire !== null && typeof (wire as { error?: unknown }).error === 'object') {
    const err = (wire as { error: Record<string, unknown> }).error;
    if (typeof err.message === 'string' && typeof err.reason === 'string') {
      throw iscpError(IscpErrorCodes.AccessInvalid, `${context} failed with status ${response.status}: ${err.message} (${err.reason})`, {
        details: { reason: err.reason, ...(typeof err.code === 'string' ? { code: err.code } : {}) },
      });
    }
  }
  throw iscpErrorFromWire(wire, `${context} failed with status ${response.status}`);
}

export interface RelayHttpClientOptions {
  baseUrl: string;
  relayId: string;
  provider: CryptoProvider;
  fetchImpl?: FetchLike;
  now?: () => Date;
}

export class RelayHttpClient {
  private readonly baseUrl: string;
  private readonly relayId: string;
  private readonly provider: CryptoProvider;
  private readonly fetchImpl: FetchLike;
  private readonly now: () => Date;

  constructor(opts: RelayHttpClientOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/$/, '');
    this.relayId = opts.relayId;
    this.provider = opts.provider;
    this.fetchImpl = opts.fetchImpl ?? ((url, init) => fetch(url, init));
    this.now = opts.now ?? (() => new Date());
  }

  /** GET /.well-known/iscp/relay — returns the raw signed descriptor plus server-computed pin. */
  async fetchSignedDescriptor(): Promise<{ descriptor: SignedDescriptor; pin?: string }> {
    const response = await this.fetchImpl(`${this.baseUrl}/.well-known/iscp/relay`);
    if (!response.ok) await parseError(response, 'relay discovery');
    const body = (await response.json()) as { descriptor?: unknown; pin?: unknown };
    return {
      descriptor: SignedDescriptorSchema.parse(body.descriptor),
      pin: typeof body.pin === 'string' ? body.pin : undefined,
    };
  }

  /** POST /v2/relay/devices/bind-self — device self-binding with a fresh proof. */
  async bindSelf(device: Device): Promise<RelayCredentialPair> {
    const proof = this.relayProof(device);
    return this.credentialCall('/v2/relay/devices/bind-self', { identity: device.identity, proof });
  }

  /** POST /v2/relay/devices/register-with-ticket — enrollment via pairing ticket. */
  async registerWithTicket(device: Device, ticket: { ticketId: string; maxUses: number }): Promise<RelayCredentialPair> {
    const proof = this.relayProof(device);
    return this.credentialCall('/v2/relay/devices/register-with-ticket', {
      ticket_id: ticket.ticketId,
      max_uses: ticket.maxUses,
      identity: device.identity,
      proof,
    });
  }

  /**
   * POST /v2/relay/devices/register-with-ticket — Infinimesh Cloud managed
   * provisioning (v2 signed-ticket contract, OPS 2026-08-16 §5.5).
   *
   * Sends the full signed ticket, the submitted identity, and a possession
   * proof bound to this relay with `challenge = ticket.ticket_id` (±5 min
   * server window, nonce replay-gated). The enrollee shape (device_type/role)
   * is fixed server-side; this client intentionally sends neither. An
   * `Idempotency-Key` header is generated once and reused on the automatic
   * network-failure retry so an interrupted first attempt is replayed, not
   * double-consumed.
   */
  async registerWithSignedTicket(
    device: Device,
    ticket: PairingTicket,
    opts?: { displayName?: string; metadata?: Record<string, unknown>; idempotencyKey?: string },
  ): Promise<SignedTicketRegistration> {
    const proof = createDeviceProof(this.provider, device, {
      audience: this.relayId,
      challenge: ticket.ticket_id,
      now: this.now(),
    });
    const path = '/v2/relay/devices/register-with-ticket';
    const body = JSON.stringify({
      ticket,
      identity: device.identity,
      identity_proof: proof,
      ...(opts?.displayName !== undefined ? { display_name: opts.displayName } : {}),
      ...(opts?.metadata !== undefined ? { metadata: opts.metadata } : {}),
    });
    const headers = {
      'Content-Type': 'application/json',
      'Idempotency-Key': opts?.idempotencyKey ?? toBase64Url(this.provider.randomBytes(18)),
    };
    let response;
    try {
      response = await this.fetchImpl(`${this.baseUrl}${path}`, { method: 'POST', headers, body });
    } catch {
      // Network interruption: retry once with the identical body and
      // Idempotency-Key — if the first request landed, the Cloud replays the
      // stored response instead of consuming the ticket again.
      response = await this.fetchImpl(`${this.baseUrl}${path}`, { method: 'POST', headers, body });
    }
    if (!response.ok) await parseError(response, 'signed-ticket registration');
    const raw = (await response.json()) as { grant?: unknown };
    if (raw === null || typeof raw !== 'object' || raw.grant === undefined) {
      throw iscpError(IscpErrorCodes.TrustInvalid, 'signed-ticket registration did not return a trust grant');
    }
    const parsed = SignedTicketRegistrationSchema.parse(raw);
    if (!parsed.access.token || !parsed.refresh.token) {
      throw iscpError(IscpErrorCodes.AccessInvalid, 'relay did not return credential tokens');
    }
    return parsed;
  }

  /**
   * POST /v2/relay/devices/renew-grant — Infinimesh Cloud grant renewal
   * (frozen contract, OPS 2026-08-17 §4.3).
   *
   * Sends the renewal id, the enrolled identity, and a possession proof bound
   * to this relay with `challenge = renewal_id`. The device key never changes:
   * renewal only re-issues the Trust Grant for the already-registered device.
   * An `Idempotency-Key` header is generated once and reused on the automatic
   * network-failure retry so an interrupted first attempt is replayed, not
   * double-consumed.
   */
  async renewGrant(
    device: Device,
    renewalId: string,
    opts?: { idempotencyKey?: string },
  ): Promise<GrantRenewal> {
    const proof = createDeviceProof(this.provider, device, {
      audience: this.relayId,
      challenge: renewalId,
      now: this.now(),
    });
    const path = '/v2/relay/devices/renew-grant';
    const body = JSON.stringify({
      renewal_id: renewalId,
      identity: device.identity,
      identity_proof: proof,
    });
    const headers = {
      'Content-Type': 'application/json',
      'Idempotency-Key': opts?.idempotencyKey ?? toBase64Url(this.provider.randomBytes(18)),
    };
    let response;
    try {
      response = await this.fetchImpl(`${this.baseUrl}${path}`, { method: 'POST', headers, body });
    } catch {
      // Network interruption: retry once with the identical body and
      // Idempotency-Key — if the first request landed, the Cloud replays the
      // stored response instead of consuming the renewal again.
      response = await this.fetchImpl(`${this.baseUrl}${path}`, { method: 'POST', headers, body });
    }
    if (!response.ok) await parseError(response, 'grant renewal');
    const raw = (await response.json()) as { grant?: unknown };
    if (raw === null || typeof raw !== 'object' || raw.grant === undefined) {
      throw iscpError(IscpErrorCodes.TrustInvalid, 'grant renewal did not return a trust grant');
    }
    return GrantRenewalSchema.parse(raw);
  }

  /** POST /v2/relay/devices/refresh-access — rotates both credentials; the old refresh credential is revoked. */
  async refreshAccess(refreshToken: string): Promise<RelayCredentialPair> {
    return this.credentialCall('/v2/relay/devices/refresh-access', { refresh: refreshToken });
  }

  /** POST /v2/relay/devices/revoke-access — self-revocation with the device's own access credential. */
  async revokeAccess(deviceId: string, accessToken: string): Promise<void> {
    const response = await this.fetchImpl(`${this.baseUrl}/v2/relay/devices/revoke-access`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${accessToken}`,
      },
      body: JSON.stringify({ device_id: deviceId }),
    });
    if (!response.ok) await parseError(response, 'relay access revocation');
  }

  /** POST /v2/relay/envelopes — submit an opaque envelope; returns the relay receipt (not an E2E receipt). */
  async submitEnvelope(envelope: SecureEnvelope, device: Device, accessToken: string): Promise<DeliveryReceipt> {
    const path = '/v2/relay/envelopes';
    const proof = this.accessProof(device, 'POST', path, accessToken);
    const response = await this.fetchImpl(`${this.baseUrl}${path}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${accessToken}`,
        'X-ISCP-Access-Proof': toBase64Url(utf8Encode(JSON.stringify(proof))),
      },
      body: JSON.stringify(envelope),
    });
    if (!response.ok) await parseError(response, 'envelope submission');
    return DeliveryReceiptSchema.parse(await response.json());
  }

  /** DeviceProof for relay HTTP binding endpoints (self-declared challenge, relay audience). */
  relayProof(device: Device): DeviceProof {
    return createDeviceProof(this.provider, device, {
      audience: this.relayId,
      challenge: toBase64Url(this.provider.randomBytes(16)),
      now: this.now(),
    });
  }

  /** DeviceProof for the X-ISCP-Access-Proof PoP header. */
  accessProof(device: Device, method: string, path: string, accessToken: string): DeviceProof {
    return createDeviceProof(this.provider, device, {
      audience: this.relayId,
      challenge: accessProofChallenge(this.provider, method, path, accessToken),
      now: this.now(),
    });
  }

  private async credentialCall(path: string, body: unknown): Promise<RelayCredentialPair> {
    const response = await this.fetchImpl(`${this.baseUrl}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!response.ok) await parseError(response, `relay ${path}`);
    const pair = RelayCredentialPairSchema.parse(await response.json());
    if (!pair.access.token || !pair.refresh.token) {
      throw iscpError(IscpErrorCodes.AccessInvalid, 'relay did not return credential tokens');
    }
    return pair;
  }
}
