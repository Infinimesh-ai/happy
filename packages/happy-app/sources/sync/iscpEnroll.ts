/**
 * App-side ISCP enrollment (dual-stack Phase 3).
 *
 * Two-step flow so the operator can compare the out-of-band device
 * confirmation code before anything is persisted:
 *   1. enrollIscpDevice(): generate identity locally, then either consume a
 *      signed pairing ticket against the Cloud's managed v2 contract (the
 *      response carries the official device id and the pre-authorized Trust
 *      Grant — no self-authorization) or, without a ticket, local-lab
 *      bind-self + trust self-authorization — returns pending data + code;
 *   2. confirmIscpEnrollment(): persist the profile after the human confirms.
 *
 * The device private key is generated here and stored only in SecureStore
 * under this profile's namespace; it never leaves the device.
 */

import {
    RelayHttpClient,
    TrustRootClient,
    createDevice,
    createNobleProvider,
    decodeEnrollmentFromTransport,
    grantSigningKey,
    identityThumbprint,
    toBase64Url,
    utf8Encode,
    verifyGrant,
    verifyPairingTicket,
    verifyRelayDescriptor,
    verifyTrustRootDescriptor,
    type CryptoProvider,
    type DeviceIdentity,
    type TrustGrant,
    type TrustRootKey,
} from '@slopus/iscp';

import { saveIscpProfile, type IscpProfileData } from './networkProfile';

export interface IscpEnrollOptions {
    relayUrl: string;
    trustUrl: string;
    relayId: string;
    trustRootId: string;
    domainId: string;
    /** The daemon's ISCP device id (shown by `happy iscp status` on the machine). */
    agentDeviceId: string;
    /**
     * base64url enrollment payload from a QR/deep link: the Console/JingSi
     * iscp_enrollment_wrapper or a bare signed ticket. Omit for local-lab
     * bind-self.
     */
    ticket?: string;
    profileId?: string;
}

export interface IscpEnrollmentPending {
    data: IscpProfileData;
    confirmationCode: string;
}

/** Same derivation as happy-cli: 6 digits bound to the long-term identity kid. */
export function deviceConfirmationCode(provider: CryptoProvider, identity: DeviceIdentity): string {
    const digest = provider.sha256(utf8Encode(`iscp/happy/device-confirmation\0${identity.public_key.kid}`));
    const view = new DataView(digest.buffer, digest.byteOffset, digest.byteLength);
    return (view.getUint32(0) % 1_000_000).toString().padStart(6, '0');
}

export async function enrollIscpDevice(opts: IscpEnrollOptions): Promise<IscpEnrollmentPending> {
    const provider = createNobleProvider();

    const relayHttp = new RelayHttpClient({ baseUrl: opts.relayUrl, relayId: opts.relayId, provider });
    const trustRoot = new TrustRootClient({ baseUrl: opts.trustUrl, trustRootId: opts.trustRootId, provider });
    const { descriptor: signedRelay } = await relayHttp.fetchSignedDescriptor();
    verifyRelayDescriptor(provider, signedRelay);
    const signedTrust = await trustRoot.fetchSignedDescriptor();
    const trustDescriptor = verifyTrustRootDescriptor(provider, signedTrust);

    // Wrapper or bare-ticket transport payload (Console/JingSi QR/deep link).
    const payload = opts.ticket !== undefined && opts.ticket !== ''
        ? decodeEnrollmentFromTransport(opts.ticket)
        : undefined;
    const domainId = payload?.ticket.domain_id ?? opts.domainId;

    const deviceId = `happy-app-${toBase64Url(provider.randomBytes(9))}`;
    let device = createDevice(provider, { domainId, deviceId });

    let credentials;
    let grant: TrustGrant;
    if (payload !== undefined) {
        // Managed provisioning (Infinimesh Cloud v2 signed-ticket contract):
        // verify the ticket client-side, register in one call, and take the
        // pre-authorized grant from the response. Never self-authorize here.
        const ticket = payload.ticket;
        if (ticket.relay_id !== opts.relayId || ticket.trust_root_id !== opts.trustRootId) {
            throw new Error(`pairing ticket is bound to ${ticket.relay_id}/${ticket.trust_root_id}, not ${opts.relayId}/${opts.trustRootId}`);
        }
        const ticketKey = trustDescriptor.keys.find((k: TrustRootKey) => k.kid === ticket.signature.kid && k.state !== 'revoked' && k.state !== 'next');
        if (!ticketKey) {
            throw new Error('pairing ticket is not signed by an active trust root key');
        }
        verifyPairingTicket(provider, ticket, ticketKey.public);

        const registration = await relayHttp.registerWithSignedTicket(device, ticket, {
            displayName: payload.displayName,
            metadata: { product_kind: 'happy', runtime_kind: 'happy-app' },
        });
        const officialIdentity: DeviceIdentity = {
            ...device.identity,
            domain_id: registration.data.domain_id,
            device_id: registration.data.device_id,
        };
        device = { identity: officialIdentity, privateKey: device.privateKey };

        // Verify the grant before it is handed to the confirm step.
        grant = registration.grant;
        verifyGrant(provider, grant, grantSigningKey(trustDescriptor, grant.signature.kid), {
            audience: payload.expectedAudiencePhoneId ?? grant.audience,
            subjectDeviceId: officialIdentity.device_id,
            confirmationThumbprint: officialIdentity.public_key.kid,
            permission: grant.permissions[0] ?? 'text',
            relayId: opts.relayId,
        });
        credentials = { access: registration.access, refresh: registration.refresh };
    } else {
        credentials = await relayHttp.bindSelf(device);

        await trustRoot.submitDevice(device);
        // local-lab trust roots leave the operator endpoint open; gated ones
        // reject this and require the provisioning-bundle flow (Phase 4).
        ({ grant } = await trustRoot.authorizeDevice({
            deviceId,
            audience: opts.domainId,
            permissions: ['text'],
            relayId: opts.relayId,
            ttlSeconds: 3600,
        }));
    }

    const profileId = opts.profileId !== undefined && opts.profileId !== ''
        ? opts.profileId
        : `iscp-${device.identity.domain_id}-${opts.relayId}`;
    const data: IscpProfileData = {
        version: 1,
        profileId,
        domainId: device.identity.domain_id,
        relayId: opts.relayId,
        trustRootId: opts.trustRootId,
        relayBaseUrl: opts.relayUrl,
        trustBaseUrl: opts.trustUrl,
        agentDeviceId: opts.agentDeviceId,
        deviceSeedB64: toBase64Url(device.privateKey.bytes),
        deviceIdentity: device.identity,
        accessToken: credentials.access.token as string,
        refreshToken: credentials.refresh.token as string,
        trustGrant: grant,
        relayDescriptor: signedRelay,
        enrolledAt: new Date().toISOString(),
    };
    return { data, confirmationCode: deviceConfirmationCode(provider, device.identity) };
}

/** Persist the profile after the operator confirmed the OOB code (bundle_applied). */
export async function confirmIscpEnrollment(pending: IscpEnrollmentPending): Promise<string> {
    await saveIscpProfile(pending.data);
    return pending.data.profileId;
}

export function identityThumbprintOf(pending: IscpEnrollmentPending): string {
    return identityThumbprint(createNobleProvider(), pending.data.deviceIdentity);
}
