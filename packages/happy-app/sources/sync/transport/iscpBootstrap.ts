/**
 * Bootstrap an ISCPHappyTransport from a stored ISCP network profile:
 * rebuild the device from its SecureStore seed, fetch a fresh signed relay
 * descriptor (reference services rotate signing keys per boot), and wire the
 * peer link with per-profile cursor persistence (MMKV `cache-<profileId>`)
 * and credential-rotation write-back.
 */

import {
    AGENT_CAPABILITY_PROTOCOL,
    HAPPY_WIRE_PROTOCOL,
} from '@slopus/happy-wire';
import {
    Ed25519PrivateKey,
    RelayHttpClient,
    TrustRootClient,
    createNobleProvider,
    deviceFromStored,
    fromBase64Url,
    verifyRelayDescriptor,
} from '@slopus/iscp';

import { iscpProfileCache, readIscpProfileData, updateIscpProfileCredentials } from '../networkProfile';
import { ISCPHappyTransport } from './ISCPHappyTransport';
import { createIscpPeerLink } from './iscpLink';

/** The app-side capability manifest (counterpart of the agent's agent.capability.v1). */
function appCapabilityManifest() {
    return {
        product_kind: 'happy',
        device_type: 'app',
        device_role: 'owner_app',
        protocol_versions: [AGENT_CAPABILITY_PROTOCOL, HAPPY_WIRE_PROTOCOL],
        capabilities: [],
    };
}

export async function createIscpTransportForProfile(profileId: string): Promise<ISCPHappyTransport> {
    const data = await readIscpProfileData(profileId);
    if (!data) {
        throw new Error(`ISCP profile ${profileId} has no stored credentials`);
    }
    const provider = createNobleProvider();
    const device = deviceFromStored(provider, data.deviceIdentity, new Ed25519PrivateKey(fromBase64Url(data.deviceSeedB64)));

    const relayHttp = new RelayHttpClient({ baseUrl: data.relayBaseUrl, relayId: data.relayId, provider });
    const { descriptor: freshSigned } = await relayHttp.fetchSignedDescriptor();
    const relayDescriptor = verifyRelayDescriptor(provider, freshSigned);

    const trustRoot = new TrustRootClient({ baseUrl: data.trustBaseUrl, trustRootId: data.trustRootId, domainId: data.domainId, provider });

    const link = createIscpPeerLink({
        agentDeviceId: data.agentDeviceId,
        peerOptions: {
            device,
            grant: data.trustGrant,
            relayDescriptor,
            credentials: { accessToken: data.accessToken, refreshToken: data.refreshToken },
            resolvePeerIdentity: async (deviceId) => (await trustRoot.deviceStatus(deviceId)).identity,
            manifest: appCapabilityManifest(),
            provider,
            onCredentialsRotated: (credentials) => {
                void updateIscpProfileCredentials(profileId, credentials);
            },
        },
    });

    const cache = iscpProfileCache(profileId);
    return new ISCPHappyTransport({
        link,
        cursorStore: {
            get: (sessionId) => cache.getString(`cursor:${sessionId}`) ?? null,
            set: (sessionId, cursor) => cache.set(`cursor:${sessionId}`, cursor),
        },
    });
}
