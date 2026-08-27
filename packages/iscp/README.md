# @slopus/iscp

TypeScript client for **ISCP protocol v2**, implemented from the pinned
[Infinimesh-ai/ISCP](https://github.com/Infinimesh-ai/ISCP) specification for
Happy's dual-stack networking (see `docs/network-dual-stack/`). Pure TS, dual
CJS/ESM, runs on Node (happy-cli) and React Native/Hermes (happy-app).

## Spec pinning

Everything here is derived from one upstream revision, recorded in
[`scripts/pin.json`](scripts/pin.json) (commit `fa1d493c…`, which is upstream
tag `v0.2.0-rc.1`, the ISCP v0.2 pre-release). The upstream conformance suite is a Go test package, not
portable vectors, so [`conformance-gen/`](conformance-gen/) imports the pinned
Go module and emits deterministic cross-implementation vectors into
[`test/vectors/`](test/vectors/); the vitest suite replays them against this
implementation (canonical bytes, signatures, transcript hashes, session keys,
AEAD ciphertexts are asserted byte-identical to Go).

Bumping the pin: update `scripts/pin.json` + `conformance-gen/go.mod`
(`go get github.com/Infinimesh-ai/ISCP@<sha>`), re-read `spec/` and
`schemas/json/`, then `pnpm sync-vectors && pnpm test`.

## Layout

| Path | What |
| --- | --- |
| `src/jcs.ts` | Strict canonical JSON (Go `encoding/json`-compatible escaping) + `ISCP-V2-SIGNATURE\0<type>\0<json>` signature input |
| `src/crypto/` | `provider.ts` interface (native-acceleration seam, branded key types) + noble implementation (Ed25519/X25519/HKDF-SHA256/ChaCha20-Poly1305) |
| `src/identity.ts` | Device identity, thumbprints, Device Proof challenge/response |
| `src/schemas/` | Zod mirrors of the 13 upstream JSON schemas (one object per file, `$id` recorded) |
| `src/provisioning/` | Pairing Ticket, Local Secure Channel (X25519 + OOB code), Provisioning Bundle |
| `src/trustRoot.ts` | Trust Root client: submit/authorize polling, grant verification (local + remote), revocations feed, key rotation |
| `src/relay/` | `/.well-known` discovery + descriptor pinning, envelope submission with `X-ISCP-Access-Proof` PoP, WS state machine (`CONNECTED→CHALLENGE_SENT→POP_VERIFIED→READY`) with backoff reconnect |
| `src/session/` | Hello/Ready handshake (transcript-bound HKDF), SecureEnvelope AEAD+AAD, per-direction seq+nonce replay stores with persistence hooks |
| `src/peer.ts` | `IscpPeer`: sessions over a relay; business payloads refused before `session.ready`; first payload is the `agent.capability.v1` manifest (schema in `@slopus/happy-wire`) |
| `src/storage.ts` / `src/ws-adapter.ts` | `CredentialStore`/`StateStore` injection seams (CLI: 0600 files, RN: SecureStore+MMKV) and Node `ws` / global WebSocket adapter |

Handshake transport note: session hello/ready are signed public objects with
no session key yet, so they ride in envelope-shaped messages whose
`payload_type` is the handshake object type and whose `ciphertext` carries
base64url(JSON) — a documented Happy-layer convention (see `src/peer.ts`).

## Testing

```bash
pnpm --filter @slopus/iscp test          # unit + Go-vector conformance (no docker needed)
pnpm --filter @slopus/iscp bench         # ChaCha20-Poly1305 throughput (Hermes risk tracking)

# Integration against the upstream Go reference services:
docker compose -f environments/iscp/docker-compose.yaml up --build -d
ISCP_HARNESS=1 pnpm --filter @slopus/iscp test:integration
docker compose -f environments/iscp/docker-compose.yaml down
```

The integration suite covers: dual-device enrollment → handshake → envelopes
both ways → WS kill + reconnect → relay offline-queue drain → replayed
envelope rejected by the receiver → trust revocation (epoch feed + grant
verification) and relay access revocation (submit/WS/refresh all refused).

Security invariants are enforced by tests: no `console.*` in runtime sources,
no serialization of key material, AEAD errors never echo keys
(`src/noSecretLeak.test.ts`), Ed25519/X25519 key-type separation
(NEG-004), payload-before-ready refusal (NEG-008), route tamper (NEG-009),
replay (NEG-010), revocation/audience/confirmation binding (NEG-012..014).

## CLI

`happy iscp enroll` (packages/happy-cli/src/iscp/enrollment.ts) enrolls the
machine against a relay + trust root, prints a 6-digit device confirmation
code for out-of-band operator comparison, and persists the profile to
`~/.happy/iscp/<profileId>/` (`device.key` + `bundle.json`, 0600, dir 0700) —
fully isolated from legacy `~/.happy` state.
