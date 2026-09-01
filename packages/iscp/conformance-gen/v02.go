// ISCP v0.2 vectors (upstream tag v0.2.0-rc.1): pairing ticket v3, session
// control frames, and the credential recovery sealing format. Emitted into
// v02.json and replayed by ../src/conformance/v02.test.ts.
//
// CreateReopen/CreateClose and recovery.Seal draw nonces and ephemerals from
// the process-global CSPRNG, so the objects here are hand-assembled with
// DRBG-sourced randomness and then verified through the SDK's Verify/Open
// paths as a self-check — the wire bytes are what the SDK accepts.
package main

import (
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/canonical"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/provisioning"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/recovery"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/session"
)

func signControlFrame(provider crypto.Provider, dev identity.Device, objectType string, frame any) identity.Signature {
	raw, err := json.Marshal(frame)
	if err != nil {
		panic(err)
	}
	input, err := canonical.SignatureInput(objectType, raw)
	if err != nil {
		panic(err)
	}
	sig := provider.Sign(dev.Private, input)
	return identity.Signature{Alg: "Ed25519", KID: dev.Identity.PublicKey.KID, Value: crypto.Base64URL(sig)}
}

func genV02(out string, meta map[string]any) {
	rng := newDRBG("iscp-conformance-v02")
	provider := crypto.NewProviderWithReader(rng)

	issuer, err := identity.NewDevice(provider, "local", "trust-local-signer", fixedNow)
	if err != nil {
		panic(err)
	}
	issuerSeed := rng.lastRead()
	phone, err := identity.NewDevice(provider, "local", "phone-vector-1", fixedNow)
	if err != nil {
		panic(err)
	}
	phoneSeed := rng.lastRead()
	agent, err := identity.NewDevice(provider, "local", "agent-vector-1", fixedNow)
	if err != nil {
		panic(err)
	}
	agentSeed := rng.lastRead()

	// --- pairing ticket v3 -------------------------------------------------
	ticket, err := provisioning.SignTicketV3(provider, issuer, provisioning.PairingTicketV3{
		TicketID:         "ticket-v3-vector-1",
		DomainID:         "local",
		RelayID:          "relay-local",
		TrustRootID:      "trust-local",
		Purpose:          provisioning.PurposeInvite,
		ConsumerRole:     "member_device",
		GrantAudience:    phone.Identity.DeviceID,
		GrantPermissions: []string{"text"},
		GrantTTLSeconds:  3600,
		MaxUses:          1,
		IssuedAt:         fixedNow,
		ExpiresAt:        fixedNow.Add(10 * time.Minute),
	})
	if err != nil {
		panic(err)
	}
	if err := provisioning.VerifyTicketV3(provider, ticket, issuer.Identity, fixedNow.Add(time.Minute)); err != nil {
		panic(err)
	}
	bindings, err := provisioning.BindGrantRoles(ticket, agent.Identity)
	if err != nil {
		panic(err)
	}
	if _, err := provisioning.BindGrantRoles(ticket, phone.Identity); err == nil {
		panic("audience reversal must be rejected")
	}

	// --- session control frames -------------------------------------------
	reopen := session.Reopen{
		Type:         session.TypeReopen,
		RequestID:    "reopen-vector-1",
		DomainID:     "local",
		DeviceID:     phone.Identity.DeviceID,
		PeerDeviceID: agent.Identity.DeviceID,
		RelayID:      "relay-local",
		Cause:        session.CauseRuntimeStarted,
		IssuedAt:     fixedNow,
		ExpiresAt:    fixedNow.Add(session.ControlFrameMaxTTL),
		Nonce:        crypto.Base64URL(mustRead(rng, 16)),
	}
	reopen.Signature = signControlFrame(provider, phone, session.TypeReopen, reopen)
	if err := session.VerifyReopen(provider, reopen, phone.Identity, session.ReopenVerifyOptions{
		LocalDeviceID: agent.Identity.DeviceID, DomainID: "local", RelayID: "relay-local", Now: fixedNow.Add(2 * time.Second),
	}); err != nil {
		panic(err)
	}

	closeFrame := session.Close{
		Type:         session.TypeClose,
		SessionID:    "session-vector-1",
		DomainID:     "local",
		DeviceID:     agent.Identity.DeviceID,
		PeerDeviceID: phone.Identity.DeviceID,
		RelayID:      "relay-local",
		Reason:       session.CloseReasonShutdown,
		IssuedAt:     fixedNow,
		ExpiresAt:    fixedNow.Add(session.ControlFrameMaxTTL),
		Nonce:        crypto.Base64URL(mustRead(rng, 16)),
	}
	closeFrame.Signature = signControlFrame(provider, agent, session.TypeClose, closeFrame)
	if err := session.VerifyClose(provider, closeFrame, agent.Identity, session.ReopenVerifyOptions{
		LocalDeviceID: phone.Identity.DeviceID, DomainID: "local", RelayID: "relay-local", Now: fixedNow.Add(2 * time.Second),
	}); err != nil {
		panic(err)
	}

	// --- credential recovery sealing ---------------------------------------
	wrapPriv, wrapPub, err := provider.GenerateSessionKey()
	if err != nil {
		panic(err)
	}
	wrapPrivRaw := rng.lastRead()
	serverPriv, serverPub, err := provider.GenerateSessionKey()
	if err != nil {
		panic(err)
	}
	_ = serverPriv
	wrapPublic := crypto.Base64URL(wrapPub.Bytes())
	transcript := recovery.Transcript("local", agent.Identity.DeviceID, agent.Identity.PublicKey.KID)
	plaintext := []byte(`{"access":{"credential_id":"cred_a","token":"tok_a","domain_id":"local","device_id":"agent-vector-1","issued_at":"2026-01-02T03:04:05Z","expires_at":"2026-01-02T03:19:05Z"},"refresh":{"credential_id":"cred_r","token":"tok_r","domain_id":"local","device_id":"agent-vector-1","issued_at":"2026-01-02T03:04:05Z","expires_at":"2026-01-03T03:04:05Z","rotation_counter":1}}`)
	secret, err := provider.SharedSecret(serverPriv, wrapPub)
	if err != nil {
		panic(err)
	}
	info := append(append(append([]byte{}, transcript...), wrapPub.Bytes()...), serverPub.Bytes()...)
	key, err := provider.HKDF(secret, nil, info, 32)
	if err != nil {
		panic(err)
	}
	nonce := mustRead(rng, 12)
	ciphertext, err := provider.Seal(key, nonce, plaintext, transcript)
	if err != nil {
		panic(err)
	}
	wrapped := recovery.WrappedCredentials{
		Type:              recovery.TypeWrappedCredentials,
		Ciphersuite:       crypto.CiphersuiteV2,
		RecoveryPublicKey: wrapPublic,
		ServerPublicKey:   crypto.Base64URL(serverPub.Bytes()),
		Nonce:             crypto.Base64URL(nonce),
		Ciphertext:        crypto.Base64URL(ciphertext),
	}
	opened, err := recovery.Open(provider, wrapped, wrapPriv, wrapPublic, transcript)
	if err != nil {
		panic(err)
	}
	if string(opened) != string(plaintext) {
		panic("recovery self-check plaintext mismatch")
	}

	writeJSON(out, "v02.json", map[string]any{
		"meta": meta,
		"issuer": map[string]any{
			"seed_hex": hex.EncodeToString(issuerSeed),
			"identity": mustJSONMap(issuer.Identity),
		},
		"phone": map[string]any{
			"seed_hex": hex.EncodeToString(phoneSeed),
			"identity": mustJSONMap(phone.Identity),
		},
		"agent": map[string]any{
			"seed_hex": hex.EncodeToString(agentSeed),
			"identity": mustJSONMap(agent.Identity),
		},
		"ticket_v3": map[string]any{
			"ticket":    mustJSONMap(ticket),
			"verify_at": fixedNow.Add(time.Minute).Format(time.RFC3339),
			"grant_role_bindings": map[string]any{
				"subject_device_id":       bindings.SubjectDeviceID,
				"confirmation_thumbprint": bindings.ConfirmationThumbprint,
				"audience":                bindings.Audience,
				"permissions":             bindings.Permissions,
				"relay_id":                bindings.RelayID,
			},
			"audience_reversal_consumer": phone.Identity.DeviceID,
		},
		"session_reopen": map[string]any{
			"frame":     mustJSONMap(reopen),
			"verify_at": fixedNow.Add(2 * time.Second).Format(time.RFC3339),
		},
		"session_close": map[string]any{
			"frame":     mustJSONMap(closeFrame),
			"verify_at": fixedNow.Add(2 * time.Second).Format(time.RFC3339),
		},
		"credential_recovery": map[string]any{
			"wrap_private_hex": hex.EncodeToString(wrapPrivRaw),
			"wrap_public":      wrapPublic,
			"transcript": map[string]any{
				"domain_id":  "local",
				"device_id":  agent.Identity.DeviceID,
				"thumbprint": agent.Identity.PublicKey.KID,
			},
			"wrapped":       mustJSONMap(wrapped),
			"plaintext_hex": hex.EncodeToString(plaintext),
			"challenge_sample": map[string]any{
				"idempotency_key": "idem-key-1",
				"wrap_public":     wrapPublic,
				"challenge":       recovery.Challenge("idem-key-1", wrapPublic),
			},
		},
	})
}

func mustRead(rng *drbg, n int) []byte {
	buf := make([]byte, n)
	if _, err := rng.Read(buf); err != nil {
		panic(err)
	}
	return buf
}
