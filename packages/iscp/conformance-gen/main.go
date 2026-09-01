// Conformance vector generator for @slopus/iscp.
//
// Runs against the pinned Infinimesh-ai/ISCP Go reference implementation
// (see ../scripts/pin.json) with a deterministic random stream and fixed
// timestamps, and emits JSON vectors consumed by the vitest conformance
// suite in ../src/conformance. Regenerate via `pnpm sync-vectors`.
//
// Vectors intentionally include private key material: they are fixed test
// fixtures shared between the Go and TypeScript implementations, never real
// credentials.
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/canonical"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/envelope"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/provisioning"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/session"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/trust"
)

// drbg is a deterministic reader (SHA-256 counter stream) that records every
// chunk it hands out, so generated private keys can be exported to vectors.
type drbg struct {
	seed    []byte
	counter uint64
	buf     []byte
	reads   [][]byte
}

func newDRBG(seed string) *drbg {
	sum := sha256.Sum256([]byte(seed))
	return &drbg{seed: sum[:]}
}

func (d *drbg) Read(p []byte) (int, error) {
	for len(d.buf) < len(p) {
		block := make([]byte, 8)
		binary.BigEndian.PutUint64(block, d.counter)
		d.counter++
		sum := sha256.Sum256(append(append([]byte{}, d.seed...), block...))
		d.buf = append(d.buf, sum[:]...)
	}
	copy(p, d.buf[:len(p)])
	d.buf = d.buf[len(p):]
	read := make([]byte, len(p))
	copy(read, p)
	d.reads = append(d.reads, read)
	return len(p), nil
}

func (d *drbg) lastRead() []byte {
	return d.reads[len(d.reads)-1]
}

var fixedNow = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func writeJSON(dir, name string, value any) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), append(data, '\n'), 0o644); err != nil {
		panic(err)
	}
	fmt.Println("wrote", name)
}

func mustJSONMap(v any) map[string]any {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		panic(err)
	}
	return out
}

func main() {
	out := flag.String("out", "../test/vectors", "output directory")
	pin := flag.String("pin", "", "pinned upstream commit (recorded in vectors)")
	flag.Parse()
	if err := os.MkdirAll(*out, 0o755); err != nil {
		panic(err)
	}

	meta := map[string]any{
		"generator": "packages/iscp/conformance-gen",
		"pin":       *pin,
		"note":      "deterministic fixtures; private keys here are shared test material, not credentials",
	}

	genJCS(*out, meta)
	genThumbprint(*out, meta)
	genIdentity(*out, meta)
	genSession(*out, meta)
	genProvisioning(*out, meta)
	genTrustGrant(*out, meta)
	genAccessProof(*out, meta)
	genV02(*out, meta)
}

func genJCS(out string, meta map[string]any) {
	type okCase struct {
		Name      string `json:"name"`
		Input     string `json:"input"`
		Canonical string `json:"canonical"`
	}
	type errCase struct {
		Name  string `json:"name"`
		Input string `json:"input"`
	}
	type sigCase struct {
		Name              string `json:"name"`
		ObjectType        string `json:"object_type"`
		Input             string `json:"input"`
		SignatureInputHex string `json:"signature_input_hex"`
	}

	okInputs := []struct{ name, input string }{
		{"empty-object", `{}`},
		{"sorted-keys", `{"b":1,"a":2,"c":3}`},
		{"nested", `{"z":{"y":[1,2,{"x":null}],"w":true},"a":"s"}`},
		{"html-escapes", `{"s":"<script>a&b</script>"}`},
		{"unicode", `{"s":"héllo wörld 汉字 🎉"}`},
		{"unicode-keys", `{"é":1,"a":2,"z":3,"汉":4}`},
		{"astral-key-order", `{"🎉":1,"�":2}`},
		{"line-separators", `{"s":"a b c"}`},
		{"control-chars", `{"s":"a\u0001b\nc\td\re"}`},
		{"escaped-quotes", `{"s":"say \"hi\" \\ done"}`},
		{"int64-bounds", `{"max":9223372036854775807,"min":-9223372036854775808,"zero":0}`},
		{"negative", `{"n":-42}`},
		{"array-of-scalars", `[null,true,false,"x",7]`},
		{"whitespace", "{\n  \"a\" : 1 ,\n  \"b\" : [ 1 , 2 ]\n}"},
		{"empty-string-value", `{"ciphertext":"","a":1}`},
	}
	var okCases []okCase
	for _, c := range okInputs {
		canon, err := canonical.Marshal([]byte(c.input))
		if err != nil {
			panic(fmt.Sprintf("case %s: %v", c.name, err))
		}
		okCases = append(okCases, okCase{Name: c.name, Input: c.input, Canonical: string(canon)})
	}

	errInputs := []struct{ name, input string }{
		{"duplicate-key", `{"a":1,"a":2}`},
		{"float", `{"a":1.5}`},
		{"exponent", `{"a":1e3}`},
		{"negative-zero", `{"a":-0}`},
		{"leading-zero", `{"a":01}`},
		{"int64-overflow", `{"a":9223372036854775808}`},
		{"trailing-data", `{"a":1} {"b":2}`},
		{"top-level-two-values", `1 2`},
	}
	var errCases []errCase
	for _, c := range errInputs {
		if _, err := canonical.Marshal([]byte(c.input)); err == nil {
			panic(fmt.Sprintf("case %s: expected error", c.name))
		}
		errCases = append(errCases, errCase{Name: c.name, Input: c.input})
	}

	sigInputs := []struct{ name, objectType, input string }{
		{"strips-signature", "iscp.device.proof.v2", `{"b":2,"signature":{"alg":"Ed25519","kid":"k","value":"v"},"a":1}`},
		{"no-signature-field", "iscp.test.v2", `{"a":1}`},
		{"nested-signature-kept", "iscp.test.v2", `{"outer":{"signature":"inner kept"},"a":1}`},
	}
	var sigCases []sigCase
	for _, c := range sigInputs {
		input, err := canonical.SignatureInput(c.objectType, []byte(c.input))
		if err != nil {
			panic(err)
		}
		sigCases = append(sigCases, sigCase{Name: c.name, ObjectType: c.objectType, Input: c.input, SignatureInputHex: hex.EncodeToString(input)})
	}

	writeJSON(out, "jcs.json", map[string]any{
		"meta":             meta,
		"canonical":        okCases,
		"rejected":         errCases,
		"signature_inputs": sigCases,
	})
}

func genThumbprint(out string, meta map[string]any) {
	type tpCase struct {
		Name       string `json:"name"`
		KeyType    string `json:"key_type"`
		PublicHex  string `json:"public_hex"`
		Thumbprint string `json:"thumbprint"`
	}
	var cases []tpCase
	for i := 0; i < 3; i++ {
		pub := make([]byte, 32)
		for j := range pub {
			pub[j] = byte(i*31 + j)
		}
		cases = append(cases, tpCase{
			Name:       fmt.Sprintf("ed25519-%d", i),
			KeyType:    "Ed25519",
			PublicHex:  hex.EncodeToString(pub),
			Thumbprint: crypto.Thumbprint("Ed25519", pub),
		})
	}
	writeJSON(out, "thumbprint.json", map[string]any{"meta": meta, "cases": cases})
}

func genIdentity(out string, meta map[string]any) {
	rng := newDRBG("iscp-conformance-identity")
	provider := crypto.NewProviderWithReader(rng)
	dev, err := identity.NewDevice(provider, "local", "device-vector-a", fixedNow)
	if err != nil {
		panic(err)
	}
	seed := rng.lastRead() // ed25519.GenerateKey read exactly one 32-byte seed
	proof, err := dev.CreateProof(provider, "relay-local", "challenge-vector-0001", "nonce-vector-0001", fixedNow)
	if err != nil {
		panic(err)
	}
	if err := identity.VerifyProof(provider, dev.Identity, proof, "relay-local", "challenge-vector-0001", fixedNow, 5*time.Minute); err != nil {
		panic(err)
	}
	tp, err := identity.Thumbprint(dev.Identity)
	if err != nil {
		panic(err)
	}
	writeJSON(out, "identity.json", map[string]any{
		"meta":       meta,
		"seed_hex":   hex.EncodeToString(seed),
		"identity":   mustJSONMap(dev.Identity),
		"thumbprint": tp,
		"proof": map[string]any{
			"audience":  "relay-local",
			"challenge": "challenge-vector-0001",
			"nonce":     "nonce-vector-0001",
			"issued_at": fixedNow.Format(time.RFC3339),
			"object":    mustJSONMap(proof),
		},
	})
}

func genSession(out string, meta map[string]any) {
	rng := newDRBG("iscp-conformance-session")
	provider := crypto.NewProviderWithReader(rng)

	devA, err := identity.NewDevice(provider, "local", "device-alpha", fixedNow)
	if err != nil {
		panic(err)
	}
	seedA := rng.lastRead()
	devB, err := identity.NewDevice(provider, "local", "device-beta", fixedNow)
	if err != nil {
		panic(err)
	}
	seedB := rng.lastRead()

	helloA, err := session.CreateHello(provider, devA, "sess-vector-1", devB.Identity.DeviceID, "grant-vector-1", fixedNow)
	if err != nil {
		panic(err)
	}
	ephA := rng.lastRead()
	helloB, err := session.CreateHello(provider, devB, "sess-vector-1", devA.Identity.DeviceID, "grant-vector-1", fixedNow)
	if err != nil {
		panic(err)
	}
	ephB := rng.lastRead()

	stA, err := session.Establish(provider, helloA, helloB.Hello, devA.Identity, devB.Identity)
	if err != nil {
		panic(err)
	}
	stB, err := session.Establish(provider, helloB, helloA.Hello, devB.Identity, devA.Identity)
	if err != nil {
		panic(err)
	}
	readyA, err := stA.CreateReady(provider, devA)
	if err != nil {
		panic(err)
	}
	readyB, err := stB.CreateReady(provider, devB)
	if err != nil {
		panic(err)
	}
	if err := stA.VerifyReady(provider, readyB, devB.Identity); err != nil {
		panic(err)
	}
	if err := stB.VerifyReady(provider, readyA, devA.Identity); err != nil {
		panic(err)
	}

	plaintextAtoB := []byte(`{"text":"hello from alpha"}`)
	envAtoB, err := envelope.Encrypt(provider, stA, "msg-vector-1", "text", envelope.Route{RelayID: "relay-local", TTLSeconds: 60, Priority: 5}, plaintextAtoB)
	if err != nil {
		panic(err)
	}
	plaintextBtoA := []byte(`{"text":"hello from beta 🎉"}`)
	envBtoA, err := envelope.Encrypt(provider, stB, "msg-vector-2", "text", envelope.Route{RelayID: "relay-local", TTLSeconds: 60, Priority: 5}, plaintextBtoA)
	if err != nil {
		panic(err)
	}
	// Cross-check decryption before exporting.
	if got, err := envelope.Decrypt(provider, stB, envAtoB); err != nil || string(got) != string(plaintextAtoB) {
		panic(fmt.Sprintf("a->b decrypt failed: %v", err))
	}
	if got, err := envelope.Decrypt(provider, stA, envBtoA); err != nil || string(got) != string(plaintextBtoA) {
		panic(fmt.Sprintf("b->a decrypt failed: %v", err))
	}

	writeJSON(out, "session.json", map[string]any{
		"meta": meta,
		"device_a": map[string]any{
			"seed_hex": hex.EncodeToString(seedA),
			"identity": mustJSONMap(devA.Identity),
		},
		"device_b": map[string]any{
			"seed_hex": hex.EncodeToString(seedB),
			"identity": mustJSONMap(devB.Identity),
		},
		"ephemeral_a_hex":     hex.EncodeToString(ephA),
		"ephemeral_b_hex":     hex.EncodeToString(ephB),
		"hello_a":             mustJSONMap(helloA.Hello),
		"hello_b":             mustJSONMap(helloB.Hello),
		"transcript_hash_b64": crypto.Base64URL(stA.TranscriptHash),
		"keys_a": map[string]string{
			"send_hex":    hex.EncodeToString(stA.SendKey),
			"receive_hex": hex.EncodeToString(stA.ReceiveKey),
			"ready_hex":   hex.EncodeToString(stA.ReadyKey),
		},
		"ready_a": mustJSONMap(readyA),
		"ready_b": mustJSONMap(readyB),
		"envelope_a_to_b": map[string]any{
			"plaintext_hex": hex.EncodeToString(plaintextAtoB),
			"object":        mustJSONMap(envAtoB),
		},
		"envelope_b_to_a": map[string]any{
			"plaintext_hex": hex.EncodeToString(plaintextBtoA),
			"object":        mustJSONMap(envBtoA),
		},
	})
}

func genProvisioning(out string, meta map[string]any) {
	rng := newDRBG("iscp-conformance-provisioning")
	provider := crypto.NewProviderWithReader(rng)

	oob := []byte("oob-123456")
	channel, err := provisioning.EstablishLocalChannel(provider, oob)
	if err != nil {
		panic(err)
	}
	// EstablishLocalChannel generated a then b; reads[0]/reads[1] are their raw privs.
	aPriv := rng.reads[0]
	bPriv := rng.reads[1]

	issuer, err := identity.NewDevice(provider, "local", "issuer-phone", fixedNow)
	if err != nil {
		panic(err)
	}
	issuerSeed := rng.lastRead()
	enrollee, err := identity.NewDevice(provider, "local", "enrollee-watch", fixedNow)
	if err != nil {
		panic(err)
	}
	enrolleeSeed := rng.lastRead()

	ticket, err := provisioning.SignTicket(provider, issuer, provisioning.PairingTicket{
		TicketID:    "ticket-vector-1",
		DomainID:    "local",
		RelayID:     "relay-local",
		TrustRootID: "trust-local",
		MaxUses:     1,
		IssuedAt:    fixedNow,
		ExpiresAt:   fixedNow.Add(10 * time.Minute),
	})
	if err != nil {
		panic(err)
	}
	if err := provisioning.VerifyTicket(provider, ticket, issuer.Identity, fixedNow.Add(time.Minute)); err != nil {
		panic(err)
	}

	tp, err := identity.Thumbprint(enrollee.Identity)
	if err != nil {
		panic(err)
	}
	bundle, err := provisioning.SignBundle(provider, issuer, provisioning.Bundle{
		BundleID:                    "bundle-vector-1",
		IssuedToDeviceID:            enrollee.Identity.DeviceID,
		IssuedToPublicKeyThumbprint: tp,
		RelayDescriptor:             []byte(`{"type":"relay"}`),
		TrustRootDescriptor:         []byte(`{"type":"trust"}`),
		AccessCredential:            []byte(`{"type":"access"}`),
		RefreshCredentialWrapped:    crypto.Base64URL([]byte("wrapped-refresh")),
		TrustGrant:                  []byte(`{"type":"grant"}`),
		IssuedAt:                    fixedNow,
		ExpiresAt:                   fixedNow.Add(time.Hour),
	})
	if err != nil {
		panic(err)
	}
	if err := provisioning.ApplyBundle(provider, channel, enrollee.Identity, bundle, issuer.Identity, fixedNow.Add(time.Minute)); err != nil {
		panic(err)
	}

	writeJSON(out, "provisioning.json", map[string]any{
		"meta": meta,
		"local_channel": map[string]any{
			"a_priv_hex":     hex.EncodeToString(aPriv),
			"b_priv_hex":     hex.EncodeToString(bPriv),
			"oob_secret_hex": hex.EncodeToString(oob),
			"key_hex":        hex.EncodeToString(channel.Key),
			"mac_hex":        hex.EncodeToString(channel.TranscriptMAC),
		},
		"issuer": map[string]any{
			"seed_hex": hex.EncodeToString(issuerSeed),
			"identity": mustJSONMap(issuer.Identity),
		},
		"enrollee": map[string]any{
			"seed_hex": hex.EncodeToString(enrolleeSeed),
			"identity": mustJSONMap(enrollee.Identity),
		},
		"ticket": mustJSONMap(ticket),
		"bundle": mustJSONMap(bundle),
		"verify_at": fixedNow.Add(time.Minute).Format(time.RFC3339),
	})
}

func genTrustGrant(out string, meta map[string]any) {
	rng := newDRBG("iscp-conformance-trust")
	provider := crypto.NewProviderWithReader(rng)

	issuer, err := identity.NewDevice(provider, "local", "trust-local-signer", fixedNow)
	if err != nil {
		panic(err)
	}
	issuerSeed := rng.lastRead()
	subject, err := identity.NewDevice(provider, "local", "device-gamma", fixedNow)
	if err != nil {
		panic(err)
	}
	subjectSeed := rng.lastRead()
	tp, err := identity.Thumbprint(subject.Identity)
	if err != nil {
		panic(err)
	}
	grant, err := trust.SignGrant(provider, issuer, trust.Grant{
		GrantID:                "grant-vector-1",
		SubjectDeviceID:        subject.Identity.DeviceID,
		Audience:               "happy-domain",
		ConfirmationThumbprint: tp,
		Permissions:            []string{"text", "task.invoke"},
		RelayConstraints:       []string{"relay-local"},
		NotBefore:              fixedNow.Add(-time.Second),
		ExpiresAt:              fixedNow.Add(time.Hour),
		RevocationEpoch:        0,
	})
	if err != nil {
		panic(err)
	}
	if err := trust.VerifyGrant(provider, grant, issuer.Identity, trust.VerifyOptions{
		Audience:               "happy-domain",
		SubjectDeviceID:        subject.Identity.DeviceID,
		ConfirmationThumbprint: tp,
		Permission:             "text",
		RelayID:                "relay-local",
		CurrentRevocationEpoch: 0,
		Now:                    fixedNow.Add(time.Minute),
	}); err != nil {
		panic(err)
	}

	writeJSON(out, "trust_grant.json", map[string]any{
		"meta": meta,
		"issuer": map[string]any{
			"seed_hex": hex.EncodeToString(issuerSeed),
			"identity": mustJSONMap(issuer.Identity),
		},
		"subject": map[string]any{
			"seed_hex": hex.EncodeToString(subjectSeed),
			"identity": mustJSONMap(subject.Identity),
		},
		"grant":     mustJSONMap(grant),
		"verify_at": fixedNow.Add(time.Minute).Format(time.RFC3339),
	})
}

func genAccessProof(out string, meta map[string]any) {
	type popCase struct {
		Name      string `json:"name"`
		Method    string `json:"method"`
		Path      string `json:"path"`
		Token     string `json:"token"`
		Challenge string `json:"challenge"`
	}
	build := func(method, path, token string) string {
		hash := sha256.Sum256([]byte(token))
		return "iscp/v2/relay/access-proof\x00" + method + "\x00" + path + "\x00" + crypto.Base64URL(hash[:])
	}
	cases := []popCase{
		{Name: "envelopes", Method: "POST", Path: "/v2/relay/envelopes", Token: "access-token-vector-1"},
		{Name: "other-path", Method: "GET", Path: "/v2/relay/connect", Token: "tok"},
	}
	for i := range cases {
		cases[i].Challenge = build(cases[i].Method, cases[i].Path, cases[i].Token)
	}
	writeJSON(out, "access_proof.json", map[string]any{"meta": meta, "cases": cases})
}
