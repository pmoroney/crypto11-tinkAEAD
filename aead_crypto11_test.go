package aeadcrypto11

import (
	"os"
	"path/filepath"
	"testing"

	c11 "github.com/ThalesGroup/crypto11"
)

func withSoftHSM(t *testing.T) (cfgPath string, cleanup func()) {
	t.Helper()
	// Use repo-local SoftHSM2 setup if present; otherwise, skip.
	base := filepath.Join(".softhsm2")
	conf := filepath.Join(base, "softhsm2.conf")
	if _, err := os.Stat(conf); err != nil {
		t.Skip("SoftHSM2 not configured for tests; run setup in CI or locally to enable")
	}
	// Set env for this test process
	t.Setenv("SOFTHSM2_CONF", conf)
	return conf, func() {}
}

func newCtxForSoftHSM(t *testing.T) *c11.Context {
	t.Helper()
	_, _ = withSoftHSM(t)
	cfg := &c11.Config{
		Path:       "/usr/lib/softhsm/libsofthsm2.so",
		TokenLabel: "tinktest",
		Pin:        "user-secret",
	}
	// Try common alternate paths if default is missing.
	if _, err := os.Stat(cfg.Path); err != nil {
		alt := []string{
			"/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
			"/usr/local/lib/softhsm/libsofthsm2.so",
			"/usr/local/lib/libsofthsm2.so",
			"/usr/lib/libsofthsm2.so",
		}
		for _, p := range alt {
			if _, err := os.Stat(p); err == nil {
				cfg.Path = p
				break
			}
		}
	}
	ctx, err := c11.Configure(cfg)
	if err != nil {
		t.Fatalf("configure crypto11: %v", err)
	}
	t.Cleanup(func() { _ = ctx.Close() })
	return ctx
}

func ensureAESKey(t *testing.T, ctx *c11.Context, label string, bits int) {
	t.Helper()
	k, err := ctx.FindKey(nil, []byte(label))
	if err != nil {
		t.Fatalf("FindKey: %v", err)
	}
	if k != nil {
		return
	}
	// Create a new AES key
	id := []byte("test-key-id-" + label)
	key, err := ctx.GenerateSecretKeyWithLabel(id, []byte(label), bits, c11.CipherAES)
	if err != nil {
		t.Fatalf("GenerateSecretKey: %v", err)
	}
	// Just to ensure it exists
	if key == nil {
		t.Fatalf("generated key is nil")
	}
}

func TestAEAD_WithAssociatedData_SoftHSM(t *testing.T) {
	ctx := newCtxForSoftHSM(t)
	const label = "tink-aes-gcm"
	ensureAESKey(t, ctx, label, 256)

	a, err := NewAEADCrypto11(ctx, label)
	if err != nil {
		t.Fatalf("NewAEADCrypto11: %v", err)
	}

	pt := []byte("hello aead")
	aad := []byte("user-id:42")

	ct, err := a.Encrypt(pt, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if string(ct) == string(pt) {
		t.Fatalf("ciphertext appears unmodified")
	}
	got, err := a.Decrypt(ct, aad)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(got) != string(pt) {
		t.Fatalf("roundtrip mismatch: got %q want %q", got, pt)
	}

	// Wrong AAD must fail
	if _, err := a.Decrypt(ct, []byte("user-id:43")); err == nil {
		t.Fatalf("decrypt with wrong AAD should fail")
	}
}
