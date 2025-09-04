package aeadcrypto11

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/ThalesGroup/crypto11"
	"github.com/google/tink/go/tink"
)

// AEADCrypto11 wraps a PKCS#11-backed AES key for AEAD encryption/decryption.
type AEADCrypto11 struct {
	aead cipher.AEAD
}

// NewAEADCrypto11 creates an AEAD using a PKCS#11-backed AES key label.
func NewAEADCrypto11(ctx *crypto11.Context, keyLabel string) (*AEADCrypto11, error) {
	if ctx == nil {
		return nil, errors.New("nil context")
	}
	key, err := ctx.FindKey(nil, []byte(keyLabel))
	if err != nil {
		return nil, err
	}
	if key == nil {
		return nil, errors.New("key not found")
	}
	gcm, err := key.NewGCM()
	if err != nil {
		return nil, fmt.Errorf("creating GCM AEAD: %w", err)
	}
	return &AEADCrypto11{aead: gcm}, nil
}

// Encrypt encrypts plaintext with associated data using the HSM-backed key.
func (a *AEADCrypto11) Encrypt(plaintext, associatedData []byte) ([]byte, error) {
	if a == nil || a.aead == nil {
		return nil, errors.New("AEAD not initialized")
	}
	// Generate a random nonce of the size required by the AEAD implementation.
	nonceSize := a.aead.NonceSize()
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("nonce generation failed: %w", err)
	}
	// Seal appends the ciphertext and tag to the first argument; keep dst empty.
	ct := a.aead.Seal(nil, nonce, plaintext, associatedData)
	// Prepend nonce to the ciphertext, as is common for AES-GCM.
	out := make([]byte, 0, len(nonce)+len(ct))
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// Decrypt decrypts ciphertext with associated data using the HSM-backed key.
func (a *AEADCrypto11) Decrypt(ciphertext, associatedData []byte) ([]byte, error) {
	if a == nil || a.aead == nil {
		return nil, errors.New("AEAD not initialized")
	}
	nonceSize := a.aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce := ciphertext[:nonceSize]
	ct := ciphertext[nonceSize:]
	pt, err := a.aead.Open(nil, nonce, ct, associatedData)
	if err != nil {
		return nil, err
	}
	return pt, nil
}

// Compile-time check that AEADCrypto11 implements tink.AEAD.
var _ tink.AEAD = (*AEADCrypto11)(nil)

// ---- Example PKCS#11 Context Initialization ----

// Example of how to create a crypto11.Context
// func ExampleContext() (*crypto11.Context, error) {
// 	return crypto11.Configure(&crypto11.Config{
// 		Path: "/usr/local/lib/your-pkcs11.so",
// 		TokenLabel: "YourTokenLabel",
// 		Pin: "123456",
// 	})
// }
