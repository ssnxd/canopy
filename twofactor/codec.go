package twofactor

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// Codec encrypts and decrypts the TOTP secret at rest. The default
// derives an AES-256-GCM key from the Canopy secret.
type Codec interface {
	Encrypt(plaintext []byte) (string, error)
	Decrypt(ciphertext string) ([]byte, error)
}

// SecretCodec is an AES-256-GCM codec. It derives its key from a secret
// with HKDF and a domain label. This keeps the key separate from other
// uses of the same secret.
type SecretCodec struct {
	aead cipher.AEAD
}

// NewSecretCodec derives an AES-256-GCM codec from secret.
func NewSecretCodec(secret string) (*SecretCodec, error) {
	if secret == "" {
		return nil, fmt.Errorf("two-factor: secret is required to derive the codec key")
	}
	key, err := deriveKey(secret, "canopy/two-factor/secret")
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &SecretCodec{aead: aead}, nil
}

func (c *SecretCodec) Encrypt(plaintext []byte) (string, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := c.aead.Seal(nonce, nonce, plaintext, nil)
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (c *SecretCodec) Decrypt(ciphertext string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}
	size := c.aead.NonceSize()
	if len(raw) < size {
		return nil, fmt.Errorf("two-factor: ciphertext is too short")
	}
	nonce, sealed := raw[:size], raw[size:]
	return c.aead.Open(nil, nonce, sealed, nil)
}

// deriveKey derives a 32 byte key from secret with HKDF and a label.
func deriveKey(secret, label string) ([]byte, error) {
	key := make([]byte, 32)
	reader := hkdf.New(sha256.New, []byte(secret), nil, []byte(label))
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, err
	}
	return key, nil
}
