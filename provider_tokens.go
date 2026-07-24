package canopy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/hkdf"
)

const providerTokenEnvelopePrefix = "enc.v1."

// ProviderTokenCodec encrypts provider credentials before they reach the
// configured store. Seal must use authenticated encryption.
type ProviderTokenCodec interface {
	Seal(plaintext []byte) ([]byte, error)
	Open(ciphertext []byte) ([]byte, error)
}

type aesGCMProviderTokenCodec struct {
	aead cipher.AEAD
}

func newProviderTokenCodec(secret string) ProviderTokenCodec {
	key := make([]byte, 32)
	reader := hkdf.New(sha256.New, []byte(secret), nil, []byte("canopy/provider-token/v1"))
	_, _ = io.ReadFull(reader, key)
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	return &aesGCMProviderTokenCodec{aead: aead}
}

func (c *aesGCMProviderTokenCodec) Seal(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return c.aead.Seal(nonce, nonce, plaintext, nil), nil
}

func (c *aesGCMProviderTokenCodec) Open(ciphertext []byte) ([]byte, error) {
	nonceSize := c.aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("canopy: provider token ciphertext is too short")
	}
	return c.aead.Open(nil, ciphertext[:nonceSize], ciphertext[nonceSize:], nil)
}

func encodeProviderToken(codec ProviderTokenCodec, value string) (string, error) {
	if value == "" {
		return "", nil
	}
	sealed, err := codec.Seal([]byte(value))
	if err != nil {
		return "", err
	}
	return providerTokenEnvelopePrefix + base64.RawURLEncoding.EncodeToString(sealed), nil
}

func decodeProviderToken(codec ProviderTokenCodec, value string) (string, error) {
	if value == "" {
		return "", nil
	}
	if !strings.HasPrefix(value, providerTokenEnvelopePrefix) {
		return "", fmt.Errorf("canopy: provider token is not encrypted")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, providerTokenEnvelopePrefix))
	if err != nil {
		return "", fmt.Errorf("canopy: decode provider token: %w", err)
	}
	plaintext, err := codec.Open(raw)
	if err != nil {
		return "", fmt.Errorf("canopy: decrypt provider token: %w", err)
	}
	return string(plaintext), nil
}

func encryptAccountTokens(codec ProviderTokenCodec, account *Account) (*Account, error) {
	encrypted := *account
	var err error
	encrypted.AccessToken, err = encodeProviderToken(codec, account.AccessToken)
	if err != nil {
		return nil, err
	}
	encrypted.RefreshToken, err = encodeProviderToken(codec, account.RefreshToken)
	if err != nil {
		return nil, err
	}
	encrypted.IDToken, err = encodeProviderToken(codec, account.IDToken)
	if err != nil {
		return nil, err
	}
	return &encrypted, nil
}

func decryptAccountTokens(codec ProviderTokenCodec, account *Account) (*Account, error) {
	decrypted := *account
	var err error
	decrypted.AccessToken, err = decodeProviderToken(codec, account.AccessToken)
	if err != nil {
		return nil, err
	}
	decrypted.RefreshToken, err = decodeProviderToken(codec, account.RefreshToken)
	if err != nil {
		return nil, err
	}
	decrypted.IDToken, err = decodeProviderToken(codec, account.IDToken)
	if err != nil {
		return nil, err
	}
	return &decrypted, nil
}
