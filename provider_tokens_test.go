package canopy

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestProviderTokenCodecRoundTrip(t *testing.T) {
	codec := newProviderTokenCodec("provider-token-test-secret")
	first, err := encodeProviderToken(codec, "refresh-token")
	if err != nil {
		t.Fatal(err)
	}
	second, err := encodeProviderToken(codec, "refresh-token")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("provider token encryption reused a nonce")
	}
	if !strings.HasPrefix(first, providerTokenEnvelopePrefix) {
		t.Fatalf("encrypted token = %q, want envelope prefix", first)
	}
	plain, err := decodeProviderToken(codec, first)
	if err != nil {
		t.Fatal(err)
	}
	if plain != "refresh-token" {
		t.Fatalf("plain = %q, want refresh-token", plain)
	}
}

func TestProviderTokenCodecRejectsPlaintextAndTampering(t *testing.T) {
	codec := newProviderTokenCodec("provider-token-test-secret")
	if _, err := decodeProviderToken(codec, "plaintext-token"); err == nil {
		t.Fatal("plaintext provider token was accepted")
	}
	encrypted, err := encodeProviderToken(codec, "access-token")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(encrypted, providerTokenEnvelopePrefix))
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)/2] ^= 1
	tampered := providerTokenEnvelopePrefix + base64.RawURLEncoding.EncodeToString(raw)
	if _, err := decodeProviderToken(codec, tampered); err == nil {
		t.Fatal("tampered provider token was accepted")
	}
}

func TestProviderTokenCodecSupportsKeyRotation(t *testing.T) {
	oldCodec := newProviderTokenCodec("old-provider-token-secret")
	ciphertext, err := encodeProviderToken(oldCodec, "refresh-token")
	if err != nil {
		t.Fatal(err)
	}
	rotated := newProviderTokenCodec("new-provider-token-secret", "old-provider-token-secret")
	plaintext, err := decodeProviderToken(rotated, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if plaintext != "refresh-token" {
		t.Fatalf("plaintext = %q, want refresh-token", plaintext)
	}
	withoutPrevious := newProviderTokenCodec("new-provider-token-secret")
	if _, err := decodeProviderToken(withoutPrevious, ciphertext); err == nil {
		t.Fatal("old ciphertext decrypted without the previous secret")
	}
}
