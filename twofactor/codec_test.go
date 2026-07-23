package twofactor

import (
	"encoding/base64"
	"testing"
)

func TestSecretCodecRoundTrip(t *testing.T) {
	codec, err := NewSecretCodec("dev-secret-with-enough-test-entropy")
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("JBSWY3DPEHPK3PXP")
	ciphertext, err := codec.Encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if ciphertext == string(plaintext) {
		t.Fatal("ciphertext equals plaintext; secret is not encrypted")
	}
	out, err := codec.Decrypt(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(plaintext) {
		t.Fatalf("decrypt = %q, want %q", out, plaintext)
	}
}

func TestSecretCodecRejectsTamperedCiphertext(t *testing.T) {
	codec, err := NewSecretCodec("dev-secret-with-enough-test-entropy")
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := codec.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	// Corrupt one ciphertext byte so the GCM tag no longer verifies.
	raw, err := base64.RawURLEncoding.DecodeString(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)/2] ^= 0xFF
	tampered := base64.RawURLEncoding.EncodeToString(raw)
	if _, err := codec.Decrypt(tampered); err == nil {
		t.Fatal("tampered ciphertext was accepted")
	}
}

func TestSecretCodecKeySeparation(t *testing.T) {
	a, err := NewSecretCodec("secret-one")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewSecretCodec("secret-two")
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := a.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Decrypt(ciphertext); err == nil {
		t.Fatal("a codec with a different secret decrypted the ciphertext")
	}
}
