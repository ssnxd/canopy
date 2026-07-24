package twofactor

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/ssnxd/canopy"
	"github.com/ssnxd/canopy/store/memory"
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

func TestSecretCodecSupportsKeyRotation(t *testing.T) {
	oldCodec, err := NewSecretCodec("old-secret")
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := oldCodec.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := NewRotatingSecretCodec("new-secret", "old-secret")
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := rotated.Decrypt(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != "secret" {
		t.Fatalf("plaintext = %q, want secret", plaintext)
	}
	newCiphertext, err := rotated.Encrypt([]byte("new-secret-value"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := oldCodec.Decrypt(newCiphertext); err == nil {
		t.Fatal("old codec decrypted ciphertext created with the new key")
	}
}

func TestChallengeSupportsSigningKeyRotation(t *testing.T) {
	store := memory.New()
	oldSecret := "old-production-secret-with-enough-entropy"
	oldModule := New(Options{})
	if _, err := canopy.New(canopy.Config{
		Store:   store,
		Secret:  oldSecret,
		Modules: []canopy.Module{oldModule},
	}); err != nil {
		t.Fatal(err)
	}
	token, err := oldModule.issueChallenge(context.Background(), "usr_rotation")
	if err != nil {
		t.Fatal(err)
	}
	rotatedModule := New(Options{})
	if _, err := canopy.New(canopy.Config{
		Store:           store,
		Secret:          "new-production-secret-with-enough-entropy",
		PreviousSecrets: []string{oldSecret},
		Modules:         []canopy.Module{rotatedModule},
	}); err != nil {
		t.Fatal(err)
	}
	userID, err := rotatedModule.consumeChallenge(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	if userID != "usr_rotation" {
		t.Fatalf("user id = %q, want usr_rotation", userID)
	}
}
