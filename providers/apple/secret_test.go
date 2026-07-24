package apple

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"
)

func TestJWTClientSecretSourceSignsWithP256(t *testing.T) {
	source := newTestJWTClientSecretSource(t, elliptic.P256())
	token, err := source.ClientSecret(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if parts := strings.Split(token, "."); len(parts) != 3 {
		t.Fatalf("JWT parts = %d, want 3", len(parts))
	}
}

func TestNewJWTClientSecretSourceRejectsNonP256Key(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if _, err := NewJWTClientSecretSource("team", "client", "key", keyPEM); err == nil {
		t.Fatal("NewJWTClientSecretSource() error = nil, want P-384 rejected")
	}
}

func TestJWTClientSecretSourceRejectsMutatedCurve(t *testing.T) {
	source := newTestJWTClientSecretSource(t, elliptic.P256())
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	source.PrivateKey = key
	if _, err := source.ClientSecret(context.Background()); err == nil {
		t.Fatal("ClientSecret() error = nil, want P-384 rejected")
	}
}

func TestJWTClientSecretSourceRejectsInvalidLifetime(t *testing.T) {
	for _, lifetime := range []time.Duration{-time.Second, 0, maxClientSecretLifetime + time.Nanosecond} {
		source := newTestJWTClientSecretSource(t, elliptic.P256())
		source.Lifetime = lifetime
		if _, err := source.ClientSecret(context.Background()); err == nil {
			t.Fatalf("ClientSecret() error = nil for lifetime %s", lifetime)
		}
	}
}

func newTestJWTClientSecretSource(t *testing.T, curve elliptic.Curve) *JWTClientSecretSource {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &JWTClientSecretSource{
		TeamID:     "team",
		ClientID:   "client",
		KeyID:      "key",
		PrivateKey: key,
		Lifetime:   time.Hour,
	}
}
