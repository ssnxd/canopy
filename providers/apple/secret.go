package apple

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

const maxClientSecretLifetime = 180 * 24 * time.Hour

type JWTClientSecretSource struct {
	TeamID     string
	ClientID   string
	KeyID      string
	PrivateKey *ecdsa.PrivateKey
	Lifetime   time.Duration
	Now        func() time.Time
}

func NewJWTClientSecretSource(teamID, clientID, keyID string, privateKeyPEM []byte) (*JWTClientSecretSource, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("apple: invalid private key PEM")
	}
	var key any
	var err error
	key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		key, err = x509.ParseECPrivateKey(block.Bytes)
	}
	if err != nil {
		return nil, err
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok || ecKey.Curve != elliptic.P256() {
		return nil, fmt.Errorf("apple: private key must use the P-256 curve")
	}
	return &JWTClientSecretSource{
		TeamID:     teamID,
		ClientID:   clientID,
		KeyID:      keyID,
		PrivateKey: ecKey,
		Lifetime:   maxClientSecretLifetime,
	}, nil
}

func (s *JWTClientSecretSource) ClientSecret(ctx context.Context) (string, error) {
	if s.TeamID == "" || s.ClientID == "" || s.KeyID == "" || s.PrivateKey == nil {
		return "", fmt.Errorf("apple: team id, client id, key id, and private key are required")
	}
	if s.PrivateKey.Curve != elliptic.P256() {
		return "", fmt.Errorf("apple: private key must use the P-256 curve")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	now := time.Now().UTC()
	if s.Now != nil {
		now = s.Now().UTC()
	}
	lifetime := s.Lifetime
	if lifetime <= 0 || lifetime > maxClientSecretLifetime {
		return "", fmt.Errorf("apple: lifetime must be between 1ns and %s", maxClientSecretLifetime)
	}
	header := map[string]string{
		"alg": "ES256",
		"kid": s.KeyID,
		"typ": "JWT",
	}
	claims := map[string]any{
		"iss": s.TeamID,
		"iat": now.Unix(),
		"exp": now.Add(lifetime).Unix(),
		"aud": "https://appleid.apple.com",
		"sub": s.ClientID,
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	unsigned := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(unsigned))
	r, ss, err := ecdsa.Sign(rand.Reader, s.PrivateKey, digest[:])
	if err != nil {
		return "", err
	}
	signature := appendFixed(r, ss, 32)
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func appendFixed(r, s *big.Int, size int) []byte {
	out := make([]byte, size*2)
	rb := r.Bytes()
	sb := s.Bytes()
	copy(out[size-len(rb):size], rb)
	copy(out[size*2-len(sb):], sb)
	return out
}
