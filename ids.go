package canopy

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
)

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func newID(prefix string) (string, error) {
	tok, err := randomToken(18)
	if err != nil {
		return "", err
	}
	if prefix == "" {
		return tok, nil
	}
	return prefix + "_" + strings.ToLower(tok), nil
}
