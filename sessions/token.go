package sessions

import (
	"crypto/sha256"
	"encoding/base64"
)

const tokenDigestPrefix = "sha256:"

// TokenDigest returns the non-reversible value stores should persist and use
// for session-token lookup.
func TokenDigest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return tokenDigestPrefix + base64.RawURLEncoding.EncodeToString(sum[:])
}
