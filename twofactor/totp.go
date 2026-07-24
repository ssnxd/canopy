package twofactor

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"net/url"
	"strings"
	"time"
)

// Authenticator abstracts the one-time password algorithm. The default
// is RFC 6238 TOTP. An application can supply its own.
type Authenticator interface {
	GenerateSecret() (string, error)
	URI(secret, account, issuer string) string
	Validate(secret, code string, at time.Time) bool
	ValidateCounter(secret, code string, at time.Time) (counter int64, ok bool)
}

// TOTP is an RFC 6238 authenticator. The zero value uses safe defaults.
type TOTP struct {
	Digits int
	Period time.Duration
	Skew   int
	Hash   func() hash.Hash
}

// NewTOTP returns a TOTP authenticator with standard defaults: six
// digits, a thirty second period, one step of skew, and SHA-1.
func NewTOTP() *TOTP {
	return &TOTP{Digits: 6, Period: 30 * time.Second, Skew: 1, Hash: sha1.New}
}

var base32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

func (t *TOTP) GenerateSecret() (string, error) {
	buf := make([]byte, 20)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base32NoPad.EncodeToString(buf), nil
}

func (t *TOTP) URI(secret, account, issuer string) string {
	label := account
	if issuer != "" {
		label = issuer + ":" + account
	}
	query := url.Values{}
	query.Set("secret", secret)
	if issuer != "" {
		query.Set("issuer", issuer)
	}
	query.Set("algorithm", "SHA1")
	query.Set("digits", fmt.Sprintf("%d", t.digits()))
	query.Set("period", fmt.Sprintf("%d", int(t.period().Seconds())))
	return "otpauth://totp/" + url.PathEscape(label) + "?" + query.Encode()
}

func (t *TOTP) Validate(secret, code string, at time.Time) bool {
	_, ok := t.ValidateCounter(secret, code, at)
	return ok
}

// ValidateCounter validates code and returns the matching RFC 6238 counter.
// Callers persist the counter to reject reuse of the same one-time code.
func (t *TOTP) ValidateCounter(secret, code string, at time.Time) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != t.digits() {
		return 0, false
	}
	key, err := base32NoPad.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return 0, false
	}
	period := int64(t.period().Seconds())
	if period <= 0 || t.Skew < 0 {
		return 0, false
	}
	counter := at.Unix() / period
	skew := int64(t.Skew)
	for offset := -skew; offset <= skew; offset++ {
		step := counter + offset
		candidate := t.hotp(key, step)
		if subtle.ConstantTimeCompare([]byte(code), []byte(candidate)) == 1 {
			return step, true
		}
	}
	return 0, false
}

// GenerateCode returns the TOTP code for secret at time at.
func (t *TOTP) GenerateCode(secret string, at time.Time) (string, error) {
	key, err := base32NoPad.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", err
	}
	period := int64(t.period().Seconds())
	if period <= 0 {
		return "", fmt.Errorf("two-factor: invalid period")
	}
	return t.hotp(key, at.Unix()/period), nil
}

func (t *TOTP) hotp(key []byte, counter int64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(counter))
	mac := hmac.New(t.hashFn(), key)
	_, _ = mac.Write(buf[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset]&0x7f) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])
	mod := uint32(1)
	for i := 0; i < t.digits(); i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", t.digits(), value%mod)
}

func (t *TOTP) digits() int {
	if t.Digits == 0 {
		return 6
	}
	return t.Digits
}

func (t *TOTP) period() time.Duration {
	if t.Period == 0 {
		return 30 * time.Second
	}
	return t.Period
}

func (t *TOTP) hashFn() func() hash.Hash {
	if t.Hash == nil {
		return sha1.New
	}
	return t.Hash
}
