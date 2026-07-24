package twofactor

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/ssnxd/canopy"
)

const (
	moduleID                  = "two-factor"
	challengeIdentifierPrefix = "two_factor_challenge:"
)

// Options configures the two-factor module.
type Options struct {
	Issuer           string        // label shown in the authenticator app
	Authenticator    Authenticator // default: RFC 6238 TOTP
	Codec            Codec         // default: AES-GCM key derived from the Canopy secret
	BackupCodeCount  int           // default: 10
	ChallengeTTL     time.Duration // default: 10 minutes
	RecentAuthMaxAge time.Duration // default: 10 minutes
}

// Module adds TOTP two-factor authentication with backup codes. It
// implements canopy.Module, canopy.RouteModule, and
// canopy.SignInInterceptor.
type Module struct {
	issuer           string
	authenticator    Authenticator
	codec            Codec
	backupCodeCount  int
	challengeTTL     time.Duration
	recentAuthMaxAge time.Duration

	core  canopy.Core
	store canopy.TwoFactorStore
	chKey []byte
}

// New returns a two-factor module.
func New(o Options) *Module {
	return &Module{
		issuer:           o.Issuer,
		authenticator:    o.Authenticator,
		codec:            o.Codec,
		backupCodeCount:  o.BackupCodeCount,
		challengeTTL:     o.ChallengeTTL,
		recentAuthMaxAge: o.RecentAuthMaxAge,
	}
}

func (m *Module) ID() string { return moduleID }

func (m *Module) Init(core canopy.Core) error {
	store, ok := core.Store().(canopy.TwoFactorStore)
	if !ok {
		return fmt.Errorf("two-factor: store does not implement canopy.TwoFactorStore")
	}
	secret := core.Config().Secret
	if m.codec == nil {
		codec, err := NewSecretCodec(secret)
		if err != nil {
			return err
		}
		m.codec = codec
	}
	key, err := deriveKey(secret, "canopy/two-factor/challenge")
	if err != nil {
		return err
	}
	m.chKey = key
	m.core = core
	m.store = store
	if m.authenticator == nil {
		m.authenticator = NewTOTP()
	}
	if m.backupCodeCount == 0 {
		m.backupCodeCount = 10
	}
	if m.challengeTTL == 0 {
		m.challengeTTL = 10 * time.Minute
	}
	if m.recentAuthMaxAge == 0 {
		m.recentAuthMaxAge = 10 * time.Minute
	}
	if m.issuer == "" {
		m.issuer = "Canopy"
	}
	return nil
}

func (m *Module) Routes() []canopy.Route {
	return []canopy.Route{
		{Method: http.MethodPost, Pattern: "/two-factor/enable", RequireSession: true, Handler: http.HandlerFunc(m.handleEnable)},
		{Method: http.MethodPost, Pattern: "/two-factor/verify", RequireSession: true, Handler: http.HandlerFunc(m.handleVerify)},
		{Method: http.MethodPost, Pattern: "/two-factor/disable", RequireSession: true, Handler: http.HandlerFunc(m.handleDisable)},
		{Method: http.MethodPost, Pattern: "/two-factor/challenge", Handler: http.HandlerFunc(m.handleChallenge)},
		{Method: http.MethodPost, Pattern: "/two-factor/backup", Handler: http.HandlerFunc(m.handleBackup)},
	}
}

// AfterPrimaryAuth returns a challenge when the user has two-factor
// enabled. It returns nil to continue a normal sign-in.
func (m *Module) AfterPrimaryAuth(ctx context.Context, user canopy.User) (*canopy.StepUpChallenge, error) {
	tf, err := m.store.GetTwoFactor(ctx, user.ID)
	if err != nil {
		if errors.Is(err, canopy.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	if !tf.Enabled {
		return nil, nil
	}
	token, err := m.issueChallenge(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	return &canopy.StepUpChallenge{Token: token, Methods: []string{"totp", "backup_code"}}, nil
}

func (m *Module) handleEnable(w http.ResponseWriter, r *http.Request) {
	data, ok := canopy.SessionFromContext(r.Context())
	if !ok {
		canopy.WriteError(w, canopy.ErrUnauthorized)
		return
	}
	if data.Session.ImpersonatedBy != "" {
		canopy.WriteError(w, canopy.ErrForbidden)
		return
	}
	if time.Since(data.Session.CreatedAt) > m.recentAuthMaxAge {
		canopy.WriteError(w, canopy.ErrRecentAuthentication)
		return
	}
	if tf, err := m.store.GetTwoFactor(r.Context(), data.User.ID); err == nil && tf.Enabled {
		canopy.WriteError(w, canopy.ErrConflict)
		return
	}
	secret, err := m.authenticator.GenerateSecret()
	if err != nil {
		canopy.WriteError(w, err)
		return
	}
	encrypted, err := m.codec.Encrypt([]byte(secret))
	if err != nil {
		canopy.WriteError(w, err)
		return
	}
	now := time.Now().UTC()
	if err := m.store.UpsertTwoFactor(r.Context(), &canopy.TwoFactor{
		UserID:    data.User.ID,
		Secret:    encrypted,
		Enabled:   false,
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		canopy.WriteError(w, err)
		return
	}
	canopy.WriteJSON(w, http.StatusOK, map[string]any{
		"secret": secret,
		"uri":    m.authenticator.URI(secret, data.User.Email, m.issuer),
	})
}

func (m *Module) handleVerify(w http.ResponseWriter, r *http.Request) {
	data, ok := canopy.SessionFromContext(r.Context())
	if !ok {
		canopy.WriteError(w, canopy.ErrUnauthorized)
		return
	}
	if data.Session.ImpersonatedBy != "" {
		canopy.WriteError(w, canopy.ErrForbidden)
		return
	}
	if time.Since(data.Session.CreatedAt) > m.recentAuthMaxAge {
		canopy.WriteError(w, canopy.ErrRecentAuthentication)
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if !canopy.DecodeJSON(w, r, &req) {
		return
	}
	tf, err := m.store.GetTwoFactor(r.Context(), data.User.ID)
	if err != nil {
		canopy.WriteError(w, canopy.ErrInvalidTwoFactorCode)
		return
	}
	secret, err := m.codec.Decrypt(tf.Secret)
	if err != nil {
		canopy.WriteError(w, err)
		return
	}
	counter, valid := m.authenticator.ValidateCounter(string(secret), req.Code, time.Now())
	if !valid {
		canopy.WriteError(w, canopy.ErrInvalidTwoFactorCode)
		return
	}
	tf.Enabled = true
	tf.LastTOTPStep = counter
	tf.UpdatedAt = time.Now().UTC()
	if err := m.store.UpsertTwoFactor(r.Context(), tf); err != nil {
		canopy.WriteError(w, err)
		return
	}
	plain, hashes, err := m.generateBackupCodes()
	if err != nil {
		canopy.WriteError(w, err)
		return
	}
	if err := m.store.ReplaceBackupCodes(r.Context(), data.User.ID, hashes); err != nil {
		canopy.WriteError(w, err)
		return
	}
	m.core.Audit(r.Context(), canopy.AuditEvent{Type: "two_factor.enabled", UserID: data.User.ID, Email: data.User.Email, Success: true})
	canopy.WriteJSON(w, http.StatusOK, map[string]any{"backupCodes": plain})
}

func (m *Module) handleDisable(w http.ResponseWriter, r *http.Request) {
	data, ok := canopy.SessionFromContext(r.Context())
	if !ok {
		canopy.WriteError(w, canopy.ErrUnauthorized)
		return
	}
	if data.Session.ImpersonatedBy != "" {
		canopy.WriteError(w, canopy.ErrForbidden)
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if !canopy.DecodeJSON(w, r, &req) {
		return
	}
	tf, err := m.store.GetTwoFactor(r.Context(), data.User.ID)
	if err != nil || !tf.Enabled {
		canopy.WriteError(w, canopy.ErrInvalidTwoFactorCode)
		return
	}
	if !m.verifyCode(r.Context(), data.User.ID, tf, req.Code) {
		canopy.WriteError(w, canopy.ErrInvalidTwoFactorCode)
		return
	}
	if err := m.store.DeleteTwoFactor(r.Context(), data.User.ID); err != nil {
		canopy.WriteError(w, err)
		return
	}
	m.core.Audit(r.Context(), canopy.AuditEvent{Type: "two_factor.disabled", UserID: data.User.ID, Email: data.User.Email, Success: true})
	canopy.WriteJSON(w, http.StatusOK, map[string]bool{"success": true})
}

func (m *Module) handleChallenge(w http.ResponseWriter, r *http.Request) {
	m.completeChallenge(w, r, false)
}

func (m *Module) handleBackup(w http.ResponseWriter, r *http.Request) {
	m.completeChallenge(w, r, true)
}

func (m *Module) completeChallenge(w http.ResponseWriter, r *http.Request, useBackup bool) {
	var req struct {
		Token      string `json:"token"`
		Code       string `json:"code"`
		RememberMe *bool  `json:"rememberMe"`
	}
	if !canopy.DecodeJSON(w, r, &req) {
		return
	}
	userID, err := m.consumeChallenge(r.Context(), req.Token)
	if err != nil {
		canopy.WriteError(w, err)
		return
	}
	tf, err := m.store.GetTwoFactor(r.Context(), userID)
	if err != nil || !tf.Enabled {
		canopy.WriteError(w, canopy.ErrInvalidTwoFactorCode)
		return
	}
	valid := false
	if useBackup {
		consumed, err := m.store.ConsumeBackupCode(r.Context(), userID, hashToken(normalizeBackupCode(req.Code)))
		valid = err == nil && consumed
	} else {
		valid = m.verifyTOTP(r.Context(), userID, tf, req.Code)
	}
	if !valid {
		m.core.Audit(r.Context(), canopy.AuditEvent{Type: "two_factor.challenge.failed", UserID: userID, Success: false, Error: canopy.ErrInvalidTwoFactorCode.Error()})
		canopy.WriteError(w, canopy.ErrInvalidTwoFactorCode)
		return
	}
	user, err := m.core.Store().FindUserByID(r.Context(), userID)
	if err != nil {
		canopy.WriteError(w, canopy.ErrUnauthorized)
		return
	}
	data, token, err := m.core.IssueSession(r.Context(), *user, canopy.SessionOptions{
		RememberMe: req.RememberMe,
		IPAddress:  requestIP(r),
		UserAgent:  r.UserAgent(),
	})
	if err != nil {
		canopy.WriteError(w, err)
		return
	}
	m.core.Config().Session.SetCookie(w, token, req.RememberMe)
	m.core.Audit(r.Context(), canopy.AuditEvent{Type: "two_factor.challenge.succeeded", UserID: userID, Email: user.Email, Success: true})
	canopy.WriteJSON(w, http.StatusOK, data)
}

func (m *Module) verifyCode(ctx context.Context, userID string, tf *canopy.TwoFactor, code string) bool {
	if m.verifyTOTP(ctx, userID, tf, code) {
		return true
	}
	consumed, err := m.store.ConsumeBackupCode(ctx, userID, hashToken(normalizeBackupCode(code)))
	return err == nil && consumed
}

func (m *Module) verifyTOTP(ctx context.Context, userID string, tf *canopy.TwoFactor, code string) bool {
	secret, err := m.codec.Decrypt(tf.Secret)
	if err != nil {
		return false
	}
	counter, ok := m.authenticator.ValidateCounter(string(secret), code, time.Now())
	if !ok {
		return false
	}
	consumed, err := m.store.ConsumeTOTPStep(ctx, userID, counter)
	return err == nil && consumed
}

func (m *Module) generateBackupCodes() (plain []string, hashes []string, err error) {
	for i := 0; i < m.backupCodeCount; i++ {
		buf := make([]byte, 10)
		if _, err := rand.Read(buf); err != nil {
			return nil, nil, err
		}
		code := base32NoPad.EncodeToString(buf)
		plain = append(plain, code)
		hashes = append(hashes, hashToken(code))
	}
	return plain, hashes, nil
}

type challengeClaims struct {
	UserID string `json:"uid"`
	Exp    int64  `json:"exp"`
	Nonce  string `json:"n"`
}

func (m *Module) issueChallenge(ctx context.Context, userID string) (string, error) {
	nonce, err := randToken(12)
	if err != nil {
		return "", err
	}
	claims := challengeClaims{UserID: userID, Exp: time.Now().Add(m.challengeTTL).Unix(), Nonce: nonce}
	body, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(body)
	token := encoded + "." + m.sign(encoded)
	id, err := randToken(16)
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	if err := m.core.Store().CreateVerification(ctx, &canopy.Verification{
		ID:         "2fc_" + id,
		Identifier: challengeIdentifierPrefix + userID,
		Value:      hashToken(token),
		ExpiresAt:  time.Unix(claims.Exp, 0).UTC(),
		CreatedAt:  now,
		UpdatedAt:  now,
	}); err != nil {
		return "", err
	}
	return token, nil
}

func (m *Module) consumeChallenge(ctx context.Context, token string) (string, error) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return "", canopy.ErrInvalidToken
	}
	if !hmac.Equal([]byte(m.sign(parts[0])), []byte(parts[1])) {
		return "", canopy.ErrInvalidToken
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", canopy.ErrInvalidToken
	}
	var claims challengeClaims
	if err := json.Unmarshal(body, &claims); err != nil || claims.UserID == "" {
		return "", canopy.ErrInvalidToken
	}
	if time.Now().Unix() > claims.Exp {
		return "", canopy.ErrExpiredToken
	}
	if _, err := m.core.Store().ConsumeVerification(ctx, challengeIdentifierPrefix+claims.UserID, hashToken(token), time.Now().UTC()); err != nil {
		return "", canopy.ErrInvalidToken
	}
	return claims.UserID, nil
}

func (m *Module) sign(value string) string {
	mac := hmac.New(sha256.New, m.chKey)
	_, _ = mac.Write([]byte(value))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func hashToken(value string) string {
	sum := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func randToken(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func normalizeBackupCode(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	code = strings.ReplaceAll(code, "-", "")
	code = strings.ReplaceAll(code, " ", "")
	return code
}

func requestIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
