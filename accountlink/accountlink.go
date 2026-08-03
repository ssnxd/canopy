package accountlink

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/ssnxd/canopy"
	"github.com/ssnxd/canopy/oauth"
	xoauth2 "golang.org/x/oauth2"
)

const (
	moduleID             = "account-link"
	linkIdentifierPrefix = "account_link:"
	// maxRequestBodyBytes limits the size of a request body that the module
	// parses. It matches the limit of the core handler.
	maxRequestBodyBytes = 1 << 20 // 1 MiB
)

// Options configures the account-link module.
type Options struct {
	LinkStateTTL     time.Duration // default: 10 minutes
	RecentAuthMaxAge time.Duration // default: 10 minutes
	StateCookieName  string        // default: "canopy.link_state"
}

// Module adds an explicit account-linking confirmation flow. It implements
// canopy.Module and canopy.RouteModule.
type Module struct {
	linkStateTTL     time.Duration
	recentAuthMaxAge time.Duration
	stateCookieName  string

	core         canopy.Core
	stateKey     []byte
	oldStateKeys [][]byte
}

// New returns an account-link module.
func New(o Options) *Module {
	return &Module{
		linkStateTTL:     o.LinkStateTTL,
		recentAuthMaxAge: o.RecentAuthMaxAge,
		stateCookieName:  o.StateCookieName,
	}
}

func (m *Module) ID() string { return moduleID }

func (m *Module) Init(core canopy.Core) error {
	stateKeys, err := core.ModuleKeys("state")
	if err != nil {
		return err
	}
	m.stateKey = stateKeys.Current
	m.oldStateKeys = stateKeys.Previous
	m.core = core
	if m.linkStateTTL == 0 {
		m.linkStateTTL = 10 * time.Minute
	}
	if m.recentAuthMaxAge == 0 {
		m.recentAuthMaxAge = 10 * time.Minute
	}
	if m.stateCookieName == "" {
		m.stateCookieName = "canopy.link_state"
	}
	return nil
}

func (m *Module) Routes() []canopy.Route {
	return []canopy.Route{
		{Method: http.MethodPost, Pattern: "/link-social", RequireSession: true, Handler: http.HandlerFunc(m.handleInitiate)},
		{Method: http.MethodGet, Pattern: "/link-social/callback/{provider}", RequireSession: true, Handler: http.HandlerFunc(m.handleCallback)},
		{Method: http.MethodPost, Pattern: "/link-social/callback/{provider}", RequireSession: true, Handler: http.HandlerFunc(m.handleCallback)},
	}
}

// linkStatePayload is the signed state for one link attempt. UserID pins
// the flow to the user that started it. BindingHash pins the flow to the
// browser that holds the state cookie.
type linkStatePayload struct {
	ID           string    `json:"id"`
	UserID       string    `json:"userId"`
	Provider     string    `json:"provider"`
	Nonce        string    `json:"nonce"`
	PKCEVerifier string    `json:"pkceVerifier"`
	CallbackURL  string    `json:"callbackURL,omitempty"`
	BindingHash  string    `json:"bindingHash"`
	IssuedAt     time.Time `json:"issuedAt"`
}

func (m *Module) handleInitiate(w http.ResponseWriter, r *http.Request) {
	data, ok := canopy.SessionFromContext(r.Context())
	if !ok {
		canopy.WriteError(w, canopy.ErrUnauthorized)
		return
	}
	if data.Session.ImpersonatedBy != "" {
		m.fail(w, r, data, "", canopy.ErrForbidden)
		return
	}
	if time.Since(data.Session.CreatedAt) > m.recentAuthMaxAge {
		m.fail(w, r, data, "", canopy.ErrRecentAuthentication)
		return
	}
	var req struct {
		Provider    string `json:"provider"`
		CallbackURL string `json:"callbackURL"`
	}
	if !canopy.DecodeJSON(w, r, &req) {
		return
	}
	provider, ok := m.core.Providers()[req.Provider]
	if !ok {
		m.fail(w, r, data, req.Provider, canopy.ErrProviderFailure)
		return
	}
	if _, err := m.core.Store().FindAccountByUserProvider(r.Context(), data.User.ID, provider.ID()); err == nil {
		m.fail(w, r, data, provider.ID(), canopy.ErrConflict)
		return
	} else if !errors.Is(err, canopy.ErrNotFound) {
		m.fail(w, r, data, provider.ID(), err)
		return
	}
	cfg, err := provider.Config(r.Context())
	if err != nil {
		m.fail(w, r, data, provider.ID(), err)
		return
	}
	stateID, err := randToken(18)
	if err != nil {
		canopy.WriteError(w, err)
		return
	}
	nonce, err := randToken(18)
	if err != nil {
		canopy.WriteError(w, err)
		return
	}
	pkce, err := randToken(32)
	if err != nil {
		canopy.WriteError(w, err)
		return
	}
	binding, err := randToken(32)
	if err != nil {
		canopy.WriteError(w, err)
		return
	}
	payload := linkStatePayload{
		ID:           stateID,
		UserID:       data.User.ID,
		Provider:     provider.ID(),
		Nonce:        nonce,
		PKCEVerifier: pkce,
		CallbackURL:  m.core.ResolveCallbackURL(req.CallbackURL),
		BindingHash:  hashToken(binding),
		IssuedAt:     time.Now().UTC(),
	}
	state, err := m.signState(payload)
	if err != nil {
		canopy.WriteError(w, err)
		return
	}
	verificationID, err := randToken(16)
	if err != nil {
		canopy.WriteError(w, err)
		return
	}
	now := time.Now().UTC()
	// ReplaceVerification keeps one pending link per user, so a new
	// initiation invalidates the previous state.
	if err := m.core.Store().ReplaceVerification(r.Context(), &canopy.Verification{
		ID:         "alk_" + verificationID,
		Identifier: linkIdentifierPrefix + data.User.ID,
		Value:      hashToken(state),
		ExpiresAt:  now.Add(m.linkStateTTL),
		CreatedAt:  now,
		UpdatedAt:  now,
	}); err != nil {
		canopy.WriteError(w, err)
		return
	}
	m.setStateCookie(w, binding)
	start := oauth.StartOptions{
		State:        state,
		Nonce:        nonce,
		PKCEVerifier: pkce,
		CallbackURL:  payload.CallbackURL,
	}
	authOpts := append(provider.AuthCodeOptions(start), xoauth2.SetAuthURLParam("nonce", nonce))
	m.core.Audit(r.Context(), canopy.AuditEvent{
		Type: "account_link.initiated", UserID: data.User.ID, Email: data.User.Email,
		ProviderID: provider.ID(), IPAddress: m.core.ClientIP(r), UserAgent: r.UserAgent(), Success: true,
	})
	canopy.WriteJSON(w, http.StatusOK, map[string]string{"url": cfg.AuthCodeURL(state, authOpts...)})
}

func (m *Module) handleCallback(w http.ResponseWriter, r *http.Request) {
	data, ok := canopy.SessionFromContext(r.Context())
	if !ok {
		canopy.WriteError(w, canopy.ErrUnauthorized)
		return
	}
	providerID := r.PathValue("provider")
	if data.Session.ImpersonatedBy != "" {
		m.fail(w, r, data, providerID, canopy.ErrForbidden)
		return
	}
	if time.Since(data.Session.CreatedAt) > m.recentAuthMaxAge {
		m.fail(w, r, data, providerID, canopy.ErrRecentAuthentication)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	if err := r.ParseForm(); err != nil {
		m.fail(w, r, data, providerID, canopy.ErrInvalidInput)
		return
	}
	state := r.Form.Get("state")
	code := r.Form.Get("code")
	if providerID == "" || state == "" || code == "" {
		m.fail(w, r, data, providerID, canopy.ErrInvalidInput)
		return
	}
	provider, ok := m.core.Providers()[providerID]
	if !ok {
		m.fail(w, r, data, providerID, canopy.ErrProviderFailure)
		return
	}
	cookie, err := r.Cookie(m.stateCookieName)
	if err != nil {
		m.fail(w, r, data, providerID, canopy.ErrInvalidState)
		return
	}
	payload, err := m.verifyState(state)
	if err != nil ||
		payload.Provider != provider.ID() ||
		!hmac.Equal([]byte(payload.BindingHash), []byte(hashToken(cookie.Value))) {
		m.fail(w, r, data, providerID, canopy.ErrInvalidState)
		return
	}
	// The completing session must belong to the user that started the
	// link. This stops a fixation of the flow onto another account.
	if payload.UserID != data.User.ID {
		m.fail(w, r, data, providerID, canopy.ErrInvalidState)
		return
	}
	identifier := linkIdentifierPrefix + data.User.ID
	value := hashToken(state)
	tok, err := provider.Exchange(r.Context(), code, payload.PKCEVerifier)
	if err != nil {
		m.fail(w, r, data, providerID, canopy.ErrProviderFailure)
		return
	}
	profile, err := provider.Profile(r.Context(), tok, payload.Nonce)
	if err != nil || profile == nil || profile.AccountID == "" {
		m.fail(w, r, data, providerID, canopy.ErrProviderFailure)
		return
	}
	if profile.ProviderID != "" && profile.ProviderID != provider.ID() {
		m.fail(w, r, data, providerID, canopy.ErrProviderFailure)
		return
	}
	if !profile.EmailVerified {
		m.fail(w, r, data, providerID, canopy.ErrUnverifiedEmail)
		return
	}
	email := normalizeEmail(profile.Email)
	if email == "" || email != normalizeEmail(data.User.Email) {
		m.fail(w, r, data, providerID, canopy.ErrAccountLinkMismatch)
		return
	}
	now := time.Now().UTC()
	if err := m.persistLink(r.Context(), data, provider.ID(), profile, identifier, value, now); err != nil {
		m.fail(w, r, data, providerID, err)
		return
	}
	m.clearStateCookie(w)
	m.core.Audit(r.Context(), canopy.AuditEvent{
		Type: "account_link.succeeded", UserID: data.User.ID, Email: data.User.Email,
		ProviderID: provider.ID(), IPAddress: m.core.ClientIP(r), UserAgent: r.UserAgent(), Success: true,
	})
	if payload.CallbackURL != "" {
		http.Redirect(w, r, payload.CallbackURL, http.StatusFound)
		return
	}
	canopy.WriteJSON(w, http.StatusOK, map[string]any{
		"success":    true,
		"providerId": provider.ID(),
		"accountId":  profile.AccountID,
	})
}

// persistLink consumes the one-time link state and writes the provider
// account. A new account is created atomically with the consume. An
// account that is already linked to the same user gets a credential
// refresh after a separate consume.
func (m *Module) persistLink(
	ctx context.Context,
	data *canopy.SessionData,
	providerID string,
	profile *oauth.Profile,
	identifier string,
	value string,
	now time.Time,
) error {
	existing, err := m.core.Store().FindAccount(ctx, providerID, profile.AccountID)
	switch {
	case err == nil && existing.UserID != data.User.ID:
		return canopy.ErrConflict
	case err == nil:
		// The account is already linked to this user. Consume the state so
		// it stays single-use, then refresh the credentials idempotently.
		if _, err := m.core.Store().ConsumeVerification(ctx, identifier, value, now); err != nil {
			return canopy.ErrInvalidState
		}
		account := &canopy.Account{
			UserID:     data.User.ID,
			AccountID:  profile.AccountID,
			ProviderID: providerID,
		}
		applyProfileCredentials(account, profile)
		return m.core.UpdateLinkedAccount(ctx, account)
	case errors.Is(err, canopy.ErrNotFound):
		accountID, err := randToken(18)
		if err != nil {
			return err
		}
		account := &canopy.Account{
			ID:         "acc_" + strings.ToLower(accountID),
			UserID:     data.User.ID,
			AccountID:  profile.AccountID,
			ProviderID: providerID,
			CreatedAt:  now,
			UpdatedAt:  now,
		}
		applyProfileCredentials(account, profile)
		if err := m.core.LinkAccount(ctx, identifier, value, now, account); err != nil {
			if errors.Is(err, canopy.ErrNotFound) {
				return canopy.ErrInvalidState
			}
			return err
		}
		return nil
	default:
		return err
	}
}

// fail audits a failed link step and writes the error response.
func (m *Module) fail(w http.ResponseWriter, r *http.Request, data *canopy.SessionData, providerID string, err error) {
	m.core.Audit(r.Context(), canopy.AuditEvent{
		Type: "account_link.failed", UserID: data.User.ID, Email: data.User.Email,
		ProviderID: providerID, IPAddress: m.core.ClientIP(r), UserAgent: r.UserAgent(),
		Success: false, Error: err.Error(),
	})
	canopy.WriteError(w, err)
}

func (m *Module) setStateCookie(w http.ResponseWriter, value string) {
	session := m.core.Config().Session
	http.SetCookie(w, &http.Cookie{
		Name:     m.stateCookieName,
		Value:    value,
		Path:     session.CookiePath,
		Domain:   session.CookieDomain,
		HttpOnly: true,
		Secure:   session.Secure,
		SameSite: session.SameSite,
		MaxAge:   int(m.linkStateTTL.Seconds()),
		Expires:  time.Now().Add(m.linkStateTTL),
	})
}

func (m *Module) clearStateCookie(w http.ResponseWriter) {
	session := m.core.Config().Session
	http.SetCookie(w, &http.Cookie{
		Name:     m.stateCookieName,
		Value:    "",
		Path:     session.CookiePath,
		Domain:   session.CookieDomain,
		HttpOnly: true,
		Secure:   session.Secure,
		SameSite: session.SameSite,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}

func (m *Module) signState(payload linkStatePayload) (string, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(body)
	return encoded + "." + m.sign(encoded), nil
}

func (m *Module) verifyState(state string) (linkStatePayload, error) {
	var payload linkStatePayload
	parts := strings.SplitN(state, ".", 2)
	if len(parts) != 2 {
		return payload, canopy.ErrInvalidState
	}
	if !m.validSignature(parts[0], parts[1]) {
		return payload, canopy.ErrInvalidState
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return payload, canopy.ErrInvalidState
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return payload, canopy.ErrInvalidState
	}
	if payload.ID == "" || payload.UserID == "" || payload.Provider == "" ||
		payload.Nonce == "" || payload.PKCEVerifier == "" || payload.BindingHash == "" {
		return payload, canopy.ErrInvalidState
	}
	return payload, nil
}

func (m *Module) sign(value string) string {
	mac := hmac.New(sha256.New, m.stateKey)
	_, _ = mac.Write([]byte(value))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (m *Module) validSignature(value, signature string) bool {
	valid := false
	for _, key := range append([][]byte{m.stateKey}, m.oldStateKeys...) {
		mac := hmac.New(sha256.New, key)
		_, _ = mac.Write([]byte(value))
		if hmac.Equal([]byte(signature), []byte(base64.RawURLEncoding.EncodeToString(mac.Sum(nil)))) {
			valid = true
		}
	}
	return valid
}

func applyProfileCredentials(account *canopy.Account, profile *oauth.Profile) {
	account.AccessToken = profile.AccessToken
	account.RefreshToken = profile.RefreshToken
	account.AccessTokenExpiresAt = profile.AccessTokenExpiresAt
	account.RefreshTokenExpiresAt = profile.RefreshTokenExpiresAt
	account.Scope = profile.Scope
	account.IDToken = profile.IDToken
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

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
