//go:build e2e

package canopy_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/ssnxd/canopy"
	authoauth "github.com/ssnxd/canopy/oauth"
	"github.com/ssnxd/canopy/store/postgres"
	"golang.org/x/oauth2"
)

func TestE2EEmailPasswordHTTPWithPostgres(t *testing.T) {
	db := e2eDB(t)
	sender := &e2eEmailSender{}
	auth := e2eAuth(t, db, canopy.Config{
		RequireEmailVerification: true,
		EmailSender:              sender,
		TrustedOrigins:           []string{"https://app.example.test"},
	})
	handler := auth.Handler()

	signup := postJSON(t, handler, "/sign-up/email", map[string]string{
		"name":        "Ada Lovelace",
		"email":       "Ada@Example.COM",
		"password":    "correct-password",
		"callbackURL": "https://app.example.test/verify",
	}, nil)
	if signup.Code != http.StatusOK {
		t.Fatalf("signup status = %d, body = %s", signup.Code, signup.Body.String())
	}
	signupCookie := cookieNamed(t, signup.Result().Cookies(), "canopy.session_token")
	if signupCookie.Value == "" || !signupCookie.HttpOnly {
		t.Fatalf("signup cookie = %#v", signupCookie)
	}
	if len(sender.verificationMessages) != 1 {
		t.Fatalf("verification messages = %d, want 1", len(sender.verificationMessages))
	}

	blocked := postJSON(t, handler, "/sign-in/email", map[string]string{
		"email":    "ada@example.com",
		"password": "correct-password",
	}, nil)
	if blocked.Code != http.StatusForbidden {
		t.Fatalf("unverified signin status = %d, body = %s", blocked.Code, blocked.Body.String())
	}

	verify := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/verify-email?token="+url.QueryEscape(sender.verificationMessages[0].Token), nil)
	handler.ServeHTTP(verify, req)
	if verify.Code != http.StatusOK {
		t.Fatalf("verify status = %d, body = %s", verify.Code, verify.Body.String())
	}

	signin := postJSON(t, handler, "/sign-in/email", map[string]string{
		"email":    "ada@example.com",
		"password": "correct-password",
	}, nil)
	if signin.Code != http.StatusOK {
		t.Fatalf("signin status = %d, body = %s", signin.Code, signin.Body.String())
	}
	sessionCookie := cookieNamed(t, signin.Result().Cookies(), "canopy.session_token")

	session := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/get-session", nil)
	req.AddCookie(sessionCookie)
	handler.ServeHTTP(session, req)
	if session.Code != http.StatusOK || session.Body.String() == "null\n" {
		t.Fatalf("get-session status = %d, body = %s", session.Code, session.Body.String())
	}

	resetRequest := postJSON(t, handler, "/request-password-reset", map[string]string{
		"email":       "ada@example.com",
		"callbackURL": "https://app.example.test/reset",
	}, nil)
	if resetRequest.Code != http.StatusOK {
		t.Fatalf("request reset status = %d, body = %s", resetRequest.Code, resetRequest.Body.String())
	}
	if len(sender.resetMessages) != 1 {
		t.Fatalf("reset messages = %d, want 1", len(sender.resetMessages))
	}

	reset := postJSON(t, handler, "/reset-password", map[string]string{
		"token":       sender.resetMessages[0].Token,
		"newPassword": "new-correct-password",
	}, nil)
	if reset.Code != http.StatusOK {
		t.Fatalf("reset status = %d, body = %s", reset.Code, reset.Body.String())
	}

	revoked := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/get-session", nil)
	req.AddCookie(sessionCookie)
	handler.ServeHTTP(revoked, req)
	if revoked.Code != http.StatusOK || revoked.Body.String() != "null\n" {
		t.Fatalf("revoked session status = %d, body = %s", revoked.Code, revoked.Body.String())
	}

	oldPassword := postJSON(t, handler, "/sign-in/email", map[string]string{
		"email":    "ada@example.com",
		"password": "correct-password",
	}, nil)
	if oldPassword.Code != http.StatusUnauthorized {
		t.Fatalf("old password status = %d, body = %s", oldPassword.Code, oldPassword.Body.String())
	}

	newPassword := postJSON(t, handler, "/sign-in/email", map[string]string{
		"email":    "ada@example.com",
		"password": "new-correct-password",
	}, nil)
	if newPassword.Code != http.StatusOK {
		t.Fatalf("new password status = %d, body = %s", newPassword.Code, newPassword.Body.String())
	}
}

func TestE2EOAuthHTTPWithPostgres(t *testing.T) {
	db := e2eDB(t)
	provider := &e2eOAuthProvider{
		id:        "google",
		email:     "oauth@example.com",
		accountID: "google-sub",
	}
	auth := e2eAuth(t, db, canopy.Config{
		Providers:      []authoauth.Provider{provider},
		TrustedOrigins: []string{"https://app.example.test"},
	})
	handler := auth.Handler()

	start := postJSON(t, handler, "/sign-in/social", map[string]string{
		"provider":    "google",
		"callbackURL": "https://app.example.test/dashboard",
	}, nil)
	if start.Code != http.StatusOK {
		t.Fatalf("oauth start status = %d, body = %s", start.Code, start.Body.String())
	}
	stateCookie := cookieNamed(t, start.Result().Cookies(), "canopy.oauth_state")
	var startBody canopy.SignInSocialOutput
	if err := json.NewDecoder(start.Body).Decode(&startBody); err != nil {
		t.Fatal(err)
	}
	state := stateFromURL(t, startBody.URL)

	callback := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/callback/google?state="+url.QueryEscape(state)+"&code=auth-code", nil)
	req.AddCookie(stateCookie)
	handler.ServeHTTP(callback, req)
	if callback.Code != http.StatusFound {
		t.Fatalf("oauth callback status = %d, body = %s", callback.Code, callback.Body.String())
	}
	if callback.Header().Get("Location") != "https://app.example.test/dashboard" {
		t.Fatalf("callback location = %q", callback.Header().Get("Location"))
	}
	sessionCookie := cookieNamed(t, callback.Result().Cookies(), "canopy.session_token")
	if sessionCookie.Value == "" || !sessionCookie.HttpOnly {
		t.Fatalf("session cookie = %#v", sessionCookie)
	}

	refresh := postJSON(t, handler, "/refresh-provider-token", map[string]string{
		"providerId": "google",
	}, []*http.Cookie{sessionCookie})
	if refresh.Code != http.StatusOK {
		t.Fatalf("refresh status = %d, body = %s", refresh.Code, refresh.Body.String())
	}
	var refreshed struct {
		AccessToken string `json:"accessToken"`
		ProviderID  string `json:"providerId"`
	}
	if err := json.NewDecoder(refresh.Body).Decode(&refreshed); err != nil {
		t.Fatal(err)
	}
	if refreshed.ProviderID != "google" || refreshed.AccessToken != "new-access-token" {
		t.Fatalf("refresh body = %#v", refreshed)
	}

	replay := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/callback/google?state="+url.QueryEscape(state)+"&code=auth-code", nil)
	req.AddCookie(stateCookie)
	handler.ServeHTTP(replay, req)
	if replay.Code != http.StatusBadRequest {
		t.Fatalf("replay status = %d, body = %s", replay.Code, replay.Body.String())
	}
}

func e2eAuth(t *testing.T, db *sql.DB, cfg canopy.Config) *canopy.Auth {
	t.Helper()
	cfg.Store = postgres.New(db)
	cfg.Secret = "dev-secret-with-enough-test-entropy"
	auth, err := canopy.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return auth
}

func e2eDB(t *testing.T) *sql.DB {
	t.Helper()
	raw := os.Getenv("CANOPY_E2E_DATABASE_URL")
	if raw == "" {
		t.Skip("set CANOPY_E2E_DATABASE_URL to run e2e tests")
	}
	admin, err := sql.Open("postgres", raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.Ping(); err != nil {
		t.Fatalf("connect to e2e database: %v", err)
	}
	schema := "canopy_e2e_" + randomHex(t, 8)
	if _, err := admin.Exec(`create schema ` + quoteIdent(schema)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(`drop schema if exists ` + quoteIdent(schema) + ` cascade`)
		_ = admin.Close()
	})

	db, err := sql.Open("postgres", withSearchPath(raw, schema))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(4)
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Ping(); err != nil {
		t.Fatalf("connect to e2e schema: %v", err)
	}
	if err := postgres.New(db).Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return db
}

func withSearchPath(raw, schema string) string {
	if u, err := url.Parse(raw); err == nil && u.Scheme != "" && u.Host != "" {
		q := u.Query()
		q.Set("search_path", schema)
		u.RawQuery = q.Encode()
		return u.String()
	}
	if strings.TrimSpace(raw) == "" {
		return raw
	}
	return raw + " search_path=" + schema
}

func quoteIdent(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
}

func randomHex(t *testing.T, n int) string {
	t.Helper()
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(buf)
}

func postJSON(t *testing.T, handler http.Handler, path string, body any, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(encoded))
	req.Header.Set("Content-Type", "application/json")
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func cookieNamed(t *testing.T, cookies []*http.Cookie, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	t.Fatalf("missing cookie %q in %#v", name, cookies)
	return nil
}

func stateFromURL(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	state := u.Query().Get("state")
	if state == "" {
		t.Fatalf("auth url missing state: %s", raw)
	}
	return state
}

type e2eEmailSender struct {
	verificationMessages []canopy.EmailVerificationMessage
	resetMessages        []canopy.PasswordResetMessage
}

func (s *e2eEmailSender) SendEmailVerification(ctx context.Context, message canopy.EmailVerificationMessage) error {
	s.verificationMessages = append(s.verificationMessages, message)
	return nil
}

func (s *e2eEmailSender) SendPasswordReset(ctx context.Context, message canopy.PasswordResetMessage) error {
	s.resetMessages = append(s.resetMessages, message)
	return nil
}

type e2eOAuthProvider struct {
	id        string
	email     string
	accountID string
	nonce     string
}

func (p *e2eOAuthProvider) ID() string { return p.id }

func (p *e2eOAuthProvider) Config(ctx context.Context) (*oauth2.Config, error) {
	return &oauth2.Config{
		ClientID:     "client",
		ClientSecret: "secret",
		RedirectURL:  "https://app.example.test/callback/" + p.id,
		Scopes:       []string{"openid", "email", "profile"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://" + p.id + ".example.test/auth",
			TokenURL: "https://" + p.id + ".example.test/token",
		},
	}, nil
}

func (p *e2eOAuthProvider) AuthCodeOptions(opts authoauth.StartOptions) []oauth2.AuthCodeOption {
	p.nonce = opts.Nonce
	return []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(opts.PKCEVerifier)}
}

func (p *e2eOAuthProvider) Exchange(ctx context.Context, code string, verifier string) (*oauth2.Token, error) {
	return &oauth2.Token{
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		Expiry:       time.Now().Add(time.Hour),
	}, nil
}

func (p *e2eOAuthProvider) Refresh(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	return (&oauth2.Token{
		AccessToken:  "new-access-token",
		RefreshToken: refreshToken,
		Expiry:       time.Now().Add(time.Hour),
	}).WithExtra(map[string]any{"scope": "openid email profile"}), nil
}

func (p *e2eOAuthProvider) Profile(ctx context.Context, token *oauth2.Token, nonce string) (*authoauth.Profile, error) {
	if nonce != p.nonce {
		return nil, canopy.ErrInvalidState
	}
	return &authoauth.Profile{
		ProviderID:           p.id,
		AccountID:            p.accountID,
		Email:                p.email,
		EmailVerified:        true,
		Name:                 "OAuth User",
		Image:                "https://example.test/avatar.png",
		AccessToken:          token.AccessToken,
		RefreshToken:         token.RefreshToken,
		AccessTokenExpiresAt: &token.Expiry,
	}, nil
}
