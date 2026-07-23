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
	"github.com/ssnxd/canopy/admin"
	authoauth "github.com/ssnxd/canopy/oauth"
	"github.com/ssnxd/canopy/organization"
	"github.com/ssnxd/canopy/store/postgres"
	"github.com/ssnxd/canopy/twofactor"
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

func TestE2ETwoFactorWithPostgres(t *testing.T) {
	db := e2eDB(t)
	auth := e2eAuth(t, db, canopy.Config{
		Modules: []canopy.Module{twofactor.New(twofactor.Options{Issuer: "Canopy E2E"})},
	})
	handler := auth.Handler()
	totp := twofactor.NewTOTP()

	signup := postJSON(t, handler, "/sign-up/email", map[string]string{
		"name": "Ada", "email": "tfa@example.com", "password": "correct-password",
	}, nil)
	if signup.Code != http.StatusOK {
		t.Fatalf("signup status = %d, body = %s", signup.Code, signup.Body.String())
	}
	sessionCookie := cookieNamed(t, signup.Result().Cookies(), "canopy.session_token")

	enable := postJSON(t, handler, "/two-factor/enable", map[string]string{}, []*http.Cookie{sessionCookie})
	if enable.Code != http.StatusOK {
		t.Fatalf("enable status = %d, body = %s", enable.Code, enable.Body.String())
	}
	var enableBody struct {
		Secret string `json:"secret"`
	}
	if err := json.NewDecoder(enable.Body).Decode(&enableBody); err != nil {
		t.Fatal(err)
	}

	code, err := totp.GenerateCode(enableBody.Secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	verify := postJSON(t, handler, "/two-factor/verify", map[string]string{"code": code}, []*http.Cookie{sessionCookie})
	if verify.Code != http.StatusOK {
		t.Fatalf("verify status = %d, body = %s", verify.Code, verify.Body.String())
	}
	var verifyBody struct {
		BackupCodes []string `json:"backupCodes"`
	}
	if err := json.NewDecoder(verify.Body).Decode(&verifyBody); err != nil {
		t.Fatal(err)
	}
	if len(verifyBody.BackupCodes) == 0 {
		t.Fatal("no backup codes returned")
	}

	// Sign-in now returns a challenge instead of a session.
	challengeToken := func() string {
		signin := postJSON(t, handler, "/sign-in/email", map[string]string{
			"email": "tfa@example.com", "password": "correct-password",
		}, nil)
		if signin.Code != http.StatusOK {
			t.Fatalf("signin status = %d, body = %s", signin.Code, signin.Body.String())
		}
		var body struct {
			TwoFactorRequired bool   `json:"twoFactorRequired"`
			Token             string `json:"token"`
		}
		if err := json.NewDecoder(signin.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if !body.TwoFactorRequired || body.Token == "" {
			t.Fatalf("expected a challenge, got %#v", body)
		}
		return body.Token
	}

	// Complete with a TOTP code.
	code2, err := totp.GenerateCode(enableBody.Secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	challenge := postJSON(t, handler, "/two-factor/challenge", map[string]any{"token": challengeToken(), "code": code2}, nil)
	if challenge.Code != http.StatusOK {
		t.Fatalf("challenge status = %d, body = %s", challenge.Code, challenge.Body.String())
	}
	cookieNamed(t, challenge.Result().Cookies(), "canopy.session_token")

	// A backup code works once.
	backup := postJSON(t, handler, "/two-factor/backup", map[string]any{"token": challengeToken(), "code": verifyBody.BackupCodes[0]}, nil)
	if backup.Code != http.StatusOK {
		t.Fatalf("backup status = %d, body = %s", backup.Code, backup.Body.String())
	}
	reuse := postJSON(t, handler, "/two-factor/backup", map[string]any{"token": challengeToken(), "code": verifyBody.BackupCodes[0]}, nil)
	if reuse.Code != http.StatusUnauthorized {
		t.Fatalf("reused backup status = %d, want 401", reuse.Code)
	}
}

func TestE2EOrganizationWithPostgres(t *testing.T) {
	db := e2eDB(t)
	auth := e2eAuth(t, db, canopy.Config{
		Modules: []canopy.Module{organization.New(organization.Options{})},
	})
	handler := auth.Handler()

	ownerCookie := e2eSignUp(t, handler, "Ada", "owner@example.com")
	inviteeCookie := e2eSignUp(t, handler, "Grace", "member@example.com")

	create := postJSON(t, handler, "/organization/create", map[string]string{"name": "Acme Inc"}, []*http.Cookie{ownerCookie})
	if create.Code != http.StatusOK {
		t.Fatalf("create status = %d, body = %s", create.Code, create.Body.String())
	}
	var org canopy.Organization
	if err := json.NewDecoder(create.Body).Decode(&org); err != nil {
		t.Fatal(err)
	}

	invite := postJSON(t, handler, "/organization/invite", map[string]string{
		"organizationId": org.ID, "email": "member@example.com", "role": organization.RoleMember,
	}, []*http.Cookie{ownerCookie})
	if invite.Code != http.StatusOK {
		t.Fatalf("invite status = %d, body = %s", invite.Code, invite.Body.String())
	}
	var invitation canopy.Invitation
	if err := json.NewDecoder(invite.Body).Decode(&invitation); err != nil {
		t.Fatal(err)
	}

	accept := postJSON(t, handler, "/organization/accept-invitation", map[string]string{"invitationId": invitation.ID}, []*http.Cookie{inviteeCookie})
	if accept.Code != http.StatusOK {
		t.Fatalf("accept status = %d, body = %s", accept.Code, accept.Body.String())
	}

	setActive := postJSON(t, handler, "/organization/set-active", map[string]string{"organizationId": org.ID}, []*http.Cookie{inviteeCookie})
	if setActive.Code != http.StatusOK {
		t.Fatalf("set-active status = %d, body = %s", setActive.Code, setActive.Body.String())
	}

	membersReq := httptest.NewRequest(http.MethodGet, "/organization/members?organizationId="+org.ID, nil)
	membersReq.AddCookie(ownerCookie)
	membersRec := httptest.NewRecorder()
	handler.ServeHTTP(membersRec, membersReq)
	if membersRec.Code != http.StatusOK {
		t.Fatalf("members status = %d, body = %s", membersRec.Code, membersRec.Body.String())
	}
	var membersBody struct {
		Members []canopy.Member `json:"members"`
	}
	if err := json.NewDecoder(membersRec.Body).Decode(&membersBody); err != nil {
		t.Fatal(err)
	}
	if len(membersBody.Members) != 2 {
		t.Fatalf("members = %d, want 2", len(membersBody.Members))
	}
}

func TestE2EAdminWithPostgres(t *testing.T) {
	db := e2eDB(t)
	store := postgres.New(db)
	auth := e2eAuth(t, db, canopy.Config{
		Modules: []canopy.Module{admin.New(admin.Options{})},
	})
	handler := auth.Handler()

	adminCookie := e2eSignUp(t, handler, "Root", "root@example.com")
	adminUser, err := store.FindUserByEmail(context.Background(), "root@example.com")
	if err != nil {
		t.Fatal(err)
	}
	adminUser.Role = "admin"
	if err := store.UpdateUser(context.Background(), adminUser); err != nil {
		t.Fatal(err)
	}

	e2eSignUp(t, handler, "Grace", "grace@example.com")
	target, err := store.FindUserByEmail(context.Background(), "grace@example.com")
	if err != nil {
		t.Fatal(err)
	}

	// List users.
	listReq := httptest.NewRequest(http.MethodGet, "/admin/users?q=grace", nil)
	listReq.AddCookie(adminCookie)
	listRec := httptest.NewRecorder()
	handler.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list users status = %d, body = %s", listRec.Code, listRec.Body.String())
	}
	var listBody struct {
		Users []canopy.User `json:"users"`
		Total int           `json:"total"`
	}
	if err := json.NewDecoder(listRec.Body).Decode(&listBody); err != nil {
		t.Fatal(err)
	}
	if listBody.Total != 1 || len(listBody.Users) != 1 {
		t.Fatalf("search grace returned total=%d users=%d", listBody.Total, len(listBody.Users))
	}

	// Ban blocks sign-in; unban restores it.
	ban := postJSON(t, handler, "/admin/ban-user", map[string]any{"userId": target.ID, "reason": "abuse"}, []*http.Cookie{adminCookie})
	if ban.Code != http.StatusOK {
		t.Fatalf("ban status = %d, body = %s", ban.Code, ban.Body.String())
	}
	blocked := postJSON(t, handler, "/sign-in/email", map[string]string{"email": "grace@example.com", "password": "correct-password"}, nil)
	if blocked.Code != http.StatusForbidden {
		t.Fatalf("banned sign-in status = %d, want 403", blocked.Code)
	}
	unban := postJSON(t, handler, "/admin/unban-user", map[string]string{"userId": target.ID}, []*http.Cookie{adminCookie})
	if unban.Code != http.StatusOK {
		t.Fatalf("unban status = %d, body = %s", unban.Code, unban.Body.String())
	}

	// Impersonate the target and stop.
	imp := postJSON(t, handler, "/admin/impersonate", map[string]string{"userId": target.ID}, []*http.Cookie{adminCookie})
	if imp.Code != http.StatusOK {
		t.Fatalf("impersonate status = %d, body = %s", imp.Code, imp.Body.String())
	}
	impCookie := cookieNamed(t, imp.Result().Cookies(), "canopy.session_token")
	stop := postJSON(t, handler, "/admin/stop-impersonating", nil, []*http.Cookie{impCookie})
	if stop.Code != http.StatusOK {
		t.Fatalf("stop status = %d, body = %s", stop.Code, stop.Body.String())
	}
	var restored canopy.SessionData
	if err := json.NewDecoder(stop.Body).Decode(&restored); err != nil {
		t.Fatal(err)
	}
	if restored.User.Email != "root@example.com" {
		t.Fatalf("restored user = %q, want root", restored.User.Email)
	}
}

func e2eSignUp(t *testing.T, handler http.Handler, name, email string) *http.Cookie {
	t.Helper()
	rec := postJSON(t, handler, "/sign-up/email", map[string]string{
		"name": name, "email": email, "password": "correct-password",
	}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("signup status = %d, body = %s", rec.Code, rec.Body.String())
	}
	return cookieNamed(t, rec.Result().Cookies(), "canopy.session_token")
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
