package accountlink_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ssnxd/canopy"
	"github.com/ssnxd/canopy/accountlink"
	authoauth "github.com/ssnxd/canopy/oauth"
	"github.com/ssnxd/canopy/store/memory"
	"golang.org/x/oauth2"
)

// fakeProvider is a deterministic OAuth provider modeled on the fake
// provider in the core oauth tests. It accepts every nonce it issued, so a
// superseded state fails at the one-time verification instead of at the
// provider.
type fakeProvider struct {
	id              string
	email           string
	accountID       string
	emailUnverified bool
	nonces          map[string]bool
	lastVerifier    string
}

func newFakeProvider(id, email, accountID string) *fakeProvider {
	return &fakeProvider{id: id, email: email, accountID: accountID, nonces: map[string]bool{}}
}

func (p *fakeProvider) ID() string { return p.id }

func (p *fakeProvider) Config(ctx context.Context) (*oauth2.Config, error) {
	return &oauth2.Config{
		ClientID:     "client",
		ClientSecret: "secret",
		RedirectURL:  "https://app.example.test/link-social/callback/" + p.id,
		Scopes:       []string{"openid", "email", "profile"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://" + p.id + ".example.test/auth",
			TokenURL: "https://" + p.id + ".example.test/token",
		},
	}, nil
}

func (p *fakeProvider) AuthCodeOptions(opts authoauth.StartOptions) []oauth2.AuthCodeOption {
	p.nonces[opts.Nonce] = true
	return []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(opts.PKCEVerifier)}
}

func (p *fakeProvider) Exchange(ctx context.Context, code string, verifier string) (*oauth2.Token, error) {
	p.lastVerifier = verifier
	return &oauth2.Token{
		AccessToken:  "link-access-token",
		RefreshToken: "link-refresh-token",
		Expiry:       time.Now().Add(time.Hour),
	}, nil
}

func (p *fakeProvider) Refresh(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	return &oauth2.Token{AccessToken: "refreshed", RefreshToken: refreshToken}, nil
}

func (p *fakeProvider) Profile(ctx context.Context, token *oauth2.Token, nonce string) (*authoauth.Profile, error) {
	if !p.nonces[nonce] {
		return nil, canopy.ErrInvalidState
	}
	return &authoauth.Profile{
		ProviderID:           p.id,
		AccountID:            p.accountID,
		Email:                p.email,
		EmailVerified:        !p.emailUnverified,
		Name:                 "Link User",
		AccessToken:          token.AccessToken,
		RefreshToken:         token.RefreshToken,
		AccessTokenExpiresAt: &token.Expiry,
	}, nil
}

type flowFixture struct {
	auth     *canopy.Auth
	handler  http.Handler
	store    *memory.Store
	provider *fakeProvider
}

func newFlow(t *testing.T, opts accountlink.Options) *flowFixture {
	t.Helper()
	store := memory.New()
	provider := newFakeProvider("google", "ada@example.com", "google-sub")
	auth, err := canopy.New(canopy.Config{
		Store:     store,
		Secret:    "dev-secret-with-enough-test-entropy",
		Providers: []authoauth.Provider{provider},
		Modules:   []canopy.Module{accountlink.New(opts)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return &flowFixture{auth: auth, handler: auth.Handler(), store: store, provider: provider}
}

func post(t *testing.T, handler http.Handler, path string, body any, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(encoded))
	req.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func get(t *testing.T, handler http.Handler, path string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func cookie(t *testing.T, rec *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("missing cookie %q", name)
	return nil
}

func decode(t *testing.T, rec *httptest.ResponseRecorder, dst any) {
	t.Helper()
	if err := json.NewDecoder(rec.Body).Decode(dst); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, rec.Body.String())
	}
}

func errorCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	decode(t, rec, &body)
	return body.Error.Code
}

func (f *flowFixture) signUp(t *testing.T, email string) *http.Cookie {
	t.Helper()
	rec := post(t, f.handler, "/sign-up/email", map[string]string{
		"name": "Ada", "email": email, "password": "correct-password",
	}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("signup status = %d, body = %s", rec.Code, rec.Body.String())
	}
	return cookie(t, rec, "canopy.session_token")
}

// initiate starts a link and returns the provider state and the binding
// cookie.
func (f *flowFixture) initiate(t *testing.T, session *http.Cookie) (string, *http.Cookie) {
	t.Helper()
	rec := post(t, f.handler, "/link-social", map[string]string{"provider": "google"}, []*http.Cookie{session})
	if rec.Code != http.StatusOK {
		t.Fatalf("initiate status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var body struct {
		URL string `json:"url"`
	}
	decode(t, rec, &body)
	u, err := url.Parse(body.URL)
	if err != nil {
		t.Fatal(err)
	}
	state := u.Query().Get("state")
	if state == "" {
		t.Fatalf("auth url missing state: %s", body.URL)
	}
	binding := cookie(t, rec, "canopy.link_state")
	if binding.Value == "" || !binding.HttpOnly {
		t.Fatalf("binding cookie = %#v", binding)
	}
	return state, binding
}

func (f *flowFixture) complete(t *testing.T, state string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	return get(t, f.handler, "/link-social/callback/google?state="+url.QueryEscape(state)+"&code=auth-code", cookies)
}

// backdateSession makes the session older than the recent-auth window.
func (f *flowFixture) backdateSession(t *testing.T, session *http.Cookie) {
	t.Helper()
	data, err := f.store.FindSessionByToken(context.Background(), session.Value)
	if err != nil {
		t.Fatal(err)
	}
	data.Session.CreatedAt = time.Now().Add(-11 * time.Minute)
	if err := f.store.UpdateSession(context.Background(), &data.Session); err != nil {
		t.Fatal(err)
	}
}

func TestAccountLinkHappyPathStoresEncryptedTokens(t *testing.T) {
	f := newFlow(t, accountlink.Options{})
	session := f.signUp(t, "ada@example.com")
	state, binding := f.initiate(t, session)

	rec := f.complete(t, state, []*http.Cookie{session, binding})
	if rec.Code != http.StatusOK {
		t.Fatalf("complete status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Success    bool   `json:"success"`
		ProviderID string `json:"providerId"`
		AccountID  string `json:"accountId"`
	}
	decode(t, rec, &body)
	if !body.Success || body.ProviderID != "google" || body.AccountID != "google-sub" {
		t.Fatalf("complete body = %#v", body)
	}
	if f.provider.lastVerifier == "" {
		t.Fatal("PKCE verifier was not passed to provider exchange")
	}
	cleared := cookie(t, rec, "canopy.link_state")
	if cleared.MaxAge >= 0 {
		t.Fatalf("state cookie was not cleared: %#v", cleared)
	}
	data, err := f.store.FindSessionByToken(context.Background(), session.Value)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := f.store.FindAccount(context.Background(), "google", "google-sub")
	if err != nil {
		t.Fatal(err)
	}
	if stored.UserID != data.User.ID {
		t.Fatalf("account user = %q, want %q", stored.UserID, data.User.ID)
	}
	if stored.AccessToken == "" || stored.AccessToken == "link-access-token" ||
		stored.RefreshToken == "" || stored.RefreshToken == "link-refresh-token" {
		t.Fatalf("provider credentials were stored in plaintext: %#v", stored)
	}
	if !strings.HasPrefix(stored.AccessToken, "enc.v1.") {
		t.Fatalf("access token is not in the encrypted envelope: %q", stored.AccessToken)
	}
}

func TestAccountLinkRedirectsToCallbackURLOnSuccess(t *testing.T) {
	f := newFlow(t, accountlink.Options{})
	session := f.signUp(t, "ada@example.com")
	rec := post(t, f.handler, "/link-social", map[string]string{
		"provider": "google", "callbackURL": "/settings/security",
	}, []*http.Cookie{session})
	if rec.Code != http.StatusOK {
		t.Fatalf("initiate status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var body struct {
		URL string `json:"url"`
	}
	decode(t, rec, &body)
	u, err := url.Parse(body.URL)
	if err != nil {
		t.Fatal(err)
	}
	binding := cookie(t, rec, "canopy.link_state")

	done := f.complete(t, u.Query().Get("state"), []*http.Cookie{session, binding})
	if done.Code != http.StatusFound {
		t.Fatalf("complete status = %d, want 302", done.Code)
	}
	if got := done.Header().Get("Location"); got != "/settings/security" {
		t.Fatalf("redirect location = %q", got)
	}
}

func TestAccountLinkRejectsReplayedState(t *testing.T) {
	f := newFlow(t, accountlink.Options{})
	session := f.signUp(t, "ada@example.com")
	state, binding := f.initiate(t, session)

	first := f.complete(t, state, []*http.Cookie{session, binding})
	if first.Code != http.StatusOK {
		t.Fatalf("first complete status = %d, body = %s", first.Code, first.Body.String())
	}
	replay := f.complete(t, state, []*http.Cookie{session, binding})
	if replay.Code != http.StatusBadRequest || errorCode(t, replay) != "INVALID_STATE" {
		t.Fatalf("replay status = %d, body = %s", replay.Code, replay.Body.String())
	}
}

func TestAccountLinkRejectsExpiredState(t *testing.T) {
	f := newFlow(t, accountlink.Options{LinkStateTTL: time.Nanosecond})
	session := f.signUp(t, "ada@example.com")
	state, binding := f.initiate(t, session)

	rec := f.complete(t, state, []*http.Cookie{session, binding})
	if rec.Code != http.StatusBadRequest || errorCode(t, rec) != "INVALID_STATE" {
		t.Fatalf("expired complete status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if _, err := f.store.FindAccount(context.Background(), "google", "google-sub"); err != canopy.ErrNotFound {
		t.Fatalf("account err = %v, want ErrNotFound", err)
	}
}

func TestAccountLinkSecondInitiateSupersedesFirstState(t *testing.T) {
	f := newFlow(t, accountlink.Options{})
	session := f.signUp(t, "ada@example.com")
	firstState, firstBinding := f.initiate(t, session)
	secondState, secondBinding := f.initiate(t, session)

	stale := f.complete(t, firstState, []*http.Cookie{session, firstBinding})
	if stale.Code != http.StatusBadRequest || errorCode(t, stale) != "INVALID_STATE" {
		t.Fatalf("superseded complete status = %d, body = %s", stale.Code, stale.Body.String())
	}
	fresh := f.complete(t, secondState, []*http.Cookie{session, secondBinding})
	if fresh.Code != http.StatusOK {
		t.Fatalf("fresh complete status = %d, body = %s", fresh.Code, fresh.Body.String())
	}
}

func TestAccountLinkRejectsCompletionByAnotherUser(t *testing.T) {
	f := newFlow(t, accountlink.Options{})
	adaSession := f.signUp(t, "ada@example.com")
	state, binding := f.initiate(t, adaSession)
	bobSession := f.signUp(t, "bob@example.com")

	rec := f.complete(t, state, []*http.Cookie{bobSession, binding})
	if rec.Code != http.StatusBadRequest || errorCode(t, rec) != "INVALID_STATE" {
		t.Fatalf("wrong-user complete status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if _, err := f.store.FindAccount(context.Background(), "google", "google-sub"); err != canopy.ErrNotFound {
		t.Fatalf("account err = %v, want ErrNotFound", err)
	}
}

func TestAccountLinkRejectsUnverifiedProviderEmail(t *testing.T) {
	f := newFlow(t, accountlink.Options{})
	f.provider.emailUnverified = true
	session := f.signUp(t, "ada@example.com")
	state, binding := f.initiate(t, session)

	rec := f.complete(t, state, []*http.Cookie{session, binding})
	if rec.Code != http.StatusForbidden || errorCode(t, rec) != "UNVERIFIED_EMAIL" {
		t.Fatalf("unverified complete status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestAccountLinkRejectsProviderEmailMismatch(t *testing.T) {
	f := newFlow(t, accountlink.Options{})
	f.provider.email = "other@example.com"
	session := f.signUp(t, "ada@example.com")
	state, binding := f.initiate(t, session)

	rec := f.complete(t, state, []*http.Cookie{session, binding})
	if rec.Code != http.StatusConflict || errorCode(t, rec) != "ACCOUNT_LINK_MISMATCH" {
		t.Fatalf("mismatch complete status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if _, err := f.store.FindAccount(context.Background(), "google", "google-sub"); err != canopy.ErrNotFound {
		t.Fatalf("account err = %v, want ErrNotFound", err)
	}
}

func TestAccountLinkInitiationRequiresRecentAuthentication(t *testing.T) {
	f := newFlow(t, accountlink.Options{})
	session := f.signUp(t, "ada@example.com")
	f.backdateSession(t, session)

	rec := post(t, f.handler, "/link-social", map[string]string{"provider": "google"}, []*http.Cookie{session})
	if rec.Code != http.StatusForbidden || errorCode(t, rec) != "RECENT_AUTHENTICATION_REQUIRED" {
		t.Fatalf("stale initiate status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestAccountLinkCompletionRequiresRecentAuthentication(t *testing.T) {
	f := newFlow(t, accountlink.Options{})
	session := f.signUp(t, "ada@example.com")
	state, binding := f.initiate(t, session)
	f.backdateSession(t, session)

	rec := f.complete(t, state, []*http.Cookie{session, binding})
	if rec.Code != http.StatusForbidden || errorCode(t, rec) != "RECENT_AUTHENTICATION_REQUIRED" {
		t.Fatalf("stale complete status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestAccountLinkRejectsImpersonatedSession(t *testing.T) {
	f := newFlow(t, accountlink.Options{})
	session := f.signUp(t, "ada@example.com")
	state, binding := f.initiate(t, session)
	user, err := f.store.FindUserByEmail(context.Background(), "ada@example.com")
	if err != nil {
		t.Fatal(err)
	}
	_, impersonatedToken, err := f.auth.API().IssueSession(context.Background(), *user, canopy.SessionOptions{
		ImpersonatedBy: "usr_admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	impersonated := &http.Cookie{Name: "canopy.session_token", Value: impersonatedToken}

	initiate := post(t, f.handler, "/link-social", map[string]string{"provider": "google"}, []*http.Cookie{impersonated})
	if initiate.Code != http.StatusForbidden || errorCode(t, initiate) != "FORBIDDEN" {
		t.Fatalf("impersonated initiate status = %d, body = %s", initiate.Code, initiate.Body.String())
	}
	complete := f.complete(t, state, []*http.Cookie{impersonated, binding})
	if complete.Code != http.StatusForbidden || errorCode(t, complete) != "FORBIDDEN" {
		t.Fatalf("impersonated complete status = %d, body = %s", complete.Code, complete.Body.String())
	}
}

func TestAccountLinkRejectsAccountLinkedToAnotherUser(t *testing.T) {
	f := newFlow(t, accountlink.Options{})
	session := f.signUp(t, "ada@example.com")
	now := time.Now().UTC()
	other := &canopy.User{ID: "usr_other", Name: "Bob", Email: "bob@example.com", CreatedAt: now, UpdatedAt: now}
	if err := f.store.CreateUser(context.Background(), other); err != nil {
		t.Fatal(err)
	}
	if err := f.store.CreateAccount(context.Background(), &canopy.Account{
		ID: "acc_other", UserID: other.ID, AccountID: "google-sub", ProviderID: "google",
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	state, binding := f.initiate(t, session)

	rec := f.complete(t, state, []*http.Cookie{session, binding})
	if rec.Code != http.StatusConflict || errorCode(t, rec) != "CONFLICT" {
		t.Fatalf("conflict complete status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestAccountLinkInitiationRejectsExistingProviderAccount(t *testing.T) {
	f := newFlow(t, accountlink.Options{})
	session := f.signUp(t, "ada@example.com")
	data, err := f.store.FindSessionByToken(context.Background(), session.Value)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := f.store.CreateAccount(context.Background(), &canopy.Account{
		ID: "acc_existing", UserID: data.User.ID, AccountID: "google-sub", ProviderID: "google",
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	rec := post(t, f.handler, "/link-social", map[string]string{"provider": "google"}, []*http.Cookie{session})
	if rec.Code != http.StatusConflict || errorCode(t, rec) != "CONFLICT" {
		t.Fatalf("existing-account initiate status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestAccountLinkAlreadyLinkedToSelfIsIdempotent(t *testing.T) {
	f := newFlow(t, accountlink.Options{})
	session := f.signUp(t, "ada@example.com")
	state, binding := f.initiate(t, session)
	// Simulate a link that lands between initiation and completion.
	data, err := f.store.FindSessionByToken(context.Background(), session.Value)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := f.store.CreateAccount(context.Background(), &canopy.Account{
		ID: "acc_self", UserID: data.User.ID, AccountID: "google-sub", ProviderID: "google",
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	rec := f.complete(t, state, []*http.Cookie{session, binding})
	if rec.Code != http.StatusOK {
		t.Fatalf("idempotent complete status = %d, body = %s", rec.Code, rec.Body.String())
	}
	stored, err := f.store.FindAccount(context.Background(), "google", "google-sub")
	if err != nil {
		t.Fatal(err)
	}
	if stored.ID != "acc_self" {
		t.Fatalf("account id = %q, want the existing row", stored.ID)
	}
	if stored.AccessToken == "" || stored.AccessToken == "link-access-token" {
		t.Fatalf("refreshed access token = %q, want an encrypted value", stored.AccessToken)
	}
	other, err := f.store.FindAccountByUserProvider(context.Background(), data.User.ID, "google")
	if err != nil {
		t.Fatal(err)
	}
	if other.ID != "acc_self" {
		t.Fatalf("duplicate account created: %#v", other)
	}
	// The state stays single-use on the refresh path.
	replay := f.complete(t, state, []*http.Cookie{session, binding})
	if replay.Code != http.StatusBadRequest || errorCode(t, replay) != "INVALID_STATE" {
		t.Fatalf("refresh replay status = %d, body = %s", replay.Code, replay.Body.String())
	}
}

func TestAccountLinkRejectsMissingOrTamperedBindingCookie(t *testing.T) {
	f := newFlow(t, accountlink.Options{})
	session := f.signUp(t, "ada@example.com")
	state, binding := f.initiate(t, session)

	missing := f.complete(t, state, []*http.Cookie{session})
	if missing.Code != http.StatusBadRequest || errorCode(t, missing) != "INVALID_STATE" {
		t.Fatalf("missing-cookie status = %d, body = %s", missing.Code, missing.Body.String())
	}
	tampered := f.complete(t, state, []*http.Cookie{session, {Name: binding.Name, Value: "tampered-value"}})
	if tampered.Code != http.StatusBadRequest || errorCode(t, tampered) != "INVALID_STATE" {
		t.Fatalf("tampered-cookie status = %d, body = %s", tampered.Code, tampered.Body.String())
	}
	if _, err := f.store.FindAccount(context.Background(), "google", "google-sub"); err != canopy.ErrNotFound {
		t.Fatalf("account err = %v, want ErrNotFound", err)
	}
}

func TestAccountLinkRejectsSignedOutSession(t *testing.T) {
	f := newFlow(t, accountlink.Options{})
	session := f.signUp(t, "ada@example.com")
	state, binding := f.initiate(t, session)
	signOut := post(t, f.handler, "/sign-out", map[string]string{}, []*http.Cookie{session})
	if signOut.Code != http.StatusOK {
		t.Fatalf("sign-out status = %d, body = %s", signOut.Code, signOut.Body.String())
	}

	rec := f.complete(t, state, []*http.Cookie{session, binding})
	if rec.Code != http.StatusUnauthorized || errorCode(t, rec) != "UNAUTHORIZED" {
		t.Fatalf("signed-out complete status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestAccountLinkTamperedStateSignatureIsRejected(t *testing.T) {
	f := newFlow(t, accountlink.Options{})
	session := f.signUp(t, "ada@example.com")
	state, binding := f.initiate(t, session)
	tampered := state[:len(state)-2] + "xx"

	rec := f.complete(t, tampered, []*http.Cookie{session, binding})
	if rec.Code != http.StatusBadRequest || errorCode(t, rec) != "INVALID_STATE" {
		t.Fatalf("tampered-state status = %d, body = %s", rec.Code, rec.Body.String())
	}
}
