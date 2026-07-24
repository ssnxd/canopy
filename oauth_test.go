package canopy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	authoauth "github.com/ssnxd/canopy/oauth"
	"golang.org/x/oauth2"
)

type updateFailingStore struct {
	*memoryStore
	err error
}

func (s *updateFailingStore) UpdateAccount(ctx context.Context, account *Account) error {
	return s.err
}

type fakeOAuthProvider struct {
	id              string
	email           string
	accountID       string
	lastVerifier    string
	lastNonce       string
	profileProvider string
	emailUnverified bool
	refreshErr      error
	refreshedToken  *oauth2.Token
}

func (p *fakeOAuthProvider) ID() string { return p.id }

func (p *fakeOAuthProvider) Config(ctx context.Context) (*oauth2.Config, error) {
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

func (p *fakeOAuthProvider) AuthCodeOptions(opts authoauth.StartOptions) []oauth2.AuthCodeOption {
	p.lastNonce = opts.Nonce
	return []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(opts.PKCEVerifier)}
}

func (p *fakeOAuthProvider) Exchange(ctx context.Context, code string, verifier string) (*oauth2.Token, error) {
	p.lastVerifier = verifier
	return &oauth2.Token{
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		Expiry:       time.Now().Add(time.Hour),
	}, nil
}

func (p *fakeOAuthProvider) Refresh(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	if p.refreshErr != nil {
		return nil, p.refreshErr
	}
	if p.refreshedToken != nil {
		return p.refreshedToken, nil
	}
	return &oauth2.Token{
		AccessToken:  "new-access-token",
		RefreshToken: refreshToken,
		Expiry:       time.Now().Add(2 * time.Hour),
	}, nil
}

func (p *fakeOAuthProvider) Profile(ctx context.Context, token *oauth2.Token, nonce string) (*authoauth.Profile, error) {
	if nonce != p.lastNonce {
		return nil, ErrInvalidState
	}
	providerID := p.profileProvider
	if providerID == "" {
		providerID = p.id
	}
	return &authoauth.Profile{
		ProviderID:           providerID,
		AccountID:            p.accountID,
		Email:                p.email,
		EmailVerified:        !p.emailUnverified,
		Name:                 "OAuth User",
		Image:                "https://example.test/avatar.png",
		AccessToken:          token.AccessToken,
		RefreshToken:         token.RefreshToken,
		AccessTokenExpiresAt: &token.Expiry,
	}, nil
}

func TestRefreshProviderTokenUpdatesAccount(t *testing.T) {
	store := newMemoryStore()
	provider := &fakeOAuthProvider{
		id:        "google",
		email:     "oauth@example.com",
		accountID: "google-sub",
		refreshedToken: (&oauth2.Token{
			AccessToken:  "rotated-access-token",
			RefreshToken: "rotated-refresh-token",
			Expiry:       time.Now().Add(3 * time.Hour),
		}).WithExtra(map[string]any{"scope": "openid email profile calendar"}),
	}
	auth, err := New(Config{
		Store:     store,
		Secret:    "dev-secret-with-enough-test-entropy",
		Providers: []authoauth.Provider{provider},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	start, binding, err := auth.API().SignInSocial(ctx, SignInSocialInput{Provider: "google"})
	if err != nil {
		t.Fatal(err)
	}
	out, err := auth.API().OAuthCallback(ctx, OAuthCallbackInput{
		Provider:     "google",
		Code:         "auth-code",
		State:        stateFromURL(t, start.URL),
		StateBinding: binding,
	})
	if err != nil {
		t.Fatal(err)
	}
	data := out.Result.Session
	stored, err := store.FindAccountByUserProvider(ctx, data.User.ID, "google")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(stored.AccessToken, providerTokenEnvelopePrefix) ||
		!strings.HasPrefix(stored.RefreshToken, providerTokenEnvelopePrefix) {
		t.Fatalf("provider credentials were stored in plaintext: %#v", stored)
	}
	refreshed, err := auth.API().RefreshProviderToken(ctx, RefreshProviderTokenInput{
		UserID:     data.User.ID,
		ProviderID: "google",
	})
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.AccessToken != "rotated-access-token" || refreshed.RefreshToken != "rotated-refresh-token" {
		t.Fatalf("unexpected refreshed token: %#v", refreshed)
	}
	if refreshed.Scope != "openid email profile calendar" {
		t.Fatalf("scope = %q", refreshed.Scope)
	}
}

func TestRefreshProviderTokenWithoutRefreshToken(t *testing.T) {
	store := newMemoryStore()
	provider := &fakeOAuthProvider{id: "apple"}
	auth, err := New(Config{
		Store:     store,
		Secret:    "dev-secret-with-enough-test-entropy",
		Providers: []authoauth.Provider{provider},
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	user := &User{ID: "usr_1", Name: "Ada", Email: "ada@example.com", CreatedAt: now, UpdatedAt: now}
	if err := store.CreateUser(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateAccount(context.Background(), &Account{
		ID:         "acc_1",
		UserID:     user.ID,
		AccountID:  "apple-sub",
		ProviderID: "apple",
		CreatedAt:  now,
		UpdatedAt:  now,
	}); err != nil {
		t.Fatal(err)
	}
	_, err = auth.API().RefreshProviderToken(context.Background(), RefreshProviderTokenInput{
		UserID:     user.ID,
		ProviderID: "apple",
	})
	if err != ErrNoRefreshToken {
		t.Fatalf("err = %v, want ErrNoRefreshToken", err)
	}
}

func TestOAuthLoginPreservesCredentialsOmittedByProvider(t *testing.T) {
	auth, err := New(Config{
		Store:  newMemoryStore(),
		Secret: "dev-secret-with-enough-test-entropy",
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	profile := &authoauth.Profile{
		ProviderID:    "google",
		AccountID:     "google-sub",
		Email:         "oauth@example.com",
		EmailVerified: true,
		AccessToken:   "first-access-token",
		RefreshToken:  "durable-refresh-token",
		Scope:         "openid email",
		IDToken:       "first-id-token",
	}
	first, err := auth.API().signInOAuthProfile(ctx, "google", profile, nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	profile.AccessToken = "second-access-token"
	profile.RefreshToken = ""
	profile.Scope = ""
	profile.IDToken = ""
	if _, err := auth.API().signInOAuthProfile(ctx, "google", profile, nil, "", ""); err != nil {
		t.Fatal(err)
	}
	account, err := auth.API().findAccountByUserProvider(ctx, first.Session.User.ID, "google")
	if err != nil {
		t.Fatal(err)
	}
	if account.AccessToken != "second-access-token" {
		t.Fatalf("access token = %q, want updated token", account.AccessToken)
	}
	if account.RefreshToken != "durable-refresh-token" {
		t.Fatalf("refresh token = %q, want preserved token", account.RefreshToken)
	}
	if account.Scope != "openid email" || account.IDToken != "first-id-token" {
		t.Fatalf("omitted credentials were cleared: %#v", account)
	}
}

func TestOAuthLoginPropagatesAccountUpdateFailure(t *testing.T) {
	updateErr := errors.New("update failed")
	store := &updateFailingStore{memoryStore: newMemoryStore(), err: updateErr}
	auth, err := New(Config{
		Store:  store,
		Secret: "dev-secret-with-enough-test-entropy",
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	profile := &authoauth.Profile{
		ProviderID:    "google",
		AccountID:     "google-sub",
		Email:         "oauth@example.com",
		EmailVerified: true,
		AccessToken:   "first-access-token",
	}
	if _, err := auth.API().signInOAuthProfile(ctx, "google", profile, nil, "", ""); err != nil {
		t.Fatal(err)
	}
	profile.AccessToken = "second-access-token"
	if _, err := auth.API().signInOAuthProfile(ctx, "google", profile, nil, "", ""); !errors.Is(err, updateErr) {
		t.Fatalf("signInOAuthProfile() error = %v, want %v", err, updateErr)
	}
}

func TestOAuthFlowCreatesSessionAndRejectsReplay(t *testing.T) {
	provider := &fakeOAuthProvider{id: "google", email: "oauth@example.com", accountID: "google-sub"}
	auth, err := New(Config{
		Store:     newMemoryStore(),
		Secret:    "dev-secret-with-enough-test-entropy",
		Providers: []authoauth.Provider{provider},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	start, binding, err := auth.API().SignInSocial(ctx, SignInSocialInput{Provider: "google"})
	if err != nil {
		t.Fatal(err)
	}
	state := stateFromURL(t, start.URL)
	out, err := auth.API().OAuthCallback(ctx, OAuthCallbackInput{
		Provider:     "google",
		Code:         "auth-code",
		State:        state,
		StateBinding: binding,
	})
	if err != nil {
		t.Fatal(err)
	}
	data := out.Result.Session
	token := out.Result.Token
	if token == "" || data.User.Email != "oauth@example.com" {
		t.Fatalf("unexpected oauth session: token=%q data=%#v", token, data)
	}
	if provider.lastVerifier == "" {
		t.Fatal("PKCE verifier was not passed to provider exchange")
	}
	_, err = auth.API().OAuthCallback(ctx, OAuthCallbackInput{
		Provider:     "google",
		Code:         "auth-code",
		State:        state,
		StateBinding: binding,
	})
	if err == nil {
		t.Fatal("expected replayed OAuth state to be rejected")
	}
}

func TestHTTPOAuthFlowManagesStateAndSessionCookies(t *testing.T) {
	provider := &fakeOAuthProvider{id: "google", email: "oauth@example.com", accountID: "google-sub"}
	auth, err := New(Config{
		Store:     newMemoryStore(),
		Secret:    "dev-secret-with-enough-test-entropy",
		Providers: []authoauth.Provider{provider},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := auth.Handler()
	body, _ := json.Marshal(SignInSocialInput{Provider: "google"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/sign-in/social", bytes.NewReader(body))
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("start status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var start SignInSocialOutput
	if err := json.NewDecoder(rec.Body).Decode(&start); err != nil {
		t.Fatal(err)
	}
	state := stateFromURL(t, start.URL)
	var stateCookie *http.Cookie
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == "canopy.oauth_state" {
			stateCookie = cookie
		}
	}
	if stateCookie == nil || stateCookie.Value == "" || !stateCookie.HttpOnly {
		t.Fatalf("missing state cookie: %#v", rec.Result().Cookies())
	}
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/callback/google?state="+url.QueryEscape(state)+"&code=auth-code", nil)
	req.AddCookie(stateCookie)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("callback status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var sawSessionCookie, sawClearedState bool
	for _, cookie := range rec.Result().Cookies() {
		switch cookie.Name {
		case "canopy.session_token":
			sawSessionCookie = cookie.Value != "" && cookie.HttpOnly
		case "canopy.oauth_state":
			sawClearedState = cookie.MaxAge < 0
		}
	}
	if !sawSessionCookie || !sawClearedState {
		t.Fatalf("callback cookies = %#v", rec.Result().Cookies())
	}
}

func TestOAuthRejectsSameEmailAccountLinking(t *testing.T) {
	provider := &fakeOAuthProvider{id: "google", email: "ada@example.com", accountID: "google-sub"}
	auth, err := New(Config{
		Store:     newMemoryStore(),
		Secret:    "dev-secret-with-enough-test-entropy",
		Providers: []authoauth.Provider{provider},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, _, err := auth.API().SignUpEmail(ctx, SignUpEmailInput{
		Name:     "Ada",
		Email:    "ada@example.com",
		Password: "correct-password",
	}); err != nil {
		t.Fatal(err)
	}
	start, binding, err := auth.API().SignInSocial(ctx, SignInSocialInput{Provider: "google"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = auth.API().OAuthCallback(ctx, OAuthCallbackInput{
		Provider:     "google",
		Code:         "auth-code",
		State:        stateFromURL(t, start.URL),
		StateBinding: binding,
	})
	if err != ErrAccountLinking {
		t.Fatalf("err = %v, want ErrAccountLinking", err)
	}
}

func TestOAuthRejectsUnverifiedProviderEmailForNewUser(t *testing.T) {
	provider := &fakeOAuthProvider{
		id:              "google",
		email:           "unverified@example.com",
		accountID:       "google-unverified-sub",
		emailUnverified: true,
	}
	auth, err := New(Config{
		Store:     newMemoryStore(),
		Secret:    "dev-secret-with-enough-test-entropy",
		Providers: []authoauth.Provider{provider},
	})
	if err != nil {
		t.Fatal(err)
	}
	start, binding, err := auth.API().SignInSocial(context.Background(), SignInSocialInput{Provider: "google"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = auth.API().OAuthCallback(context.Background(), OAuthCallbackInput{
		Provider:     "google",
		Code:         "auth-code",
		State:        stateFromURL(t, start.URL),
		StateBinding: binding,
	})
	if err != ErrProviderFailure {
		t.Fatalf("err = %v, want ErrProviderFailure", err)
	}
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
