package canopy

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	authoauth "github.com/ssnxd/canopy/oauth"
	"github.com/ssnxd/canopy/password"
)

// countingHasher wraps a hasher and counts Verify calls.
type countingHasher struct {
	mu       sync.Mutex
	inner    password.Hasher
	verifies int
}

func newCountingHasher() *countingHasher {
	return &countingHasher{inner: &password.Argon2idHasher{Memory: 1024, Iterations: 1, Parallelism: 1, SaltLength: 8, KeyLength: 16}}
}

func (h *countingHasher) Hash(ctx context.Context, pw string) (string, error) {
	return h.inner.Hash(ctx, pw)
}

func (h *countingHasher) Verify(ctx context.Context, pw, encoded string) (bool, bool, error) {
	h.mu.Lock()
	h.verifies++
	h.mu.Unlock()
	return h.inner.Verify(ctx, pw, encoded)
}

func (h *countingHasher) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.verifies
}

// A sign-in for an unknown user must still run a password verify.
// A missing verify would leak account existence through response time.
func TestSignInVerifiesEvenForUnknownUser(t *testing.T) {
	hasher := newCountingHasher()
	auth, err := New(Config{
		Store:          newMemoryStore(),
		Secret:         "dev-secret-with-enough-test-entropy",
		PasswordHasher: hasher,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, _, err := auth.API().SignUpEmail(ctx, SignUpEmailInput{Name: "Ada", Email: "real@example.com", Password: "correct-password"}); err != nil {
		t.Fatal(err)
	}
	before := hasher.count()
	_, _, err = auth.API().SignInEmail(ctx, SignInEmailInput{Email: "ghost@example.com", Password: "any-password"})
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("err = %v, want ErrInvalidCredentials", err)
	}
	if hasher.count() == before {
		t.Fatal("no password verify ran for an unknown user; timing side channel remains")
	}
}

// An untrusted callback host must not receive the one-time reset token.
func TestPasswordResetDropsUntrustedCallbackURL(t *testing.T) {
	sender := &testEmailSender{}
	auth, err := New(Config{
		Store:          newMemoryStore(),
		Secret:         "dev-secret-with-enough-test-entropy",
		EmailSender:    sender,
		TrustedOrigins: []string{"https://app.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, _, err := auth.API().SignUpEmail(ctx, SignUpEmailInput{Name: "Ada", Email: "victim@example.com", Password: "correct-password"}); err != nil {
		t.Fatal(err)
	}
	if err := auth.API().RequestPasswordReset(ctx, RequestPasswordResetInput{
		Email:       "victim@example.com",
		CallbackURL: "https://evil.attacker.example/collect",
	}); err != nil {
		t.Fatal(err)
	}
	if len(sender.resetMessages) != 1 {
		t.Fatalf("reset messages = %d, want 1", len(sender.resetMessages))
	}
	msg := sender.resetMessages[0]
	if msg.URL != "" {
		t.Fatalf("untrusted callback URL was kept: %q", msg.URL)
	}
	if msg.CallbackURL != "" {
		t.Fatalf("untrusted callback URL was kept: %q", msg.CallbackURL)
	}
	if msg.Token == "" {
		t.Fatal("token must still be available for the app to build its own link")
	}
}

// A trusted callback host keeps the full link with the token.
func TestPasswordResetKeepsTrustedCallbackURL(t *testing.T) {
	sender := &testEmailSender{}
	auth, err := New(Config{
		Store:          newMemoryStore(),
		Secret:         "dev-secret-with-enough-test-entropy",
		EmailSender:    sender,
		TrustedOrigins: []string{"https://app.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, _, err := auth.API().SignUpEmail(ctx, SignUpEmailInput{Name: "Ada", Email: "ada@example.com", Password: "correct-password"}); err != nil {
		t.Fatal(err)
	}
	if err := auth.API().RequestPasswordReset(ctx, RequestPasswordResetInput{
		Email:       "ada@example.com",
		CallbackURL: "https://app.example.com/reset",
	}); err != nil {
		t.Fatal(err)
	}
	msg := sender.resetMessages[0]
	if !strings.HasPrefix(msg.URL, "https://app.example.com/reset?token=") {
		t.Fatalf("trusted callback URL was not kept: %q", msg.URL)
	}
}

func TestCheckOriginSecFetch(t *testing.T) {
	trusted := Config{TrustedOrigins: []string{"https://app.example.com"}}
	empty := Config{}
	newReq := func(method string, headers map[string]string) *http.Request {
		r := httptest.NewRequest(method, "/sign-in/email", nil)
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		return r
	}
	cases := []struct {
		name    string
		cfg     Config
		method  string
		headers map[string]string
		want    bool
	}{
		{"GET is always allowed", trusted, http.MethodGet, nil, true},
		{"no origin no sec-fetch allows api client", trusted, http.MethodPost, nil, true},
		{"trusted origin allowed", trusted, http.MethodPost, map[string]string{"Origin": "https://app.example.com"}, true},
		{"untrusted origin rejected", trusted, http.MethodPost, map[string]string{"Origin": "https://evil.example"}, false},
		{"cross-site rejected without origin", trusted, http.MethodPost, map[string]string{"Sec-Fetch-Site": "cross-site"}, false},
		{"cross-site untrusted origin rejected", trusted, http.MethodPost, map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example"}, false},
		{"cross-site trusted origin allowed", trusted, http.MethodPost, map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://app.example.com"}, true},
		{"same-origin allowed with empty trusted origins", empty, http.MethodPost, map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": "https://self.example"}, true},
		{"disabled check allows all", Config{DisableOriginCheck: true}, http.MethodPost, map[string]string{"Origin": "https://evil.example"}, true},
	}
	for _, c := range cases {
		if got := c.cfg.CheckOrigin(newReq(c.method, c.headers)); got != c.want {
			t.Errorf("%s: CheckOrigin = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestResolveCallbackURL(t *testing.T) {
	cfg := Config{TrustedOrigins: []string{"https://app.example.com"}}
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"   ", ""},
		{"https://app.example.com/reset", "https://app.example.com/reset"},
		{"https://evil.example/reset", ""},
		{"//evil.example/reset", ""},
		{"http://app.example.com/reset", ""},
		{"/reset-password", "/reset-password"},
		{"javascript:alert(1)", ""},
		{"https://app.example.com.evil.example/x", ""},
	}
	for _, c := range cases {
		if got := cfg.resolveCallbackURL(c.in); got != c.want {
			t.Errorf("resolveCallbackURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// An oversize request body must be rejected, not read into memory.
func TestRequestBodyIsSizeLimited(t *testing.T) {
	auth, err := New(Config{Store: newMemoryStore(), Secret: "dev-secret-with-enough-test-entropy"})
	if err != nil {
		t.Fatal(err)
	}
	handler := auth.Handler()

	filler := strings.Repeat("a", (1<<20)+1024) // just over 1 MiB
	body := []byte(`{"name":"` + filler + `","email":"a@b.com","password":"correct-password"}`)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/sign-up/email", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("oversize body status = %d, want 400", rec.Code)
	}
}

// The OAuth redirect target must not be an untrusted host (open-redirect guard).
func TestOAuthDropsUntrustedRedirect(t *testing.T) {
	provider := &fakeOAuthProvider{id: "google", email: "oauth@example.com", accountID: "google-sub"}
	auth, err := New(Config{
		Store:          newMemoryStore(),
		Secret:         "dev-secret-with-enough-test-entropy",
		Providers:      []authoauth.Provider{provider},
		TrustedOrigins: []string{"https://app.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	start, binding, err := auth.API().SignInSocial(ctx, SignInSocialInput{
		Provider:    "google",
		CallbackURL: "https://evil.attacker.example/steal",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _, callbackURL, _, err := auth.API().OAuthCallback(ctx, OAuthCallbackInput{
		Provider:     "google",
		Code:         "auth-code",
		State:        stateFromURL(t, start.URL),
		StateBinding: binding,
	})
	if err != nil {
		t.Fatal(err)
	}
	if callbackURL != "" {
		t.Fatalf("untrusted OAuth redirect was kept: %q", callbackURL)
	}
}
