package canopy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestConfigRequiresProductionSecret(t *testing.T) {
	_, err := New(Config{
		Store:       newMemoryStore(),
		Secret:      "short",
		Environment: Production,
	})
	if err == nil {
		t.Fatal("expected production secret validation error")
	}
}

func TestConfigDefaultsToProductionSafety(t *testing.T) {
	if _, err := New(Config{Store: newMemoryStore(), Secret: "short"}); err == nil {
		t.Fatal("default environment accepted a short secret")
	}
	auth, err := New(Config{
		Store:  newMemoryStore(),
		Secret: "production-secret-with-enough-entropy",
	})
	if err != nil {
		t.Fatal(err)
	}
	if auth.cfg.Environment != Production || !auth.cfg.Session.Secure {
		t.Fatalf("default config = %#v, want production with secure cookies", auth.cfg)
	}
}

func TestConfigRejectsUnknownEnvironmentAndInvalidLifetimes(t *testing.T) {
	_, err := New(Config{
		Store:       newMemoryStore(),
		Secret:      "production-secret-with-enough-entropy",
		Environment: Environment("prod"),
	})
	if err == nil {
		t.Fatal("unknown environment was accepted")
	}
	_, err = New(Config{
		Store:         newMemoryStore(),
		Secret:        "development-secret",
		Environment:   Development,
		OAuthStateTTL: -time.Minute,
	})
	if err == nil {
		t.Fatal("negative oauth state lifetime was accepted")
	}
}

func TestConfigRequiresEmailSenderForRequiredVerification(t *testing.T) {
	_, err := New(Config{
		Store:                    newMemoryStore(),
		Secret:                   "production-secret-with-enough-entropy",
		RequireEmailVerification: true,
	})
	if err == nil {
		t.Fatal("required email verification accepted the no-op sender")
	}
}

func TestHTTPErrorEnvelopeUsesStableTypedCodes(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{name: "invalid input", err: ErrInvalidInput, status: http.StatusBadRequest, code: "INVALID_INPUT"},
		{name: "invalid state", err: ErrInvalidState, status: http.StatusBadRequest, code: "INVALID_STATE"},
		{name: "storage failure", err: ErrStorageFailure, status: http.StatusInternalServerError, code: "STORAGE_FAILURE"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			writeError(rec, test.err)
			if rec.Code != test.status {
				t.Fatalf("status = %d, want %d", rec.Code, test.status)
			}
			var body struct {
				Error struct {
					Code string `json:"code"`
				} `json:"error"`
			}
			if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body.Error.Code != test.code {
				t.Fatalf("code = %q, want %q", body.Error.Code, test.code)
			}
		})
	}
}

func TestEmailSignInCreatesFreshTokensAndAuditsSuccess(t *testing.T) {
	store := newMemoryStore()
	audit := &testAuditLogger{}
	auth, err := New(Config{
		Store:       store,
		Secret:      "dev-secret-with-enough-test-entropy",
		AuditLogger: audit,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	signup, firstToken, err := auth.API().SignUpEmail(ctx, SignUpEmailInput{
		Name:     "Ada",
		Email:    " ADA@Example.COM ",
		Password: "correct-password",
	})
	if err != nil {
		t.Fatal(err)
	}
	if signup.User.Email != "ada@example.com" {
		t.Fatalf("email was not conservatively normalized: %q", signup.User.Email)
	}
	if signup.User.EmailVerified {
		t.Fatal("email was marked verified without mailbox proof")
	}
	signin, err := auth.API().SignInEmail(ctx, SignInEmailInput{
		Email:    "ada@example.com",
		Password: "correct-password",
	})
	if err != nil {
		t.Fatal(err)
	}
	if firstToken == signin.Token {
		t.Fatal("sign-in reused an existing session token")
	}
	if len(audit.events) == 0 || audit.events[len(audit.events)-1].Type != "sign_in.email.succeeded" {
		t.Fatalf("missing success audit event: %#v", audit.events)
	}
}

func TestHTTPEmailFlowAndSessionContext(t *testing.T) {
	auth, err := New(Config{
		Store:  newMemoryStore(),
		Secret: "dev-secret-with-enough-test-entropy",
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := auth.Handler()
	body, _ := json.Marshal(map[string]string{
		"name":     "Ada",
		"email":    "ada@example.com",
		"password": "correct-password",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/sign-up/email", bytes.NewReader(body))
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "canopy.session_token" || !cookies[0].HttpOnly {
		t.Fatalf("unexpected cookies: %#v", cookies)
	}
	var sawSession bool
	next := auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, sawSession = SessionFromContext(r.Context())
	}))
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookies[0])
	next.ServeHTTP(httptest.NewRecorder(), req)
	if !sawSession {
		t.Fatal("middleware did not populate session context")
	}
}

func TestMiddlewareAcceptsBearerToken(t *testing.T) {
	auth, err := New(Config{
		Store:  newMemoryStore(),
		Secret: "dev-secret-with-enough-test-entropy",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, token, err := auth.API().SignUpEmail(context.Background(), SignUpEmailInput{
		Name:     "Ada",
		Email:    "ada@example.com",
		Password: "correct-password",
	})
	if err != nil {
		t.Fatal(err)
	}
	var sawSession bool
	next := auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, sawSession = SessionFromContext(r.Context())
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	next.ServeHTTP(httptest.NewRecorder(), req)
	if !sawSession {
		t.Fatal("middleware did not accept bearer token")
	}
}

func TestSignUpUsesAtomicUserAccountProvisioningWhenAvailable(t *testing.T) {
	wantErr := errors.New("provision failed")
	store := &failingProvisionStore{
		memoryStore: newMemoryStore(),
		err:         wantErr,
	}
	auth, err := New(Config{
		Store:  store,
		Secret: "dev-secret-with-enough-test-entropy",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = auth.API().SignUpEmail(context.Background(), SignUpEmailInput{
		Name:     "Ada",
		Email:    "ada@example.com",
		Password: "correct-password",
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want %v", err, wantErr)
	}
	if !store.called {
		t.Fatal("CreateUserAccount was not used")
	}
	if _, err := store.FindUserByEmail(context.Background(), "ada@example.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("FindUserByEmail err = %v, want ErrNotFound", err)
	}
}

type failingProvisionStore struct {
	*memoryStore
	err    error
	called bool
}

func (s *failingProvisionStore) CreateUserAccount(ctx context.Context, user *User, account *Account) error {
	s.called = true
	return s.err
}
