package canopy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
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
