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

func TestEmailSignInCreatesFreshTokensAndReportsRateLimit(t *testing.T) {
	store := newMemoryStore()
	limiter := &testRateLimiter{}
	audit := &testAuditLogger{}
	auth, err := New(Config{
		Store:       store,
		Secret:      "dev-secret-with-enough-test-entropy",
		RateLimiter: limiter,
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
	_, secondToken, err := auth.API().SignInEmail(ctx, SignInEmailInput{
		Email:    "ada@example.com",
		Password: "correct-password",
	})
	if err != nil {
		t.Fatal(err)
	}
	if firstToken == secondToken {
		t.Fatal("sign-in reused an existing session token")
	}
	if len(limiter.reports) != 1 || !limiter.reports[0] {
		t.Fatalf("rate limiter reports = %#v, want one success", limiter.reports)
	}
	if len(audit.events) == 0 || audit.events[len(audit.events)-1].Type != "sign_in.email.succeeded" {
		t.Fatalf("missing success audit event: %#v", audit.events)
	}
}

func TestSignInRateLimited(t *testing.T) {
	auth, err := New(Config{
		Store:       newMemoryStore(),
		Secret:      "dev-secret-with-enough-test-entropy",
		RateLimiter: &testRateLimiter{allowErr: ErrRateLimited},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = auth.API().SignInEmail(context.Background(), SignInEmailInput{
		Email:    "ada@example.com",
		Password: "correct-password",
	})
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("err = %v, want ErrRateLimited", err)
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
