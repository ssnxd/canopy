package canopy

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

// seamModule exercises every module capability: Init, RouteModule, and
// SignInInterceptor.
type seamModule struct {
	inited      bool
	challenge   bool
	sawStoreOK  bool
	interceptCt int
}

func (m *seamModule) ID() string { return "seam" }

func (m *seamModule) Init(core Core) error {
	m.inited = true
	// A module reads its optional store capability here.
	_, m.sawStoreOK = core.Store().(userAccountStore)
	return nil
}

func (m *seamModule) Routes() []Route {
	return []Route{{
		Method:         http.MethodGet,
		Pattern:        "/seam/whoami",
		RequireSession: true,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			data, ok := SessionFromContext(r.Context())
			if !ok {
				writeError(w, ErrUnauthorized)
				return
			}
			writeJSON(w, http.StatusOK, data.User)
		}),
	}}
}

func (m *seamModule) AfterPrimaryAuth(ctx context.Context, user User) (*StepUpChallenge, error) {
	m.interceptCt++
	if m.challenge {
		return &StepUpChallenge{Token: "challenge-token", Methods: []string{"totp"}}, nil
	}
	return nil, nil
}

func newSeamAuth(t *testing.T, m *seamModule) *Auth {
	t.Helper()
	auth, err := New(Config{
		Store:   newMemoryStore(),
		Secret:  "dev-secret-with-enough-test-entropy",
		Modules: []Module{m},
	})
	if err != nil {
		t.Fatal(err)
	}
	return auth
}

func TestModuleInitRunsAndReadsStoreCapability(t *testing.T) {
	m := &seamModule{}
	newSeamAuth(t, m)
	if !m.inited {
		t.Fatal("module Init was not called")
	}
	if !m.sawStoreOK {
		t.Fatal("module could not read the store capability")
	}
}

func TestModuleCoreDoesNotExposeRootConfiguration(t *testing.T) {
	auth, err := New(Config{
		Store:           newMemoryStore(),
		Secret:          "current-production-secret-with-enough-entropy",
		PreviousSecrets: []string{"previous-production-secret-with-enough-entropy"},
	})
	if err != nil {
		t.Fatal(err)
	}
	runtimeType := reflect.TypeOf(auth.API().Config())
	for _, field := range []string{"Secret", "PreviousSecrets", "Store", "Hooks", "Providers"} {
		if _, ok := runtimeType.FieldByName(field); ok {
			t.Fatalf("runtime config exposes sensitive field %q", field)
		}
	}
	first, err := (moduleCore{Service: auth.API(), moduleID: "first"}).ModuleKeys("state")
	if err != nil {
		t.Fatal(err)
	}
	second, err := (moduleCore{Service: auth.API(), moduleID: "second"}).ModuleKeys("state")
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Current) != 32 || len(first.Previous) != 1 {
		t.Fatalf("first keyring sizes = (%d, %d), want (32, 1)", len(first.Current), len(first.Previous))
	}
	if bytes.Equal(first.Current, second.Current) {
		t.Fatal("different modules received the same derived key")
	}
	if bytes.Equal(first.Current, []byte("current-production-secret-with-enough-entropy")) {
		t.Fatal("module key exposes the root secret")
	}
}

func TestSignInInterceptorPausesWithChallenge(t *testing.T) {
	m := &seamModule{}
	auth := newSeamAuth(t, m)
	ctx := context.Background()
	if _, _, err := auth.API().SignUpEmail(ctx, SignUpEmailInput{Name: "Ada", Email: "ada@example.com", Password: "correct-password"}); err != nil {
		t.Fatal(err)
	}

	// No challenge: full session.
	res, err := auth.API().SignInEmail(ctx, SignInEmailInput{Email: "ada@example.com", Password: "correct-password"})
	if err != nil {
		t.Fatal(err)
	}
	if res.TwoFactorRequired() || res.Session == nil {
		t.Fatalf("expected a full session, got %#v", res)
	}

	// Challenge: no session, a step-up challenge instead.
	m.challenge = true
	res, err = auth.API().SignInEmail(ctx, SignInEmailInput{Email: "ada@example.com", Password: "correct-password"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.TwoFactorRequired() || res.Session != nil || res.Token != "" {
		t.Fatalf("expected a challenge, got %#v", res)
	}
	if res.Challenge.Token != "challenge-token" {
		t.Fatalf("challenge = %#v", res.Challenge)
	}
}

func TestModuleRouteMountingAndSessionGuard(t *testing.T) {
	m := &seamModule{}
	auth := newSeamAuth(t, m)
	handler := auth.Handler()
	ctx := context.Background()
	_, token, err := auth.API().SignUpEmail(ctx, SignUpEmailInput{Name: "Ada", Email: "ada@example.com", Password: "correct-password"})
	if err != nil {
		t.Fatal(err)
	}

	// Without a session: unauthorized.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/seam/whoami", nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no-session status = %d, want 401", rec.Code)
	}

	// With a session: the module handler runs and sees the user.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/seam/whoami", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("session status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestDuplicateModuleIsRejected(t *testing.T) {
	_, err := New(Config{
		Store:   newMemoryStore(),
		Secret:  "dev-secret-with-enough-test-entropy",
		Modules: []Module{&seamModule{}, &seamModule{}},
	})
	if err == nil {
		t.Fatal("expected duplicate module id to be rejected")
	}
}
