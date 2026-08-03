package canopychi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/ssnxd/canopy"
	"github.com/ssnxd/canopy/store/memory"
)

func newAuth(t *testing.T, basePath string) *canopy.Auth {
	t.Helper()
	auth, err := canopy.New(canopy.Config{
		Store:    memory.New(),
		Secret:   "adapter-test-secret-with-enough-entropy",
		BasePath: basePath,
	})
	if err != nil {
		t.Fatal(err)
	}
	return auth
}

func signUp(t *testing.T, h http.Handler, path string) string {
	t.Helper()
	body := `{"name":"Ada","email":"ada@example.com","password":"correct-horse-battery"}`
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("sign-up status = %d, body = %s", rec.Code, rec.Body.String())
	}
	cookie := rec.Header().Get("Set-Cookie")
	if cookie == "" {
		t.Fatal("sign-up did not set a session cookie")
	}
	return cookie
}

func TestMountAndRequireSession(t *testing.T) {
	auth := newAuth(t, "/auth")
	router := chi.NewRouter()
	Mount(router, auth)

	router.Group(func(r chi.Router) {
		r.Use(RequireSession(auth))
		r.Get("/me", func(w http.ResponseWriter, r *http.Request) {
			data, ok := canopy.SessionFromContext(r.Context())
			if !ok {
				t.Error("no session in context")
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.Write([]byte(data.User.Email))
		})
	})

	cookie := signUp(t, router, "/auth/sign-up/email")

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /me status = %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Cookie", cookie)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("authenticated /me status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != "ada@example.com" {
		t.Fatalf("unexpected /me body: %s", rec.Body.String())
	}
}

func TestMountAtRoot(t *testing.T) {
	auth := newAuth(t, "/")
	router := chi.NewRouter()
	Mount(router, auth)
	signUp(t, router, "/sign-up/email")
}

func TestOptionalSessionAllowsAnonymous(t *testing.T) {
	auth := newAuth(t, "/auth")
	router := chi.NewRouter()
	Mount(router, auth)
	router.Group(func(r chi.Router) {
		r.Use(OptionalSession(auth))
		r.Get("/page", func(w http.ResponseWriter, r *http.Request) {
			if _, ok := canopy.SessionFromContext(r.Context()); ok {
				w.Write([]byte("signed-in"))
				return
			}
			w.Write([]byte("anonymous"))
		})
	})

	req := httptest.NewRequest(http.MethodGet, "/page", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "anonymous" {
		t.Fatalf("anonymous /page = %d %q", rec.Code, rec.Body.String())
	}
}
