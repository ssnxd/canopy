package canopyecho

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
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
	e := echo.New()
	Mount(e, auth)

	e.GET("/me", func(c echo.Context) error {
		data, ok := Session(c)
		if !ok {
			t.Error("no session in context")
			return c.NoContent(http.StatusInternalServerError)
		}
		return c.String(http.StatusOK, data.User.Email)
	}, RequireSession(auth))

	cookie := signUp(t, e, "/auth/sign-up/email")

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /me status = %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Cookie", cookie)
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("authenticated /me status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != "ada@example.com" {
		t.Fatalf("unexpected /me body: %s", rec.Body.String())
	}
}

func TestOptionalSessionAllowsAnonymous(t *testing.T) {
	auth := newAuth(t, "/auth")
	e := echo.New()
	Mount(e, auth)
	e.GET("/page", func(c echo.Context) error {
		if _, ok := Session(c); ok {
			return c.String(http.StatusOK, "signed-in")
		}
		return c.String(http.StatusOK, "anonymous")
	}, OptionalSession(auth))

	req := httptest.NewRequest(http.MethodGet, "/page", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "anonymous" {
		t.Fatalf("anonymous /page = %d %q", rec.Code, rec.Body.String())
	}
}
