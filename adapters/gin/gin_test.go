package canopygin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
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
	gin.SetMode(gin.TestMode)
	auth := newAuth(t, "/auth")
	router := gin.New()
	Mount(router, auth)

	protected := router.Group("/", RequireSession(auth))
	protected.GET("/me", func(c *gin.Context) {
		data, ok := Session(c)
		if !ok {
			t.Error("no session in context")
			c.Status(http.StatusInternalServerError)
			return
		}
		c.String(http.StatusOK, data.User.Email)
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

func TestOptionalSessionAllowsAnonymous(t *testing.T) {
	gin.SetMode(gin.TestMode)
	auth := newAuth(t, "/auth")
	router := gin.New()
	Mount(router, auth)
	router.GET("/page", OptionalSession(auth), func(c *gin.Context) {
		if _, ok := Session(c); ok {
			c.String(http.StatusOK, "signed-in")
			return
		}
		c.String(http.StatusOK, "anonymous")
	})

	req := httptest.NewRequest(http.MethodGet, "/page", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "anonymous" {
		t.Fatalf("anonymous /page = %d %q", rec.Code, rec.Body.String())
	}
}
