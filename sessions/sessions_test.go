package sessions

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCookieAttributes(t *testing.T) {
	cfg := Config{Expiry: time.Hour}
	cfg.SetDefaults(true)
	rec := httptest.NewRecorder()
	cfg.SetCookie(rec, "token", nil)
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %d", len(cookies))
	}
	c := cookies[0]
	if c.Name != "canopy.session_token" || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.MaxAge == 0 {
		t.Fatalf("unexpected cookie: %#v", c)
	}
	remember := false
	rec = httptest.NewRecorder()
	cfg.SetCookie(rec, "token", &remember)
	c = rec.Result().Cookies()[0]
	if c.MaxAge != 0 {
		t.Fatalf("browser-session cookie MaxAge = %d, want 0", c.MaxAge)
	}
}
