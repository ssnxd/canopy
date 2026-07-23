package admin_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ssnxd/canopy"
	"github.com/ssnxd/canopy/admin"
	"github.com/ssnxd/canopy/store/memory"
)

type fixture struct {
	store   *memory.Store
	auth    *canopy.Auth
	handler http.Handler
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	store := memory.New()
	auth, err := canopy.New(canopy.Config{
		Store:   store,
		Secret:  "dev-secret-with-enough-test-entropy",
		Modules: []canopy.Module{admin.New(admin.Options{})},
	})
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{store: store, auth: auth, handler: auth.Handler()}
}

func (f *fixture) do(t *testing.T, method, path string, body any, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(encoded)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

func (f *fixture) signUp(t *testing.T, name, email string) *http.Cookie {
	t.Helper()
	rec := f.do(t, http.MethodPost, "/sign-up/email", map[string]string{
		"name": name, "email": email, "password": "correct-password",
	}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("signup status = %d, body = %s", rec.Code, rec.Body.String())
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "canopy.session_token" {
			return c
		}
	}
	t.Fatal("no session cookie")
	return nil
}

func (f *fixture) promoteToAdmin(t *testing.T, email string) {
	t.Helper()
	ctx := context.Background()
	user, err := f.store.FindUserByEmail(ctx, email)
	if err != nil {
		t.Fatal(err)
	}
	user.Role = "admin"
	if err := f.store.UpdateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) userID(t *testing.T, email string) string {
	t.Helper()
	user, err := f.store.FindUserByEmail(context.Background(), email)
	if err != nil {
		t.Fatal(err)
	}
	return user.ID
}

func TestAdminRequiresAdminRole(t *testing.T) {
	f := newFixture(t)
	adminCookie := f.signUp(t, "Root", "root@example.com")
	memberCookie := f.signUp(t, "Grace", "grace@example.com")

	// Not an admin yet.
	before := f.do(t, http.MethodGet, "/admin/users", nil, adminCookie)
	if before.Code != http.StatusForbidden {
		t.Fatalf("non-admin status = %d, want 403", before.Code)
	}

	f.promoteToAdmin(t, "root@example.com")
	after := f.do(t, http.MethodGet, "/admin/users", nil, adminCookie)
	if after.Code != http.StatusOK {
		t.Fatalf("admin status = %d, body = %s", after.Code, after.Body.String())
	}
	var body struct {
		Users []canopy.User `json:"users"`
		Total int           `json:"total"`
	}
	if err := json.NewDecoder(after.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Total < 2 {
		t.Fatalf("total = %d, want >= 2", body.Total)
	}

	// A regular member is still forbidden.
	forbidden := f.do(t, http.MethodGet, "/admin/users", nil, memberCookie)
	if forbidden.Code != http.StatusForbidden {
		t.Fatalf("member status = %d, want 403", forbidden.Code)
	}
}

func TestAdminBanAndUnban(t *testing.T) {
	f := newFixture(t)
	adminCookie := f.signUp(t, "Root", "root@example.com")
	f.promoteToAdmin(t, "root@example.com")
	targetCookie := f.signUp(t, "Grace", "grace@example.com")
	targetID := f.userID(t, "grace@example.com")

	ban := f.do(t, http.MethodPost, "/admin/ban-user", map[string]any{"userId": targetID, "reason": "spam"}, adminCookie)
	if ban.Code != http.StatusOK {
		t.Fatalf("ban status = %d, body = %s", ban.Code, ban.Body.String())
	}

	// The existing session no longer authenticates.
	session := f.do(t, http.MethodGet, "/get-session", nil, targetCookie)
	if strings.TrimSpace(session.Body.String()) != "null" {
		t.Fatalf("banned get-session body = %q, want null", session.Body.String())
	}

	// Sign-in is blocked with a banned error.
	blocked := f.do(t, http.MethodPost, "/sign-in/email", map[string]string{"email": "grace@example.com", "password": "correct-password"}, nil)
	if blocked.Code != http.StatusForbidden {
		t.Fatalf("banned sign-in status = %d, want 403", blocked.Code)
	}

	// Unban restores access.
	unban := f.do(t, http.MethodPost, "/admin/unban-user", map[string]string{"userId": targetID}, adminCookie)
	if unban.Code != http.StatusOK {
		t.Fatalf("unban status = %d, body = %s", unban.Code, unban.Body.String())
	}
	restored := f.do(t, http.MethodPost, "/sign-in/email", map[string]string{"email": "grace@example.com", "password": "correct-password"}, nil)
	if restored.Code != http.StatusOK {
		t.Fatalf("unbanned sign-in status = %d, body = %s", restored.Code, restored.Body.String())
	}
}

func TestAdminCreateUser(t *testing.T) {
	f := newFixture(t)
	adminCookie := f.signUp(t, "Root", "root@example.com")
	f.promoteToAdmin(t, "root@example.com")

	create := f.do(t, http.MethodPost, "/admin/create-user", map[string]string{
		"name": "Made", "email": "made@example.com", "password": "provisioned-pass", "role": "member",
	}, adminCookie)
	if create.Code != http.StatusOK {
		t.Fatalf("create-user status = %d, body = %s", create.Code, create.Body.String())
	}
	signin := f.do(t, http.MethodPost, "/sign-in/email", map[string]string{"email": "made@example.com", "password": "provisioned-pass"}, nil)
	if signin.Code != http.StatusOK {
		t.Fatalf("provisioned sign-in status = %d, body = %s", signin.Code, signin.Body.String())
	}
}

func TestAdminImpersonation(t *testing.T) {
	f := newFixture(t)
	adminCookie := f.signUp(t, "Root", "root@example.com")
	f.promoteToAdmin(t, "root@example.com")
	f.signUp(t, "Grace", "grace@example.com")
	targetID := f.userID(t, "grace@example.com")

	imp := f.do(t, http.MethodPost, "/admin/impersonate", map[string]string{"userId": targetID}, adminCookie)
	if imp.Code != http.StatusOK {
		t.Fatalf("impersonate status = %d, body = %s", imp.Code, imp.Body.String())
	}
	var impCookie *http.Cookie
	for _, c := range imp.Result().Cookies() {
		if c.Name == "canopy.session_token" {
			impCookie = c
		}
	}
	if impCookie == nil {
		t.Fatal("no impersonation cookie")
	}

	// The impersonation session is the target, marked with the admin.
	session := f.do(t, http.MethodGet, "/get-session", nil, impCookie)
	var data canopy.SessionData
	if err := json.NewDecoder(session.Body).Decode(&data); err != nil {
		t.Fatal(err)
	}
	if data.User.Email != "grace@example.com" {
		t.Fatalf("impersonation user = %q, want grace", data.User.Email)
	}
	if data.Session.ImpersonatedBy == "" {
		t.Fatal("impersonatedBy was not recorded")
	}

	// Stop impersonating restores the admin.
	stop := f.do(t, http.MethodPost, "/admin/stop-impersonating", nil, impCookie)
	if stop.Code != http.StatusOK {
		t.Fatalf("stop status = %d, body = %s", stop.Code, stop.Body.String())
	}
	var restored canopy.SessionData
	if err := json.NewDecoder(stop.Body).Decode(&restored); err != nil {
		t.Fatal(err)
	}
	if restored.User.Email != "root@example.com" {
		t.Fatalf("restored user = %q, want root", restored.User.Email)
	}
}
