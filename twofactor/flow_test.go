package twofactor_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ssnxd/canopy"
	"github.com/ssnxd/canopy/store/memory"
	"github.com/ssnxd/canopy/twofactor"
)

type flowFixture struct {
	auth    *canopy.Auth
	handler http.Handler
	totp    *twofactor.TOTP
}

func newFlow(t *testing.T) *flowFixture {
	t.Helper()
	auth, err := canopy.New(canopy.Config{
		Store:   memory.New(),
		Secret:  "dev-secret-with-enough-test-entropy",
		Modules: []canopy.Module{twofactor.New(twofactor.Options{Issuer: "Canopy Test"})},
	})
	if err != nil {
		t.Fatal(err)
	}
	return &flowFixture{auth: auth, handler: auth.Handler(), totp: twofactor.NewTOTP()}
}

func post(t *testing.T, handler http.Handler, path string, body any, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(encoded))
	req.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func cookie(t *testing.T, rec *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("missing cookie %q", name)
	return nil
}

func decode(t *testing.T, rec *httptest.ResponseRecorder, dst any) {
	t.Helper()
	if err := json.NewDecoder(rec.Body).Decode(dst); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, rec.Body.String())
	}
}

// enrolls a user and returns the session cookie, the TOTP secret, and the
// backup codes.
func (f *flowFixture) enroll(t *testing.T, email string) (*http.Cookie, string, []string) {
	t.Helper()
	signup := post(t, f.handler, "/sign-up/email", map[string]string{
		"name": "Ada", "email": email, "password": "correct-password",
	}, nil)
	if signup.Code != http.StatusOK {
		t.Fatalf("signup status = %d, body = %s", signup.Code, signup.Body.String())
	}
	sessionCookie := cookie(t, signup, "canopy.session_token")

	enable := post(t, f.handler, "/two-factor/enable", map[string]string{}, []*http.Cookie{sessionCookie})
	if enable.Code != http.StatusOK {
		t.Fatalf("enable status = %d, body = %s", enable.Code, enable.Body.String())
	}
	var enableBody struct {
		Secret string `json:"secret"`
		URI    string `json:"uri"`
	}
	decode(t, enable, &enableBody)
	if enableBody.Secret == "" || enableBody.URI == "" {
		t.Fatalf("enable body = %#v", enableBody)
	}

	code, err := f.totp.GenerateCode(enableBody.Secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	verify := post(t, f.handler, "/two-factor/verify", map[string]string{"code": code}, []*http.Cookie{sessionCookie})
	if verify.Code != http.StatusOK {
		t.Fatalf("verify status = %d, body = %s", verify.Code, verify.Body.String())
	}
	var verifyBody struct {
		BackupCodes []string `json:"backupCodes"`
	}
	decode(t, verify, &verifyBody)
	if len(verifyBody.BackupCodes) == 0 {
		t.Fatal("no backup codes returned")
	}
	return sessionCookie, enableBody.Secret, verifyBody.BackupCodes
}

// startSignIn signs in with the password and returns the challenge token.
func (f *flowFixture) startSignIn(t *testing.T, email string) string {
	t.Helper()
	signin := post(t, f.handler, "/sign-in/email", map[string]string{
		"email": email, "password": "correct-password",
	}, nil)
	if signin.Code != http.StatusOK {
		t.Fatalf("signin status = %d, body = %s", signin.Code, signin.Body.String())
	}
	// No session cookie should be set while a second factor is pending.
	for _, c := range signin.Result().Cookies() {
		if c.Name == "canopy.session_token" && c.Value != "" {
			t.Fatal("a session cookie was set before the second factor")
		}
	}
	var body struct {
		TwoFactorRequired bool     `json:"twoFactorRequired"`
		Token             string   `json:"token"`
		Methods           []string `json:"methods"`
	}
	decode(t, signin, &body)
	if !body.TwoFactorRequired || body.Token == "" {
		t.Fatalf("expected a two-factor challenge, got %#v", body)
	}
	return body.Token
}

func TestTwoFactorTOTPSignInFlow(t *testing.T) {
	f := newFlow(t)
	_, secret, _ := f.enroll(t, "ada@example.com")

	token := f.startSignIn(t, "ada@example.com")
	code, err := f.totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	challenge := post(t, f.handler, "/two-factor/challenge", map[string]any{"token": token, "code": code}, nil)
	if challenge.Code != http.StatusOK {
		t.Fatalf("challenge status = %d, body = %s", challenge.Code, challenge.Body.String())
	}
	sessionCookie := cookie(t, challenge, "canopy.session_token")

	// The issued session authenticates.
	session, err := f.auth.API().GetSession(context.Background(), sessionCookie.Value)
	if err != nil {
		t.Fatalf("get-session err = %v", err)
	}
	if session.User.Email != "ada@example.com" {
		t.Fatalf("session user = %q", session.User.Email)
	}
}

func TestTwoFactorChallengeTokenIsOneTime(t *testing.T) {
	f := newFlow(t)
	_, secret, _ := f.enroll(t, "ada@example.com")
	token := f.startSignIn(t, "ada@example.com")

	// A wrong code still consumes the one-time challenge token.
	wrong := post(t, f.handler, "/two-factor/challenge", map[string]any{"token": token, "code": "000000"}, nil)
	if wrong.Code != http.StatusUnauthorized {
		t.Fatalf("wrong code status = %d, want 401", wrong.Code)
	}
	// A correct code with the now-consumed token must fail.
	code, err := f.totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	replay := post(t, f.handler, "/two-factor/challenge", map[string]any{"token": token, "code": code}, nil)
	if replay.Code == http.StatusOK {
		t.Fatal("a consumed challenge token was accepted")
	}
}

func TestTwoFactorBackupCodeSignIn(t *testing.T) {
	f := newFlow(t)
	_, _, backupCodes := f.enroll(t, "ada@example.com")

	token := f.startSignIn(t, "ada@example.com")
	used := backupCodes[0]
	first := post(t, f.handler, "/two-factor/backup", map[string]any{"token": token, "code": used}, nil)
	if first.Code != http.StatusOK {
		t.Fatalf("backup status = %d, body = %s", first.Code, first.Body.String())
	}

	// The same backup code cannot be reused.
	token2 := f.startSignIn(t, "ada@example.com")
	reuse := post(t, f.handler, "/two-factor/backup", map[string]any{"token": token2, "code": used}, nil)
	if reuse.Code != http.StatusUnauthorized {
		t.Fatalf("reused backup status = %d, want 401", reuse.Code)
	}
}

func TestTwoFactorDisableRestoresDirectSignIn(t *testing.T) {
	f := newFlow(t)
	sessionCookie, secret, _ := f.enroll(t, "ada@example.com")

	code, _ := f.totp.GenerateCode(secret, time.Now())
	disable := post(t, f.handler, "/two-factor/disable", map[string]string{"code": code}, []*http.Cookie{sessionCookie})
	if disable.Code != http.StatusOK {
		t.Fatalf("disable status = %d, body = %s", disable.Code, disable.Body.String())
	}

	// Sign-in now returns a session directly, with no challenge.
	signin := post(t, f.handler, "/sign-in/email", map[string]string{
		"email": "ada@example.com", "password": "correct-password",
	}, nil)
	if signin.Code != http.StatusOK {
		t.Fatalf("signin status = %d, body = %s", signin.Code, signin.Body.String())
	}
	cookie(t, signin, "canopy.session_token")
}
