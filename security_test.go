package canopy

import (
	"context"
	"strings"
	"testing"

	authoauth "github.com/ssnxd/canopy/oauth"
)

// An untrusted callback host must not receive the one-time reset token.
func TestPasswordResetDropsUntrustedCallbackURL(t *testing.T) {
	sender := &testEmailSender{}
	auth, err := New(Config{
		Store:          newMemoryStore(),
		Secret:         "dev-secret-with-enough-test-entropy",
		EmailSender:    sender,
		TrustedOrigins: []string{"https://app.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, _, err := auth.API().SignUpEmail(ctx, SignUpEmailInput{Name: "Ada", Email: "victim@example.com", Password: "correct-password"}); err != nil {
		t.Fatal(err)
	}
	if err := auth.API().RequestPasswordReset(ctx, RequestPasswordResetInput{
		Email:       "victim@example.com",
		CallbackURL: "https://evil.attacker.example/collect",
	}); err != nil {
		t.Fatal(err)
	}
	if len(sender.resetMessages) != 1 {
		t.Fatalf("reset messages = %d, want 1", len(sender.resetMessages))
	}
	msg := sender.resetMessages[0]
	if msg.URL != "" {
		t.Fatalf("untrusted callback URL was kept: %q", msg.URL)
	}
	if msg.CallbackURL != "" {
		t.Fatalf("untrusted callback URL was kept: %q", msg.CallbackURL)
	}
	if msg.Token == "" {
		t.Fatal("token must still be available for the app to build its own link")
	}
}

// A trusted callback host keeps the full link with the token.
func TestPasswordResetKeepsTrustedCallbackURL(t *testing.T) {
	sender := &testEmailSender{}
	auth, err := New(Config{
		Store:          newMemoryStore(),
		Secret:         "dev-secret-with-enough-test-entropy",
		EmailSender:    sender,
		TrustedOrigins: []string{"https://app.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, _, err := auth.API().SignUpEmail(ctx, SignUpEmailInput{Name: "Ada", Email: "ada@example.com", Password: "correct-password"}); err != nil {
		t.Fatal(err)
	}
	if err := auth.API().RequestPasswordReset(ctx, RequestPasswordResetInput{
		Email:       "ada@example.com",
		CallbackURL: "https://app.example.com/reset",
	}); err != nil {
		t.Fatal(err)
	}
	msg := sender.resetMessages[0]
	if !strings.HasPrefix(msg.URL, "https://app.example.com/reset?token=") {
		t.Fatalf("trusted callback URL was not kept: %q", msg.URL)
	}
}

func TestResolveCallbackURL(t *testing.T) {
	cfg := Config{TrustedOrigins: []string{"https://app.example.com"}}
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"   ", ""},
		{"https://app.example.com/reset", "https://app.example.com/reset"},
		{"https://evil.example/reset", ""},
		{"//evil.example/reset", ""},
		{"http://app.example.com/reset", ""},
		{"/reset-password", "/reset-password"},
		{"javascript:alert(1)", ""},
		{"https://app.example.com.evil.example/x", ""},
	}
	for _, c := range cases {
		if got := cfg.resolveCallbackURL(c.in); got != c.want {
			t.Errorf("resolveCallbackURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// The OAuth redirect target must not be an untrusted host (open-redirect guard).
func TestOAuthDropsUntrustedRedirect(t *testing.T) {
	provider := &fakeOAuthProvider{id: "google", email: "oauth@example.com", accountID: "google-sub"}
	auth, err := New(Config{
		Store:          newMemoryStore(),
		Secret:         "dev-secret-with-enough-test-entropy",
		Providers:      []authoauth.Provider{provider},
		TrustedOrigins: []string{"https://app.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	start, binding, err := auth.API().SignInSocial(ctx, SignInSocialInput{
		Provider:    "google",
		CallbackURL: "https://evil.attacker.example/steal",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _, callbackURL, _, err := auth.API().OAuthCallback(ctx, OAuthCallbackInput{
		Provider:     "google",
		Code:         "auth-code",
		State:        stateFromURL(t, start.URL),
		StateBinding: binding,
	})
	if err != nil {
		t.Fatal(err)
	}
	if callbackURL != "" {
		t.Fatalf("untrusted OAuth redirect was kept: %q", callbackURL)
	}
}
