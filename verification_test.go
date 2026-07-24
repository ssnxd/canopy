package canopy

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"
)

func TestAppendTokenPreservesQueryAndFragment(t *testing.T) {
	got := appendToken("https://app.example.test/verify?language=en#confirm", "a+b&c")
	parsed, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Query().Get("language") != "en" || parsed.Query().Get("token") != "a+b&c" {
		t.Fatalf("callback query = %q", parsed.RawQuery)
	}
	if parsed.Fragment != "confirm" {
		t.Fatalf("callback fragment = %q, want confirm", parsed.Fragment)
	}
}

func TestSigningKeyRotationAcceptsInFlightTokens(t *testing.T) {
	store := newMemoryStore()
	oldAuth, err := New(Config{
		Store:  store,
		Secret: "old-production-secret-with-enough-entropy",
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	token, _, err := oldAuth.API().issueActionToken(ctx, oldAuth.API().passwordResetTokenKind(), "ada@example.com")
	if err != nil {
		t.Fatal(err)
	}
	state, err := oldAuth.API().signOAuthState(oauthStatePayload{
		ID:           "state-id",
		Provider:     "google",
		Nonce:        "nonce",
		PKCEVerifier: "verifier",
		BindingHash:  "binding",
		IssuedAt:     time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	rotatedAuth, err := New(Config{
		Store:           store,
		Secret:          "new-production-secret-with-enough-entropy",
		PreviousSecrets: []string{"old-production-secret-with-enough-entropy"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rotatedAuth.API().consumeActionToken(ctx, rotatedAuth.API().passwordResetTokenKind(), token); err != nil {
		t.Fatalf("in-flight action token failed after rotation: %v", err)
	}
	if _, err := rotatedAuth.API().verifyOAuthState(state); err != nil {
		t.Fatalf("in-flight OAuth state failed after rotation: %v", err)
	}
	unrotatedAuth, err := New(Config{
		Store:  newMemoryStore(),
		Secret: "new-production-secret-with-enough-entropy",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unrotatedAuth.API().verifyOAuthState(state); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("old OAuth state error = %v, want ErrInvalidState", err)
	}
}

type testEmailSender struct {
	verificationMessages []EmailVerificationMessage
	resetMessages        []PasswordResetMessage
}

func (s *testEmailSender) SendEmailVerification(ctx context.Context, message EmailVerificationMessage) error {
	s.verificationMessages = append(s.verificationMessages, message)
	return nil
}

func (s *testEmailSender) SendPasswordReset(ctx context.Context, message PasswordResetMessage) error {
	s.resetMessages = append(s.resetMessages, message)
	return nil
}

func TestEmailVerificationFlow(t *testing.T) {
	sender := &testEmailSender{}
	auth, err := New(Config{
		Store:                    newMemoryStore(),
		Secret:                   "dev-secret-with-enough-test-entropy",
		RequireEmailVerification: true,
		EmailSender:              sender,
		TrustedOrigins:           []string{"https://app.example.test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	_, _, err = auth.API().SignUpEmail(ctx, SignUpEmailInput{
		Name:        "Ada",
		Email:       "ada@example.com",
		Password:    "correct-password",
		CallbackURL: "https://app.example.test/verify",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(sender.verificationMessages) != 1 {
		t.Fatalf("verification messages = %d, want 1", len(sender.verificationMessages))
	}
	msg := sender.verificationMessages[0]
	if msg.Token == "" || msg.URL == "" || !msg.ExpiresAt.After(time.Now()) {
		t.Fatalf("invalid verification message: %#v", msg)
	}
	_, err = auth.API().SignInEmail(ctx, SignInEmailInput{
		Email:    "ada@example.com",
		Password: "correct-password",
	})
	if !errors.Is(err, ErrUnverifiedEmail) {
		t.Fatalf("err = %v, want ErrUnverifiedEmail", err)
	}
	user, err := auth.API().VerifyEmail(ctx, VerifyEmailInput{Token: msg.Token})
	if err != nil {
		t.Fatal(err)
	}
	if !user.EmailVerified {
		t.Fatal("user was not marked verified")
	}
	_, err = auth.API().VerifyEmail(ctx, VerifyEmailInput{Token: msg.Token})
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("replay err = %v, want ErrInvalidToken", err)
	}
	_, err = auth.API().SignInEmail(ctx, SignInEmailInput{
		Email:    "ada@example.com",
		Password: "correct-password",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestActionTokensRejectWrongPurposeAndExpiry(t *testing.T) {
	sender := &testEmailSender{}
	auth, err := New(Config{
		Store:                    newMemoryStore(),
		Secret:                   "dev-secret-with-enough-test-entropy",
		RequireEmailVerification: true,
		EmailSender:              sender,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	_, _, err = auth.API().SignUpEmail(ctx, SignUpEmailInput{
		Name:     "Ada",
		Email:    "ada@example.com",
		Password: "correct-password",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(sender.verificationMessages) != 1 {
		t.Fatalf("verification messages = %d, want 1", len(sender.verificationMessages))
	}
	expiredToken, err := auth.API().signActionToken(actionTokenPayload{
		ID:        "expired",
		Purpose:   verificationPurposeEmail,
		Email:     "ada@example.com",
		ExpiresAt: time.Now().Add(-time.Minute),
		IssuedAt:  time.Now().Add(-2 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth.API().VerifyEmail(ctx, VerifyEmailInput{Token: expiredToken}); !errors.Is(err, ErrExpiredToken) {
		t.Fatalf("expired token err = %v, want ErrExpiredToken", err)
	}

	resetToken, _, err := auth.API().issueActionToken(ctx, auth.API().passwordResetTokenKind(), "ada@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth.API().VerifyEmail(ctx, VerifyEmailInput{Token: resetToken}); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("wrong purpose err = %v, want ErrInvalidToken", err)
	}
}

func TestPasswordResetFlowRevokesSessionsAndChangesPassword(t *testing.T) {
	sender := &testEmailSender{}
	auth, err := New(Config{
		Store:       newMemoryStore(),
		Secret:      "dev-secret-with-enough-test-entropy",
		EmailSender: sender,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	_, oldToken, err := auth.API().SignUpEmail(ctx, SignUpEmailInput{
		Name:     "Ada",
		Email:    "ada@example.com",
		Password: "old-password",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.API().RequestPasswordReset(ctx, RequestPasswordResetInput{
		Email:       "ada@example.com",
		CallbackURL: "https://app.example.test/reset",
	}); err != nil {
		t.Fatal(err)
	}
	if len(sender.resetMessages) != 1 {
		t.Fatalf("reset messages = %d, want 1", len(sender.resetMessages))
	}
	if err := auth.API().ResetPassword(ctx, ResetPasswordInput{
		Token:       sender.resetMessages[0].Token,
		NewPassword: "new-password",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.API().GetSession(ctx, oldToken); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("old session err = %v, want ErrUnauthorized", err)
	}
	_, err = auth.API().SignInEmail(ctx, SignInEmailInput{
		Email:    "ada@example.com",
		Password: "old-password",
	})
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("old password err = %v, want ErrInvalidCredentials", err)
	}
	_, err = auth.API().SignInEmail(ctx, SignInEmailInput{
		Email:    "ada@example.com",
		Password: "new-password",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestPasswordResetOnlyAcceptsLatestIssuedToken(t *testing.T) {
	sender := &testEmailSender{}
	auth, err := New(Config{
		Store:       newMemoryStore(),
		Secret:      "dev-secret-with-enough-test-entropy",
		EmailSender: sender,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, _, err := auth.API().SignUpEmail(ctx, SignUpEmailInput{
		Name: "Ada", Email: "ada@example.com", Password: "correct-password",
	}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := auth.API().RequestPasswordReset(ctx, RequestPasswordResetInput{Email: "ada@example.com"}); err != nil {
			t.Fatal(err)
		}
	}
	if len(sender.resetMessages) != 2 {
		t.Fatalf("reset messages = %d, want 2", len(sender.resetMessages))
	}
	if err := auth.API().ResetPassword(ctx, ResetPasswordInput{
		Token: sender.resetMessages[0].Token, NewPassword: "first-new-password",
	}); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("superseded token err = %v, want ErrInvalidToken", err)
	}
	if err := auth.API().ResetPassword(ctx, ResetPasswordInput{
		Token: sender.resetMessages[1].Token, NewPassword: "second-new-password",
	}); err != nil {
		t.Fatal(err)
	}
}
