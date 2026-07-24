package memory

import (
	"context"
	"testing"
	"time"

	"github.com/ssnxd/canopy"
)

func TestSessionTokenIsNotRetainedAtRest(t *testing.T) {
	store := New()
	now := time.Now().UTC()
	user := &canopy.User{ID: "usr_test", Name: "Ada", Email: "ada@example.com", CreatedAt: now, UpdatedAt: now}
	if err := store.CreateUser(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	session := &canopy.Session{
		ID: "ses_test", UserID: user.ID, Token: "raw-bearer-token",
		ExpiresAt: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now,
	}
	if err := store.CreateSession(context.Background(), session); err != nil {
		t.Fatal(err)
	}
	list, err := store.ListUserSessions(context.Background(), user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Token != "" {
		t.Fatalf("stored sessions = %#v, want token omitted", list)
	}
	found, err := store.FindSessionByToken(context.Background(), "raw-bearer-token")
	if err != nil {
		t.Fatal(err)
	}
	if found.Session.Token != "raw-bearer-token" {
		t.Fatalf("resolved token = %q, want request token", found.Session.Token)
	}
}

func TestApplyPasswordResetIsAtomic(t *testing.T) {
	store := New()
	ctx := context.Background()
	now := time.Now().UTC()
	user := &canopy.User{ID: "usr_reset", Name: "Ada", Email: "ada@example.com", CreatedAt: now, UpdatedAt: now}
	account := &canopy.Account{
		ID: "acc_reset", UserID: user.ID, AccountID: user.Email,
		ProviderID: canopy.ProviderEmailPassword, Password: "old-hash", CreatedAt: now, UpdatedAt: now,
	}
	if err := store.CreateUserAccount(ctx, user, account); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateSession(ctx, &canopy.Session{
		ID: "ses_reset", UserID: user.ID, Token: "session-token",
		ExpiresAt: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	verification := &canopy.Verification{
		ID: "ver_reset", Identifier: "password_reset:ada@example.com", Value: "token-hash",
		ExpiresAt: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now,
	}
	if err := store.ReplaceVerification(ctx, verification); err != nil {
		t.Fatal(err)
	}
	account.Password = "new-hash"
	if err := store.ApplyPasswordReset(ctx, verification.Identifier, verification.Value, now, account); err != nil {
		t.Fatal(err)
	}
	if _, err := store.FindSessionByToken(ctx, "session-token"); err != canopy.ErrNotFound {
		t.Fatalf("session err = %v, want ErrNotFound", err)
	}
	updated, err := store.FindAccountByUserProvider(ctx, user.ID, canopy.ProviderEmailPassword)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Password != "new-hash" {
		t.Fatalf("password = %q, want new-hash", updated.Password)
	}
	if _, err := store.ConsumeVerification(ctx, verification.Identifier, verification.Value, now); err != canopy.ErrNotFound {
		t.Fatalf("verification err = %v, want ErrNotFound", err)
	}
}
