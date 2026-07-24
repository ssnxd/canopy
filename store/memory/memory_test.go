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
