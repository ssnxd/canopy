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

func TestCreateOrganizationWithOwnerRollsBackOnConflict(t *testing.T) {
	store := New()
	ctx := context.Background()
	now := time.Now().UTC()
	org := &canopy.Organization{ID: "org_atomic", Name: "Atomic", Slug: "atomic", CreatedAt: now, UpdatedAt: now}
	owner := &canopy.Member{
		ID: "mem_owner", OrganizationID: org.ID, UserID: "usr_owner", Role: "owner",
		CreatedAt: now, UpdatedAt: now,
	}
	if err := store.CreateMember(ctx, owner); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateOrganizationWithOwner(ctx, org, owner); err != canopy.ErrConflict {
		t.Fatalf("CreateOrganizationWithOwner() error = %v, want ErrConflict", err)
	}
	if _, err := store.FindOrganizationByID(ctx, org.ID); err != canopy.ErrNotFound {
		t.Fatalf("organization survived failed owner creation: %v", err)
	}
}

func TestAcceptInvitationChecksAndCommitsTogether(t *testing.T) {
	store := New()
	ctx := context.Background()
	now := time.Now().UTC()
	invitation := &canopy.Invitation{
		ID: "inv_atomic", OrganizationID: "org_atomic", Email: "ada@example.com",
		Role: "member", Status: "pending", ExpiresAt: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now,
	}
	if err := store.CreateInvitation(ctx, invitation); err != nil {
		t.Fatal(err)
	}
	member := &canopy.Member{
		ID: "mem_atomic", OrganizationID: invitation.OrganizationID, UserID: "usr_atomic",
		Role: invitation.Role, CreatedAt: now, UpdatedAt: now,
	}
	if err := store.AcceptInvitation(ctx, invitation.ID, "other@example.com", now, member); err != canopy.ErrNotFound {
		t.Fatalf("wrong-email accept error = %v, want ErrNotFound", err)
	}
	if err := store.AcceptInvitation(ctx, invitation.ID, invitation.Email, now, member); err != nil {
		t.Fatal(err)
	}
	if _, err := store.FindMember(ctx, member.OrganizationID, member.UserID); err != nil {
		t.Fatalf("accepted member missing: %v", err)
	}
	if err := store.AcceptInvitation(ctx, invitation.ID, invitation.Email, now, member); err != canopy.ErrNotFound {
		t.Fatalf("replayed accept error = %v, want ErrNotFound", err)
	}
}

func TestEnableTwoFactorRequiresEnrollmentBeforeWritingCodes(t *testing.T) {
	store := New()
	ctx := context.Background()
	now := time.Now().UTC()
	tf := &canopy.TwoFactor{
		UserID: "usr_atomic", Secret: "encrypted", Enabled: true,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := store.EnableTwoFactor(ctx, tf, []string{"backup-hash"}); err != canopy.ErrNotFound {
		t.Fatalf("EnableTwoFactor() error = %v, want ErrNotFound", err)
	}
	if consumed, err := store.ConsumeBackupCode(ctx, tf.UserID, "backup-hash"); err != nil || consumed {
		t.Fatalf("backup code written on failed enable: consumed=%v err=%v", consumed, err)
	}
}

func TestUpdateMemberRoleProtectsLastOwner(t *testing.T) {
	store := New()
	ctx := context.Background()
	now := time.Now().UTC()
	owner := &canopy.Member{
		ID: "mem_owner", OrganizationID: "org_owner", UserID: "usr_owner",
		Role: "owner", CreatedAt: now, UpdatedAt: now,
	}
	if err := store.CreateMember(ctx, owner); err != nil {
		t.Fatal(err)
	}
	owner.Role = "member"
	if err := store.UpdateMemberRole(ctx, owner, "owner"); err != canopy.ErrLastOrganizationOwner {
		t.Fatalf("UpdateMemberRole() error = %v, want ErrLastOrganizationOwner", err)
	}
	stored, err := store.FindMember(ctx, owner.OrganizationID, owner.UserID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Role != "owner" {
		t.Fatalf("last owner role = %q, want owner", stored.Role)
	}
}

func TestCleanupExpiredRetainsLiveRecords(t *testing.T) {
	store := New()
	ctx := context.Background()
	now := time.Now().UTC()
	user := &canopy.User{ID: "usr_cleanup", Name: "Ada", Email: "ada@example.com", CreatedAt: now, UpdatedAt: now}
	if err := store.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	for _, session := range []*canopy.Session{
		{ID: "ses_expired", UserID: user.ID, Token: "expired-token", ExpiresAt: now.Add(-time.Minute), CreatedAt: now, UpdatedAt: now},
		{ID: "ses_live", UserID: user.ID, Token: "live-token", ExpiresAt: now.Add(time.Minute), CreatedAt: now, UpdatedAt: now},
	} {
		if err := store.CreateSession(ctx, session); err != nil {
			t.Fatal(err)
		}
	}
	for _, verification := range []*canopy.Verification{
		{ID: "ver_expired", Identifier: "cleanup", Value: "expired", ExpiresAt: now.Add(-time.Minute), CreatedAt: now, UpdatedAt: now},
		{ID: "ver_live", Identifier: "cleanup", Value: "live", ExpiresAt: now.Add(time.Minute), CreatedAt: now, UpdatedAt: now},
	} {
		if err := store.CreateVerification(ctx, verification); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.CleanupExpired(ctx, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.FindSessionByToken(ctx, "expired-token"); err != canopy.ErrNotFound {
		t.Fatalf("expired session error = %v, want ErrNotFound", err)
	}
	if _, err := store.FindSessionByToken(ctx, "live-token"); err != nil {
		t.Fatalf("live session error = %v", err)
	}
	if _, err := store.ConsumeVerification(ctx, "cleanup", "expired", now); err != canopy.ErrNotFound {
		t.Fatalf("expired verification error = %v, want ErrNotFound", err)
	}
	if _, err := store.ConsumeVerification(ctx, "cleanup", "live", now); err != nil {
		t.Fatalf("live verification error = %v", err)
	}
}
