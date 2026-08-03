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

func TestAddTeamMemberRejectsConcurrentDuplicate(t *testing.T) {
	store := New()
	ctx := context.Background()
	now := time.Now().UTC()
	if err := store.CreateTeam(ctx, &canopy.Team{
		ID: "team_race", OrganizationID: "org_race", Name: "Race", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateMember(ctx, &canopy.Member{
		ID: "mem_race", OrganizationID: "org_race", UserID: "usr_race",
		Role: "member", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	for _, id := range []string{"tmem_one", "tmem_two"} {
		go func(id string) {
			results <- store.AddTeamMember(ctx, &canopy.TeamMember{
				ID: id, TeamID: "team_race", OrganizationID: "org_race",
				UserID: "usr_race", CreatedAt: now,
			})
		}(id)
	}
	var conflicts, successes int
	for range 2 {
		switch err := <-results; err {
		case nil:
			successes++
		case canopy.ErrConflict:
			conflicts++
		default:
			t.Fatalf("AddTeamMember() error = %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("successes = %d, conflicts = %d, want 1 and 1", successes, conflicts)
	}
}

func TestRemoveMemberAndClearSessionsCascadesTeamMemberships(t *testing.T) {
	store := New()
	ctx := context.Background()
	now := time.Now().UTC()
	if err := store.CreateMember(ctx, &canopy.Member{
		ID: "mem_cascade", OrganizationID: "org_cascade", UserID: "usr_cascade",
		Role: "member", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateTeam(ctx, &canopy.Team{
		ID: "team_cascade", OrganizationID: "org_cascade", Name: "Ops", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.AddTeamMember(ctx, &canopy.TeamMember{
		ID: "tmem_cascade", TeamID: "team_cascade", OrganizationID: "org_cascade",
		UserID: "usr_cascade", CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.RemoveMemberAndClearSessions(ctx, "org_cascade", "usr_cascade", now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.FindTeamMember(ctx, "team_cascade", "usr_cascade"); err != canopy.ErrNotFound {
		t.Fatalf("team membership error = %v, want ErrNotFound", err)
	}
}

func TestDeleteOrganizationCascadesTeams(t *testing.T) {
	store := New()
	ctx := context.Background()
	now := time.Now().UTC()
	if err := store.CreateOrganization(ctx, &canopy.Organization{
		ID: "org_teams", Name: "Acme", Slug: "acme", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateTeam(ctx, &canopy.Team{
		ID: "team_gone", OrganizationID: "org_teams", Name: "Ops", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateMember(ctx, &canopy.Member{
		ID: "mem_gone", OrganizationID: "org_teams", UserID: "usr_gone",
		Role: "member", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.AddTeamMember(ctx, &canopy.TeamMember{
		ID: "tmem_gone", TeamID: "team_gone", OrganizationID: "org_teams",
		UserID: "usr_gone", CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteOrganization(ctx, "org_teams"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.FindTeamByID(ctx, "team_gone"); err != canopy.ErrNotFound {
		t.Fatalf("team error = %v, want ErrNotFound", err)
	}
	if _, err := store.FindTeamMember(ctx, "team_gone", "usr_gone"); err != canopy.ErrNotFound {
		t.Fatalf("team membership error = %v, want ErrNotFound", err)
	}
}

func TestAcceptInvitationCreatesTeamMembership(t *testing.T) {
	store := New()
	ctx := context.Background()
	now := time.Now().UTC()
	if err := store.CreateTeam(ctx, &canopy.Team{
		ID: "team_invite", OrganizationID: "org_invite", Name: "Ops", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	invitation := &canopy.Invitation{
		ID: "inv_team", OrganizationID: "org_invite", Email: "ada@example.com",
		Role: "member", Status: "pending", TeamID: "team_invite",
		ExpiresAt: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now,
	}
	if err := store.CreateInvitation(ctx, invitation); err != nil {
		t.Fatal(err)
	}
	member := &canopy.Member{
		ID: "mem_team", OrganizationID: "org_invite", UserID: "usr_team",
		Role: "member", CreatedAt: now, UpdatedAt: now,
	}
	if err := store.AcceptInvitation(ctx, invitation.ID, invitation.Email, now, member); err != nil {
		t.Fatal(err)
	}
	if _, err := store.FindMember(ctx, "org_invite", "usr_team"); err != nil {
		t.Fatalf("organization membership missing: %v", err)
	}
	if _, err := store.FindTeamMember(ctx, "team_invite", "usr_team"); err != nil {
		t.Fatalf("team membership missing: %v", err)
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

func TestAddTeamMemberRequiresTeamAndMembership(t *testing.T) {
	store := New()
	ctx := context.Background()
	now := time.Now().UTC()
	member := &canopy.TeamMember{
		ID: "tmem_guard", TeamID: "team_guard", OrganizationID: "org_guard",
		UserID: "usr_guard", CreatedAt: now,
	}
	if err := store.AddTeamMember(ctx, member); err != canopy.ErrInvalidInput {
		t.Fatalf("AddTeamMember() without team error = %v, want ErrInvalidInput", err)
	}
	if err := store.CreateTeam(ctx, &canopy.Team{
		ID: "team_guard", OrganizationID: "org_guard", Name: "Guard", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.AddTeamMember(ctx, member); err != canopy.ErrInvalidInput {
		t.Fatalf("AddTeamMember() without membership error = %v, want ErrInvalidInput", err)
	}
	if err := store.CreateMember(ctx, &canopy.Member{
		ID: "mem_guard", OrganizationID: "org_guard", UserID: "usr_guard",
		Role: "member", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.AddTeamMember(ctx, member); err != nil {
		t.Fatalf("AddTeamMember() error = %v", err)
	}
}

func TestDeleteTeamClearsPendingInvitationTeam(t *testing.T) {
	store := New()
	ctx := context.Background()
	now := time.Now().UTC()
	if err := store.CreateTeam(ctx, &canopy.Team{
		ID: "team_gone", OrganizationID: "org_gone", Name: "Gone", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	invitation := &canopy.Invitation{
		ID: "inv_gone", OrganizationID: "org_gone", Email: "ada@example.com",
		Role: "member", Status: "pending", TeamID: "team_gone",
		ExpiresAt: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now,
	}
	if err := store.CreateInvitation(ctx, invitation); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteTeam(ctx, "org_gone", "team_gone"); err != nil {
		t.Fatal(err)
	}
	member := &canopy.Member{
		ID: "mem_gone", OrganizationID: "org_gone", UserID: "usr_gone",
		Role: "member", CreatedAt: now, UpdatedAt: now,
	}
	if err := store.AcceptInvitation(ctx, invitation.ID, invitation.Email, now, member); err != nil {
		t.Fatalf("AcceptInvitation() after team delete error = %v", err)
	}
	if _, err := store.FindMember(ctx, "org_gone", "usr_gone"); err != nil {
		t.Fatalf("organization membership missing: %v", err)
	}
	if _, err := store.FindTeamMember(ctx, "team_gone", "usr_gone"); err != canopy.ErrNotFound {
		t.Fatalf("unexpected team membership after team delete: %v", err)
	}
}

func TestCreateLinkedAccountConsumesVerificationAtomically(t *testing.T) {
	store := New()
	ctx := context.Background()
	now := time.Now().UTC()
	user := &canopy.User{ID: "usr_link", Name: "Ada", Email: "ada@example.com", CreatedAt: now, UpdatedAt: now}
	if err := store.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	verification := &canopy.Verification{
		ID: "alk_link", Identifier: "account_link:usr_link", Value: "state-hash",
		ExpiresAt: now.Add(time.Minute), CreatedAt: now, UpdatedAt: now,
	}
	if err := store.ReplaceVerification(ctx, verification); err != nil {
		t.Fatal(err)
	}
	account := &canopy.Account{
		ID: "acc_link", UserID: user.ID, AccountID: "google-sub", ProviderID: "google",
		CreatedAt: now, UpdatedAt: now,
	}
	if err := store.CreateLinkedAccount(ctx, verification.Identifier, verification.Value, now, account); err != nil {
		t.Fatal(err)
	}
	if _, err := store.FindAccount(ctx, "google", "google-sub"); err != nil {
		t.Fatalf("linked account missing: %v", err)
	}
	if _, err := store.ConsumeVerification(ctx, verification.Identifier, verification.Value, now); err != canopy.ErrNotFound {
		t.Fatalf("verification err = %v, want ErrNotFound", err)
	}
	replay := &canopy.Account{
		ID: "acc_replay", UserID: user.ID, AccountID: "google-sub-2", ProviderID: "google-2",
		CreatedAt: now, UpdatedAt: now,
	}
	if err := store.CreateLinkedAccount(ctx, verification.Identifier, verification.Value, now, replay); err != canopy.ErrNotFound {
		t.Fatalf("replayed link err = %v, want ErrNotFound", err)
	}
	if _, err := store.FindAccount(ctx, "google-2", "google-sub-2"); err != canopy.ErrNotFound {
		t.Fatalf("replayed account err = %v, want ErrNotFound", err)
	}
}

func TestCreateLinkedAccountKeepsVerificationOnConflict(t *testing.T) {
	store := New()
	ctx := context.Background()
	now := time.Now().UTC()
	if err := store.CreateAccount(ctx, &canopy.Account{
		ID: "acc_taken", UserID: "usr_other", AccountID: "google-sub", ProviderID: "google",
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	verification := &canopy.Verification{
		ID: "alk_conflict", Identifier: "account_link:usr_link", Value: "state-hash",
		ExpiresAt: now.Add(time.Minute), CreatedAt: now, UpdatedAt: now,
	}
	if err := store.ReplaceVerification(ctx, verification); err != nil {
		t.Fatal(err)
	}
	account := &canopy.Account{
		ID: "acc_dup", UserID: "usr_link", AccountID: "google-sub", ProviderID: "google",
		CreatedAt: now, UpdatedAt: now,
	}
	if err := store.CreateLinkedAccount(ctx, verification.Identifier, verification.Value, now, account); err != canopy.ErrConflict {
		t.Fatalf("conflicting link err = %v, want ErrConflict", err)
	}
	if _, err := store.ConsumeVerification(ctx, verification.Identifier, verification.Value, now); err != nil {
		t.Fatalf("verification consumed on failed link: %v", err)
	}
}

func TestCreateLinkedAccountRejectsExpiredVerification(t *testing.T) {
	store := New()
	ctx := context.Background()
	now := time.Now().UTC()
	verification := &canopy.Verification{
		ID: "alk_expired", Identifier: "account_link:usr_link", Value: "state-hash",
		ExpiresAt: now.Add(-time.Minute), CreatedAt: now, UpdatedAt: now,
	}
	if err := store.ReplaceVerification(ctx, verification); err != nil {
		t.Fatal(err)
	}
	account := &canopy.Account{
		ID: "acc_late", UserID: "usr_link", AccountID: "google-sub", ProviderID: "google",
		CreatedAt: now, UpdatedAt: now,
	}
	if err := store.CreateLinkedAccount(ctx, verification.Identifier, verification.Value, now, account); err != canopy.ErrNotFound {
		t.Fatalf("expired link err = %v, want ErrNotFound", err)
	}
	if _, err := store.FindAccount(ctx, "google", "google-sub"); err != canopy.ErrNotFound {
		t.Fatalf("account err = %v, want ErrNotFound", err)
	}
}
