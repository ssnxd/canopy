//go:build e2e

package postgres

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/ssnxd/canopy"
)

func TestE2EAddTeamMemberDuplicateRace(t *testing.T) {
	store, ctx := e2eStore(t)
	now := time.Now().UTC()
	seedTeamFixture(t, store, "race", now)

	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, id := range []string{"tmem_race_one", "tmem_race_two"} {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			results <- store.AddTeamMember(ctx, &canopy.TeamMember{
				ID: id, TeamID: "team_race", OrganizationID: "org_race",
				UserID: "usr_race", CreatedAt: now,
			})
		}(id)
	}
	wg.Wait()
	close(results)
	var conflicts, successes int
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, canopy.ErrConflict):
			conflicts++
		default:
			t.Fatalf("AddTeamMember() error = %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("successes = %d, conflicts = %d, want 1 and 1", successes, conflicts)
	}
}

func TestE2EAddTeamMemberRequiresOrganizationMembership(t *testing.T) {
	store, ctx := e2eStore(t)
	now := time.Now().UTC()
	seedTeamFixture(t, store, "fk", now)

	err := store.AddTeamMember(ctx, &canopy.TeamMember{
		ID: "tmem_fk_bad", TeamID: "team_fk", OrganizationID: "org_fk",
		UserID: "usr_missing", CreatedAt: now,
	})
	if !errors.Is(err, canopy.ErrInvalidInput) {
		t.Fatalf("AddTeamMember() error = %v, want ErrInvalidInput", err)
	}
}

func TestE2ERemoveMemberAndClearSessionsCascadesTeamMemberships(t *testing.T) {
	store, ctx := e2eStore(t)
	now := time.Now().UTC()
	seedTeamFixture(t, store, "cascade", now)
	if err := store.AddTeamMember(ctx, &canopy.TeamMember{
		ID: "tmem_cascade", TeamID: "team_cascade", OrganizationID: "org_cascade",
		UserID: "usr_cascade", CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	if err := store.RemoveMemberAndClearSessions(ctx, "org_cascade", "usr_cascade", now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.FindTeamMember(ctx, "team_cascade", "usr_cascade"); !errors.Is(err, canopy.ErrNotFound) {
		t.Fatalf("team membership error = %v, want ErrNotFound", err)
	}
}

func TestE2EDeleteOrganizationCascadesTeams(t *testing.T) {
	store, ctx := e2eStore(t)
	now := time.Now().UTC()
	seedTeamFixture(t, store, "orgdel", now)
	if err := store.AddTeamMember(ctx, &canopy.TeamMember{
		ID: "tmem_orgdel", TeamID: "team_orgdel", OrganizationID: "org_orgdel",
		UserID: "usr_orgdel", CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	if err := store.DeleteOrganization(ctx, "org_orgdel"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.FindTeamByID(ctx, "team_orgdel"); !errors.Is(err, canopy.ErrNotFound) {
		t.Fatalf("team error = %v, want ErrNotFound", err)
	}
	if _, err := store.FindTeamMember(ctx, "team_orgdel", "usr_orgdel"); !errors.Is(err, canopy.ErrNotFound) {
		t.Fatalf("team membership error = %v, want ErrNotFound", err)
	}
}

func TestE2EDeleteTeamCascadesTeamMemberships(t *testing.T) {
	store, ctx := e2eStore(t)
	now := time.Now().UTC()
	seedTeamFixture(t, store, "teamdel", now)
	if err := store.AddTeamMember(ctx, &canopy.TeamMember{
		ID: "tmem_teamdel", TeamID: "team_teamdel", OrganizationID: "org_teamdel",
		UserID: "usr_teamdel", CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	if err := store.DeleteTeam(ctx, "org_teamdel", "team_teamdel"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.FindTeamMember(ctx, "team_teamdel", "usr_teamdel"); !errors.Is(err, canopy.ErrNotFound) {
		t.Fatalf("team membership error = %v, want ErrNotFound", err)
	}
	if err := store.DeleteTeam(ctx, "org_teamdel", "team_teamdel"); !errors.Is(err, canopy.ErrNotFound) {
		t.Fatalf("second delete error = %v, want ErrNotFound", err)
	}
}

func TestE2EAcceptInvitationCreatesTeamMembership(t *testing.T) {
	store, ctx := e2eStore(t)
	now := time.Now().UTC()
	seedTeamFixture(t, store, "invite", now)
	if err := store.CreateInvitation(ctx, &canopy.Invitation{
		ID: "inv_team", OrganizationID: "org_invite", Email: "invitee@example.com",
		Role: "member", Status: "pending", TeamID: "team_invite",
		ExpiresAt: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	seedUser(t, store, "usr_invitee", "invitee@example.com", now)

	if err := store.AcceptInvitation(ctx, "inv_team", "invitee@example.com", now, &canopy.Member{
		ID: "mem_invitee", OrganizationID: "org_invite", UserID: "usr_invitee",
		Role: "member", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.FindMember(ctx, "org_invite", "usr_invitee"); err != nil {
		t.Fatalf("organization membership missing: %v", err)
	}
	if _, err := store.FindTeamMember(ctx, "team_invite", "usr_invitee"); err != nil {
		t.Fatalf("team membership missing: %v", err)
	}
	invitation, err := store.FindInvitation(ctx, "inv_team")
	if err != nil {
		t.Fatal(err)
	}
	if invitation.Status != "accepted" || invitation.TeamID != "team_invite" {
		t.Fatalf("invitation = %#v, want accepted with team id retained", invitation)
	}
}

// seedTeamFixture creates a user, an organization, an owner membership, and a
// team, all suffixed with the token.
func seedTeamFixture(t *testing.T, store *Store, token string, now time.Time) {
	t.Helper()
	ctx := context.Background()
	seedUser(t, store, "usr_"+token, token+"@example.com", now)
	if err := store.CreateOrganizationWithOwner(ctx, &canopy.Organization{
		ID: "org_" + token, Name: token, Slug: token, CreatedAt: now, UpdatedAt: now,
	}, &canopy.Member{
		ID: "mem_" + token, OrganizationID: "org_" + token, UserID: "usr_" + token,
		Role: "owner", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateTeam(ctx, &canopy.Team{
		ID: "team_" + token, OrganizationID: "org_" + token, Name: token,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
}

func seedUser(t *testing.T, store *Store, id, email string, now time.Time) {
	t.Helper()
	if err := store.CreateUser(context.Background(), &canopy.User{
		ID: id, Name: id, Email: email, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
}

func e2eStore(t *testing.T) (*Store, context.Context) {
	t.Helper()
	raw := os.Getenv("CANOPY_E2E_DATABASE_URL")
	if raw == "" {
		t.Skip("set CANOPY_E2E_DATABASE_URL to run e2e tests")
	}
	admin, err := sql.Open("postgres", raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.Ping(); err != nil {
		t.Fatalf("connect to e2e database: %v", err)
	}
	schema := "canopy_store_e2e_" + randomHex(t, 8)
	if _, err := admin.Exec(`create schema ` + quoteIdent(schema)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(`drop schema if exists ` + quoteIdent(schema) + ` cascade`)
		_ = admin.Close()
	})

	db, err := sql.Open("postgres", withSearchPath(raw, schema))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(4)
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Ping(); err != nil {
		t.Fatalf("connect to e2e schema: %v", err)
	}
	store := New(db)
	if err := store.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return store, context.Background()
}

func withSearchPath(raw, schema string) string {
	if u, err := url.Parse(raw); err == nil && u.Scheme != "" && u.Host != "" {
		q := u.Query()
		q.Set("search_path", schema)
		u.RawQuery = q.Encode()
		return u.String()
	}
	if strings.TrimSpace(raw) == "" {
		return raw
	}
	return raw + " search_path=" + schema
}

func quoteIdent(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
}

func randomHex(t *testing.T, n int) string {
	t.Helper()
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(buf)
}

func TestE2EDeleteTeamClearsPendingInvitationTeam(t *testing.T) {
	store, ctx := e2eStore(t)
	now := time.Now().UTC()
	seedTeamFixture(t, store, "clear", now)
	if err := store.CreateInvitation(ctx, &canopy.Invitation{
		ID: "inv_clear", OrganizationID: "org_clear", Email: "late@example.com",
		Role: "member", Status: "pending", TeamID: "team_clear",
		ExpiresAt: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteTeam(ctx, "org_clear", "team_clear"); err != nil {
		t.Fatal(err)
	}
	seedUser(t, store, "usr_late", "late@example.com", now)
	if err := store.AcceptInvitation(ctx, "inv_clear", "late@example.com", now, &canopy.Member{
		ID: "mem_late", OrganizationID: "org_clear", UserID: "usr_late",
		Role: "member", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("AcceptInvitation() after team delete error = %v", err)
	}
	if _, err := store.FindMember(ctx, "org_clear", "usr_late"); err != nil {
		t.Fatalf("organization membership missing: %v", err)
	}
	if _, err := store.FindTeamMember(ctx, "team_clear", "usr_late"); err != canopy.ErrNotFound {
		t.Fatalf("unexpected team membership after team delete: %v", err)
	}
}

func TestE2ECreateLinkedAccountIsAtomicAndSingleUse(t *testing.T) {
	store, ctx := e2eStore(t)
	now := time.Now().UTC()
	seedUser(t, store, "usr_link", "link@example.com", now)
	verification := &canopy.Verification{
		ID: "alk_link", Identifier: "account_link:usr_link", Value: "state-hash",
		ExpiresAt: now.Add(time.Minute), CreatedAt: now, UpdatedAt: now,
	}
	if err := store.ReplaceVerification(ctx, verification); err != nil {
		t.Fatal(err)
	}

	if err := store.CreateLinkedAccount(ctx, verification.Identifier, verification.Value, now, &canopy.Account{
		ID: "acc_link", UserID: "usr_link", AccountID: "google-sub", ProviderID: "google",
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.FindAccount(ctx, "google", "google-sub"); err != nil {
		t.Fatalf("linked account missing: %v", err)
	}
	if _, err := store.ConsumeVerification(ctx, verification.Identifier, verification.Value, now); !errors.Is(err, canopy.ErrNotFound) {
		t.Fatalf("verification err = %v, want ErrNotFound", err)
	}
	// A replayed token must not create a second account.
	err := store.CreateLinkedAccount(ctx, verification.Identifier, verification.Value, now, &canopy.Account{
		ID: "acc_replay", UserID: "usr_link", AccountID: "google-sub-2", ProviderID: "google-2",
		CreatedAt: now, UpdatedAt: now,
	})
	if !errors.Is(err, canopy.ErrNotFound) {
		t.Fatalf("replayed link err = %v, want ErrNotFound", err)
	}
	if _, err := store.FindAccount(ctx, "google-2", "google-sub-2"); !errors.Is(err, canopy.ErrNotFound) {
		t.Fatalf("replayed account err = %v, want ErrNotFound", err)
	}
}

func TestE2ECreateLinkedAccountKeepsVerificationOnConflict(t *testing.T) {
	store, ctx := e2eStore(t)
	now := time.Now().UTC()
	seedUser(t, store, "usr_taken", "taken@example.com", now)
	seedUser(t, store, "usr_late", "late-link@example.com", now)
	if err := store.CreateAccount(ctx, &canopy.Account{
		ID: "acc_taken", UserID: "usr_taken", AccountID: "google-sub", ProviderID: "google",
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	verification := &canopy.Verification{
		ID: "alk_conflict", Identifier: "account_link:usr_late", Value: "state-hash",
		ExpiresAt: now.Add(time.Minute), CreatedAt: now, UpdatedAt: now,
	}
	if err := store.ReplaceVerification(ctx, verification); err != nil {
		t.Fatal(err)
	}

	err := store.CreateLinkedAccount(ctx, verification.Identifier, verification.Value, now, &canopy.Account{
		ID: "acc_dup", UserID: "usr_late", AccountID: "google-sub", ProviderID: "google",
		CreatedAt: now, UpdatedAt: now,
	})
	if !errors.Is(err, canopy.ErrConflict) {
		t.Fatalf("conflicting link err = %v, want ErrConflict", err)
	}
	// The rollback keeps the one-time token, so the user can retry.
	if _, err := store.ConsumeVerification(ctx, verification.Identifier, verification.Value, now); err != nil {
		t.Fatalf("verification consumed on failed link: %v", err)
	}
}

func TestE2EProtectedRemovalRefusesConcurrentPromotion(t *testing.T) {
	store, ctx := e2eStore(t)
	now := time.Now().UTC()
	seedTeamFixture(t, store, "guard", now)
	seedUser(t, store, "usr_second", "second@example.com", now)
	member := &canopy.Member{
		ID: "mem_second", OrganizationID: "org_guard", UserID: "usr_second",
		Role: "admin", CreatedAt: now, UpdatedAt: now,
	}
	if err := store.CreateMember(ctx, member); err != nil {
		t.Fatal(err)
	}
	// The handler read the role as admin. A promotion commits before the
	// removal reaches the store.
	promoted := *member
	promoted.Role = "owner"
	if err := store.UpdateMemberRole(ctx, &promoted, "owner"); err != nil {
		t.Fatal(err)
	}
	if err := store.RemoveMemberAndClearSessionsProtected(ctx, "org_guard", "usr_second", "owner", now); err != canopy.ErrForbidden {
		t.Fatalf("stale removal error = %v, want ErrForbidden", err)
	}
	if _, err := store.FindMember(ctx, "org_guard", "usr_second"); err != nil {
		t.Fatalf("promoted owner was removed: %v", err)
	}
	// A member below the protected role is still removable.
	if err := store.RemoveMemberAndClearSessionsProtected(ctx, "org_guard", "usr_guard", "nobody", now); err != nil {
		t.Fatalf("unprotected removal error = %v", err)
	}
}
