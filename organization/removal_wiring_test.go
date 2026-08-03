package organization_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/ssnxd/canopy"
	"github.com/ssnxd/canopy/organization"
	"github.com/ssnxd/canopy/store/memory"
)

// racingStore reports a stale role for one member. It reproduces the state
// that the handler sees when a promotion commits after the handler read the
// role. The stored record still holds the real role, so only a store that
// re-checks the role inside its own transaction can refuse the removal.
type racingStore struct {
	*memory.Store
	staleUser string
	staleRole string
}

func (s *racingStore) FindMember(ctx context.Context, orgID, userID string) (*canopy.Member, error) {
	member, err := s.Store.FindMember(ctx, orgID, userID)
	if err != nil {
		return nil, err
	}
	if userID == s.staleUser {
		stale := *member
		stale.Role = s.staleRole
		return &stale, nil
	}
	return member, nil
}

// The remove-member handler must use ProtectedMemberRemovalStore. A stale
// role read must not allow the removal of an owner.
func TestRemoveMemberUsesProtectedCapability(t *testing.T) {
	base := memory.New()
	store := &racingStore{Store: base}
	auth, err := canopy.New(canopy.Config{
		Store:   store,
		Secret:  "dev-secret-with-enough-test-entropy",
		Modules: []canopy.Module{organization.New(organization.Options{})},
	})
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{handler: auth.Handler(), store: base}

	owner := f.signUp(t, "Ada", "ada@example.com")
	f.signUp(t, "Grace", "grace@example.com")
	grace, err := base.FindUserByEmail(context.Background(), "grace@example.com")
	if err != nil {
		t.Fatal(err)
	}

	create := f.do(t, http.MethodPost, "/organization/create", map[string]string{"name": "Acme"}, owner)
	if create.Code != http.StatusOK {
		t.Fatalf("create status = %d, body = %s", create.Code, create.Body.String())
	}
	var org canopy.Organization
	if err := json.NewDecoder(create.Body).Decode(&org); err != nil {
		t.Fatal(err)
	}

	// Grace holds the owner role in storage.
	now := time.Now().UTC()
	if err := base.CreateMember(context.Background(), &canopy.Member{
		ID: "mem_grace", OrganizationID: org.ID, UserID: grace.ID,
		Role: organization.RoleOwner, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	// The handler reads a stale admin role, as it would after a promotion
	// committed between the read and the removal.
	store.staleUser = grace.ID
	store.staleRole = organization.RoleAdmin

	remove := f.do(t, http.MethodPost, "/organization/remove-member", map[string]string{
		"organizationId": org.ID, "userId": grace.ID,
	}, owner)
	if remove.Code != http.StatusForbidden {
		t.Fatalf("remove status = %d, want 403; the handler must use ProtectedMemberRemovalStore", remove.Code)
	}
	if _, err := base.FindMember(context.Background(), org.ID, grace.ID); err != nil {
		t.Fatalf("owner was removed through a stale role read: %v", err)
	}
}
