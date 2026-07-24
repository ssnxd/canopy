package organization_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ssnxd/canopy"
	"github.com/ssnxd/canopy/organization"
	"github.com/ssnxd/canopy/store/memory"
)

type fixture struct {
	handler http.Handler
	store   *memory.Store
}

func newFixture(t *testing.T) *fixture {
	return newFixtureWithOptions(t, organization.Options{})
}

func newFixtureWithOptions(t *testing.T, options organization.Options) *fixture {
	t.Helper()
	store := memory.New()
	auth, err := canopy.New(canopy.Config{
		Store:   store,
		Secret:  "dev-secret-with-enough-test-entropy",
		Modules: []canopy.Module{organization.New(options)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{handler: auth.Handler(), store: store}
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
	user, err := f.store.FindUserByEmail(context.Background(), email)
	if err != nil {
		t.Fatal(err)
	}
	user.EmailVerified = true
	if err := f.store.UpdateUser(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "canopy.session_token" {
			return c
		}
	}
	t.Fatal("no session cookie")
	return nil
}

func TestOrganizationInviteAcceptAndRBAC(t *testing.T) {
	f := newFixture(t)
	owner := f.signUp(t, "Ada", "ada@example.com")
	invitee := f.signUp(t, "Grace", "grace@example.com")

	// Create an organization; the creator becomes the owner.
	create := f.do(t, http.MethodPost, "/organization/create", map[string]string{"name": "Acme Inc"}, owner)
	if create.Code != http.StatusOK {
		t.Fatalf("create status = %d, body = %s", create.Code, create.Body.String())
	}
	var org canopy.Organization
	if err := json.NewDecoder(create.Body).Decode(&org); err != nil {
		t.Fatal(err)
	}
	if org.Slug != "acme-inc" {
		t.Fatalf("slug = %q, want acme-inc", org.Slug)
	}

	// A non-member cannot set it active.
	setActive := f.do(t, http.MethodPost, "/organization/set-active", map[string]string{"organizationId": org.ID}, invitee)
	if setActive.Code != http.StatusForbidden {
		t.Fatalf("non-member set-active status = %d, want 403", setActive.Code)
	}

	// The owner invites the second user.
	invite := f.do(t, http.MethodPost, "/organization/invite", map[string]string{
		"organizationId": org.ID, "email": "grace@example.com", "role": organization.RoleMember,
	}, owner)
	if invite.Code != http.StatusOK {
		t.Fatalf("invite status = %d, body = %s", invite.Code, invite.Body.String())
	}
	var invitation canopy.Invitation
	if err := json.NewDecoder(invite.Body).Decode(&invitation); err != nil {
		t.Fatal(err)
	}

	// The invitee accepts.
	accept := f.do(t, http.MethodPost, "/organization/accept-invitation", map[string]string{"invitationId": invitation.ID}, invitee)
	if accept.Code != http.StatusOK {
		t.Fatalf("accept status = %d, body = %s", accept.Code, accept.Body.String())
	}

	// The invitee is now a member and can set the organization active.
	setActive = f.do(t, http.MethodPost, "/organization/set-active", map[string]string{"organizationId": org.ID}, invitee)
	if setActive.Code != http.StatusOK {
		t.Fatalf("member set-active status = %d, body = %s", setActive.Code, setActive.Body.String())
	}

	// A member cannot invite; that needs the invite permission.
	memberInvite := f.do(t, http.MethodPost, "/organization/invite", map[string]string{
		"organizationId": org.ID, "email": "eve@example.com", "role": organization.RoleMember,
	}, invitee)
	if memberInvite.Code != http.StatusForbidden {
		t.Fatalf("member invite status = %d, want 403", memberInvite.Code)
	}

	// The owner sees two members.
	members := f.do(t, http.MethodGet, "/organization/members?organizationId="+org.ID, nil, owner)
	if members.Code != http.StatusOK {
		t.Fatalf("members status = %d, body = %s", members.Code, members.Body.String())
	}
	var membersBody struct {
		Members []canopy.Member `json:"members"`
	}
	if err := json.NewDecoder(members.Body).Decode(&membersBody); err != nil {
		t.Fatal(err)
	}
	if len(membersBody.Members) != 2 {
		t.Fatalf("members = %d, want 2", len(membersBody.Members))
	}

	// The owner removes the member.
	removedUserID := memberUserID(t, membersBody.Members, organization.RoleMember)
	remove := f.do(t, http.MethodPost, "/organization/remove-member", map[string]string{
		"organizationId": org.ID, "userId": removedUserID,
	}, owner)
	if remove.Code != http.StatusOK {
		t.Fatalf("remove status = %d, body = %s", remove.Code, remove.Body.String())
	}
	session := f.do(t, http.MethodGet, "/get-session", nil, invitee)
	var sessionData canopy.SessionData
	if err := json.NewDecoder(session.Body).Decode(&sessionData); err != nil {
		t.Fatal(err)
	}
	if sessionData.Session.ActiveOrganizationID != "" {
		t.Fatalf("removed member retained active organization %q", sessionData.Session.ActiveOrganizationID)
	}

	// Session validation also protects membership changes made outside the
	// module route.
	now := time.Now().UTC()
	if err := f.store.CreateMember(context.Background(), &canopy.Member{
		ID: "mem_external", OrganizationID: org.ID, UserID: removedUserID,
		Role: organization.RoleMember, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	setActive = f.do(t, http.MethodPost, "/organization/set-active", map[string]string{"organizationId": org.ID}, invitee)
	if setActive.Code != http.StatusOK {
		t.Fatalf("reset active status = %d, body = %s", setActive.Code, setActive.Body.String())
	}
	if err := f.store.DeleteMember(context.Background(), org.ID, removedUserID); err != nil {
		t.Fatal(err)
	}
	session = f.do(t, http.MethodGet, "/get-session", nil, invitee)
	if err := json.NewDecoder(session.Body).Decode(&sessionData); err != nil {
		t.Fatal(err)
	}
	if sessionData.Session.ActiveOrganizationID != "" {
		t.Fatalf("session validator retained stale organization %q", sessionData.Session.ActiveOrganizationID)
	}
}

func TestOrganizationOwnerCannotBeRemoved(t *testing.T) {
	f := newFixture(t)
	owner := f.signUp(t, "Ada", "ada@example.com")
	create := f.do(t, http.MethodPost, "/organization/create", map[string]string{"name": "Acme"}, owner)
	var org canopy.Organization
	if err := json.NewDecoder(create.Body).Decode(&org); err != nil {
		t.Fatal(err)
	}
	list := f.do(t, http.MethodGet, "/organization/members?organizationId="+org.ID, nil, owner)
	var body struct {
		Members []canopy.Member `json:"members"`
	}
	if err := json.NewDecoder(list.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	remove := f.do(t, http.MethodPost, "/organization/remove-member", map[string]string{
		"organizationId": org.ID, "userId": body.Members[0].UserID,
	}, owner)
	if remove.Code != http.StatusForbidden {
		t.Fatalf("remove owner status = %d, want 403", remove.Code)
	}
}

func TestOrganizationMustRetainAnOwner(t *testing.T) {
	f := newFixture(t)
	ownerCookie := f.signUp(t, "Ada", "ada@example.com")
	owner, err := f.store.FindUserByEmail(context.Background(), "ada@example.com")
	if err != nil {
		t.Fatal(err)
	}
	create := f.do(t, http.MethodPost, "/organization/create", map[string]string{"name": "Acme"}, ownerCookie)
	var org canopy.Organization
	if err := json.NewDecoder(create.Body).Decode(&org); err != nil {
		t.Fatal(err)
	}
	demote := f.do(t, http.MethodPost, "/organization/update-member-role", map[string]string{
		"organizationId": org.ID, "userId": owner.ID, "role": organization.RoleMember,
	}, ownerCookie)
	if demote.Code != http.StatusConflict {
		t.Fatalf("last-owner demotion status = %d, want 409 (body=%s)", demote.Code, demote.Body.String())
	}
	member, err := f.store.FindMember(context.Background(), org.ID, owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	if member.Role != organization.RoleOwner {
		t.Fatalf("role after rejected demotion = %q, want owner", member.Role)
	}
}

func TestOrganizationAllowsExplicitCustomRoles(t *testing.T) {
	f := newFixtureWithOptions(t, organization.Options{AssignableRoles: []string{"billing"}})
	owner := f.signUp(t, "Ada", "ada@example.com")
	create := f.do(t, http.MethodPost, "/organization/create", map[string]string{"name": "Acme"}, owner)
	var org canopy.Organization
	if err := json.NewDecoder(create.Body).Decode(&org); err != nil {
		t.Fatal(err)
	}
	invite := f.do(t, http.MethodPost, "/organization/invite", map[string]string{
		"organizationId": org.ID, "email": "billing@example.com", "role": "billing",
	}, owner)
	if invite.Code != http.StatusOK {
		t.Fatalf("custom-role invite status = %d, body = %s", invite.Code, invite.Body.String())
	}
	rejected := f.do(t, http.MethodPost, "/organization/invite", map[string]string{
		"organizationId": org.ID, "email": "member@example.com", "role": organization.RoleMember,
	}, owner)
	if rejected.Code != http.StatusBadRequest {
		t.Fatalf("unconfigured-role invite status = %d, want 400", rejected.Code)
	}
}

func TestOrganizationInvitationRequiresVerifiedEmail(t *testing.T) {
	f := newFixture(t)
	owner := f.signUp(t, "Ada", "ada@example.com")
	invitee := f.signUp(t, "Grace", "grace@example.com")

	create := f.do(t, http.MethodPost, "/organization/create", map[string]string{"name": "Acme"}, owner)
	var org canopy.Organization
	if err := json.NewDecoder(create.Body).Decode(&org); err != nil {
		t.Fatal(err)
	}
	invite := f.do(t, http.MethodPost, "/organization/invite", map[string]string{
		"organizationId": org.ID, "email": "grace@example.com", "role": organization.RoleMember,
	}, owner)
	var invitation canopy.Invitation
	if err := json.NewDecoder(invite.Body).Decode(&invitation); err != nil {
		t.Fatal(err)
	}
	user, err := f.store.FindUserByEmail(context.Background(), "grace@example.com")
	if err != nil {
		t.Fatal(err)
	}
	user.EmailVerified = false
	if err := f.store.UpdateUser(context.Background(), user); err != nil {
		t.Fatal(err)
	}

	accept := f.do(t, http.MethodPost, "/organization/accept-invitation", map[string]string{"invitationId": invitation.ID}, invitee)
	if accept.Code != http.StatusForbidden {
		t.Fatalf("unverified invitation status = %d, want 403", accept.Code)
	}
}

func TestOrganizationDuplicateSlugIsRejected(t *testing.T) {
	f := newFixture(t)
	owner := f.signUp(t, "Ada", "ada@example.com")
	first := f.do(t, http.MethodPost, "/organization/create", map[string]string{"name": "Acme", "slug": "acme"}, owner)
	if first.Code != http.StatusOK {
		t.Fatalf("first create status = %d", first.Code)
	}
	second := f.do(t, http.MethodPost, "/organization/create", map[string]string{"name": "Acme Two", "slug": "acme"}, owner)
	if second.Code != http.StatusConflict {
		t.Fatalf("duplicate slug status = %d, want 409", second.Code)
	}
}

func memberUserID(t *testing.T, members []canopy.Member, role string) string {
	t.Helper()
	for _, m := range members {
		if m.Role == role {
			return m.UserID
		}
	}
	t.Fatalf("no member with role %q", role)
	return ""
}
