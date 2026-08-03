package organization_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/ssnxd/canopy"
	"github.com/ssnxd/canopy/organization"
)

type teamFixture struct {
	*fixture
	owner   *http.Cookie
	ownerID string
	org     canopy.Organization
}

func newTeamFixture(t *testing.T) *teamFixture {
	t.Helper()
	f := newFixture(t)
	owner := f.signUp(t, "Ada", "ada@example.com")
	create := f.do(t, http.MethodPost, "/organization/create", map[string]string{"name": "Acme Inc"}, owner)
	if create.Code != http.StatusOK {
		t.Fatalf("create org status = %d, body = %s", create.Code, create.Body.String())
	}
	var org canopy.Organization
	if err := json.NewDecoder(create.Body).Decode(&org); err != nil {
		t.Fatal(err)
	}
	user, err := f.store.FindUserByEmail(context.Background(), "ada@example.com")
	if err != nil {
		t.Fatal(err)
	}
	return &teamFixture{fixture: f, owner: owner, ownerID: user.ID, org: org}
}

// addMember signs a user up, invites them with the role, and accepts the
// invitation. It returns the session cookie and the user id.
func (f *teamFixture) addMember(t *testing.T, name, email, role string) (*http.Cookie, string) {
	t.Helper()
	cookie := f.signUp(t, name, email)
	invite := f.do(t, http.MethodPost, "/organization/invite", map[string]string{
		"organizationId": f.org.ID, "email": email, "role": role,
	}, f.owner)
	if invite.Code != http.StatusOK {
		t.Fatalf("invite status = %d, body = %s", invite.Code, invite.Body.String())
	}
	var invitation canopy.Invitation
	if err := json.NewDecoder(invite.Body).Decode(&invitation); err != nil {
		t.Fatal(err)
	}
	accept := f.do(t, http.MethodPost, "/organization/accept-invitation", map[string]string{"invitationId": invitation.ID}, cookie)
	if accept.Code != http.StatusOK {
		t.Fatalf("accept status = %d, body = %s", accept.Code, accept.Body.String())
	}
	user, err := f.store.FindUserByEmail(context.Background(), email)
	if err != nil {
		t.Fatal(err)
	}
	return cookie, user.ID
}

func (f *teamFixture) createTeam(t *testing.T, name string, cookie *http.Cookie) canopy.Team {
	t.Helper()
	rec := f.do(t, http.MethodPost, "/organization/create-team", map[string]string{
		"organizationId": f.org.ID, "name": name,
	}, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("create team status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var team canopy.Team
	if err := json.NewDecoder(rec.Body).Decode(&team); err != nil {
		t.Fatal(err)
	}
	return team
}

func TestTeamCreateListUpdateDelete(t *testing.T) {
	f := newTeamFixture(t)
	team := f.createTeam(t, "Platform", f.owner)
	if team.OrganizationID != f.org.ID || team.Name != "Platform" {
		t.Fatalf("team = %#v", team)
	}

	list := f.do(t, http.MethodGet, "/organization/list-teams?organizationId="+f.org.ID, nil, f.owner)
	if list.Code != http.StatusOK {
		t.Fatalf("list teams status = %d, body = %s", list.Code, list.Body.String())
	}
	var listBody struct {
		Teams []canopy.Team `json:"teams"`
	}
	if err := json.NewDecoder(list.Body).Decode(&listBody); err != nil {
		t.Fatal(err)
	}
	if len(listBody.Teams) != 1 || listBody.Teams[0].ID != team.ID {
		t.Fatalf("teams = %#v, want the created team", listBody.Teams)
	}

	update := f.do(t, http.MethodPost, "/organization/update-team", map[string]string{
		"organizationId": f.org.ID, "teamId": team.ID, "name": "Platform Core",
	}, f.owner)
	if update.Code != http.StatusOK {
		t.Fatalf("update team status = %d, body = %s", update.Code, update.Body.String())
	}
	stored, err := f.store.FindTeamByID(context.Background(), team.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Name != "Platform Core" {
		t.Fatalf("updated name = %q, want Platform Core", stored.Name)
	}

	remove := f.do(t, http.MethodPost, "/organization/delete-team", map[string]string{
		"organizationId": f.org.ID, "teamId": team.ID,
	}, f.owner)
	if remove.Code != http.StatusOK {
		t.Fatalf("delete team status = %d, body = %s", remove.Code, remove.Body.String())
	}
	if _, err := f.store.FindTeamByID(context.Background(), team.ID); err != canopy.ErrNotFound {
		t.Fatalf("deleted team error = %v, want ErrNotFound", err)
	}
}

func TestTeamMissingTeamReturnsNotFound(t *testing.T) {
	f := newTeamFixture(t)
	update := f.do(t, http.MethodPost, "/organization/update-team", map[string]string{
		"organizationId": f.org.ID, "teamId": "team_missing", "name": "Ghost",
	}, f.owner)
	if update.Code != http.StatusNotFound {
		t.Fatalf("update missing team status = %d, want 404", update.Code)
	}
	remove := f.do(t, http.MethodPost, "/organization/delete-team", map[string]string{
		"organizationId": f.org.ID, "teamId": "team_missing",
	}, f.owner)
	if remove.Code != http.StatusNotFound {
		t.Fatalf("delete missing team status = %d, want 404", remove.Code)
	}
}

func TestTeamAdminCanManageTeams(t *testing.T) {
	f := newTeamFixture(t)
	admin, _ := f.addMember(t, "Grace", "grace@example.com", organization.RoleAdmin)
	_, memberID := f.addMember(t, "Lin", "lin@example.com", organization.RoleMember)

	team := f.createTeam(t, "Ops", admin)
	add := f.do(t, http.MethodPost, "/organization/add-team-member", map[string]string{
		"organizationId": f.org.ID, "teamId": team.ID, "userId": memberID,
	}, admin)
	if add.Code != http.StatusOK {
		t.Fatalf("admin add team member status = %d, body = %s", add.Code, add.Body.String())
	}
	remove := f.do(t, http.MethodPost, "/organization/remove-team-member", map[string]string{
		"organizationId": f.org.ID, "teamId": team.ID, "userId": memberID,
	}, admin)
	if remove.Code != http.StatusOK {
		t.Fatalf("admin remove team member status = %d, body = %s", remove.Code, remove.Body.String())
	}
	del := f.do(t, http.MethodPost, "/organization/delete-team", map[string]string{
		"organizationId": f.org.ID, "teamId": team.ID,
	}, admin)
	if del.Code != http.StatusOK {
		t.Fatalf("admin delete team status = %d, body = %s", del.Code, del.Body.String())
	}
}

func TestTeamMemberRoleCannotManageTeams(t *testing.T) {
	f := newTeamFixture(t)
	member, memberID := f.addMember(t, "Grace", "grace@example.com", organization.RoleMember)
	team := f.createTeam(t, "Ops", f.owner)

	create := f.do(t, http.MethodPost, "/organization/create-team", map[string]string{
		"organizationId": f.org.ID, "name": "Shadow",
	}, member)
	if create.Code != http.StatusForbidden {
		t.Fatalf("member create team status = %d, want 403", create.Code)
	}
	remove := f.do(t, http.MethodPost, "/organization/delete-team", map[string]string{
		"organizationId": f.org.ID, "teamId": team.ID,
	}, member)
	if remove.Code != http.StatusForbidden {
		t.Fatalf("member delete team status = %d, want 403", remove.Code)
	}
	add := f.do(t, http.MethodPost, "/organization/add-team-member", map[string]string{
		"organizationId": f.org.ID, "teamId": team.ID, "userId": memberID,
	}, member)
	if add.Code != http.StatusForbidden {
		t.Fatalf("member add team member status = %d, want 403", add.Code)
	}

	// A member may still view teams.
	list := f.do(t, http.MethodGet, "/organization/list-teams?organizationId="+f.org.ID, nil, member)
	if list.Code != http.StatusOK {
		t.Fatalf("member list teams status = %d, body = %s", list.Code, list.Body.String())
	}
}

func TestTeamNonOrganizationMemberIsRejected(t *testing.T) {
	f := newTeamFixture(t)
	outsider := f.signUp(t, "Eve", "eve@example.com")
	team := f.createTeam(t, "Ops", f.owner)

	list := f.do(t, http.MethodGet, "/organization/list-teams?organizationId="+f.org.ID, nil, outsider)
	if list.Code != http.StatusForbidden {
		t.Fatalf("outsider list teams status = %d, want 403", list.Code)
	}
	create := f.do(t, http.MethodPost, "/organization/create-team", map[string]string{
		"organizationId": f.org.ID, "name": "Shadow",
	}, outsider)
	if create.Code != http.StatusForbidden {
		t.Fatalf("outsider create team status = %d, want 403", create.Code)
	}
	members := f.do(t, http.MethodGet, "/organization/list-team-members?organizationId="+f.org.ID+"&teamId="+team.ID, nil, outsider)
	if members.Code != http.StatusForbidden {
		t.Fatalf("outsider list team members status = %d, want 403", members.Code)
	}
}

func TestTeamMemberManagementAndDuplicates(t *testing.T) {
	f := newTeamFixture(t)
	_, memberID := f.addMember(t, "Grace", "grace@example.com", organization.RoleMember)
	f.signUp(t, "Eve", "eve@example.com")
	outsider, err := f.store.FindUserByEmail(context.Background(), "eve@example.com")
	if err != nil {
		t.Fatal(err)
	}
	team := f.createTeam(t, "Ops", f.owner)

	// A user outside the organization cannot join a team.
	add := f.do(t, http.MethodPost, "/organization/add-team-member", map[string]string{
		"organizationId": f.org.ID, "teamId": team.ID, "userId": outsider.ID,
	}, f.owner)
	if add.Code != http.StatusForbidden {
		t.Fatalf("add outsider status = %d, want 403", add.Code)
	}

	add = f.do(t, http.MethodPost, "/organization/add-team-member", map[string]string{
		"organizationId": f.org.ID, "teamId": team.ID, "userId": memberID,
	}, f.owner)
	if add.Code != http.StatusOK {
		t.Fatalf("add team member status = %d, body = %s", add.Code, add.Body.String())
	}
	duplicate := f.do(t, http.MethodPost, "/organization/add-team-member", map[string]string{
		"organizationId": f.org.ID, "teamId": team.ID, "userId": memberID,
	}, f.owner)
	if duplicate.Code != http.StatusConflict {
		t.Fatalf("duplicate team member status = %d, want 409", duplicate.Code)
	}

	list := f.do(t, http.MethodGet, "/organization/list-team-members?organizationId="+f.org.ID+"&teamId="+team.ID, nil, f.owner)
	if list.Code != http.StatusOK {
		t.Fatalf("list team members status = %d, body = %s", list.Code, list.Body.String())
	}
	var listBody struct {
		TeamMembers []canopy.TeamMember `json:"teamMembers"`
	}
	if err := json.NewDecoder(list.Body).Decode(&listBody); err != nil {
		t.Fatal(err)
	}
	if len(listBody.TeamMembers) != 1 || listBody.TeamMembers[0].UserID != memberID {
		t.Fatalf("team members = %#v, want the added member", listBody.TeamMembers)
	}

	remove := f.do(t, http.MethodPost, "/organization/remove-team-member", map[string]string{
		"organizationId": f.org.ID, "teamId": team.ID, "userId": memberID,
	}, f.owner)
	if remove.Code != http.StatusOK {
		t.Fatalf("remove team member status = %d, body = %s", remove.Code, remove.Body.String())
	}
	if _, err := f.store.FindTeamMember(context.Background(), team.ID, memberID); err != canopy.ErrNotFound {
		t.Fatalf("removed team member error = %v, want ErrNotFound", err)
	}
}

func TestTeamCrossOrganizationIsolation(t *testing.T) {
	f := newTeamFixture(t)
	otherOwner := f.signUp(t, "Mallory", "mallory@example.com")
	otherCreate := f.do(t, http.MethodPost, "/organization/create", map[string]string{"name": "Rival"}, otherOwner)
	var otherOrg canopy.Organization
	if err := json.NewDecoder(otherCreate.Body).Decode(&otherOrg); err != nil {
		t.Fatal(err)
	}
	otherTeam := f.do(t, http.MethodPost, "/organization/create-team", map[string]string{
		"organizationId": otherOrg.ID, "name": "Rival Team",
	}, otherOwner)
	var foreign canopy.Team
	if err := json.NewDecoder(otherTeam.Body).Decode(&foreign); err != nil {
		t.Fatal(err)
	}

	// A foreign team id must read as not found in this organization.
	update := f.do(t, http.MethodPost, "/organization/update-team", map[string]string{
		"organizationId": f.org.ID, "teamId": foreign.ID, "name": "Taken",
	}, f.owner)
	if update.Code != http.StatusNotFound {
		t.Fatalf("cross-org update status = %d, want 404", update.Code)
	}
	remove := f.do(t, http.MethodPost, "/organization/delete-team", map[string]string{
		"organizationId": f.org.ID, "teamId": foreign.ID,
	}, f.owner)
	if remove.Code != http.StatusNotFound {
		t.Fatalf("cross-org delete status = %d, want 404", remove.Code)
	}
	add := f.do(t, http.MethodPost, "/organization/add-team-member", map[string]string{
		"organizationId": f.org.ID, "teamId": foreign.ID, "userId": f.ownerID,
	}, f.owner)
	if add.Code != http.StatusNotFound {
		t.Fatalf("cross-org add member status = %d, want 404", add.Code)
	}
	list := f.do(t, http.MethodGet, "/organization/list-team-members?organizationId="+f.org.ID+"&teamId="+foreign.ID, nil, f.owner)
	if list.Code != http.StatusNotFound {
		t.Fatalf("cross-org list members status = %d, want 404", list.Code)
	}
	if _, err := f.store.FindTeamByID(context.Background(), foreign.ID); err != nil {
		t.Fatalf("foreign team was mutated: %v", err)
	}
}

func TestTeamInvitationAssignsTeamOnAcceptance(t *testing.T) {
	f := newTeamFixture(t)
	team := f.createTeam(t, "Ops", f.owner)
	invitee := f.signUp(t, "Grace", "grace@example.com")

	invite := f.do(t, http.MethodPost, "/organization/invite", map[string]string{
		"organizationId": f.org.ID, "email": "grace@example.com",
		"role": organization.RoleMember, "teamId": team.ID,
	}, f.owner)
	if invite.Code != http.StatusOK {
		t.Fatalf("invite status = %d, body = %s", invite.Code, invite.Body.String())
	}
	var invitation canopy.Invitation
	if err := json.NewDecoder(invite.Body).Decode(&invitation); err != nil {
		t.Fatal(err)
	}
	if invitation.TeamID != team.ID {
		t.Fatalf("invitation team id = %q, want %q", invitation.TeamID, team.ID)
	}

	accept := f.do(t, http.MethodPost, "/organization/accept-invitation", map[string]string{"invitationId": invitation.ID}, invitee)
	if accept.Code != http.StatusOK {
		t.Fatalf("accept status = %d, body = %s", accept.Code, accept.Body.String())
	}
	user, err := f.store.FindUserByEmail(context.Background(), "grace@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.FindMember(context.Background(), f.org.ID, user.ID); err != nil {
		t.Fatalf("organization membership missing: %v", err)
	}
	if _, err := f.store.FindTeamMember(context.Background(), team.ID, user.ID); err != nil {
		t.Fatalf("team membership missing: %v", err)
	}
}

func TestTeamInvitationRejectsForeignTeam(t *testing.T) {
	f := newTeamFixture(t)
	otherOwner := f.signUp(t, "Mallory", "mallory@example.com")
	otherCreate := f.do(t, http.MethodPost, "/organization/create", map[string]string{"name": "Rival"}, otherOwner)
	var otherOrg canopy.Organization
	if err := json.NewDecoder(otherCreate.Body).Decode(&otherOrg); err != nil {
		t.Fatal(err)
	}
	otherTeam := f.do(t, http.MethodPost, "/organization/create-team", map[string]string{
		"organizationId": otherOrg.ID, "name": "Rival Team",
	}, otherOwner)
	var foreign canopy.Team
	if err := json.NewDecoder(otherTeam.Body).Decode(&foreign); err != nil {
		t.Fatal(err)
	}

	invite := f.do(t, http.MethodPost, "/organization/invite", map[string]string{
		"organizationId": f.org.ID, "email": "grace@example.com",
		"role": organization.RoleMember, "teamId": foreign.ID,
	}, f.owner)
	if invite.Code != http.StatusNotFound {
		t.Fatalf("foreign-team invite status = %d, want 404", invite.Code)
	}
}

func TestTeamMembershipRemovedWithOrganizationMember(t *testing.T) {
	f := newTeamFixture(t)
	_, memberID := f.addMember(t, "Grace", "grace@example.com", organization.RoleMember)
	team := f.createTeam(t, "Ops", f.owner)
	add := f.do(t, http.MethodPost, "/organization/add-team-member", map[string]string{
		"organizationId": f.org.ID, "teamId": team.ID, "userId": memberID,
	}, f.owner)
	if add.Code != http.StatusOK {
		t.Fatalf("add team member status = %d, body = %s", add.Code, add.Body.String())
	}

	remove := f.do(t, http.MethodPost, "/organization/remove-member", map[string]string{
		"organizationId": f.org.ID, "userId": memberID,
	}, f.owner)
	if remove.Code != http.StatusOK {
		t.Fatalf("remove member status = %d, body = %s", remove.Code, remove.Body.String())
	}
	if _, err := f.store.FindTeamMember(context.Background(), team.ID, memberID); err != canopy.ErrNotFound {
		t.Fatalf("team membership survived member removal: %v", err)
	}
}

func TestTeamDeletionRemovesTeamMembers(t *testing.T) {
	f := newTeamFixture(t)
	_, memberID := f.addMember(t, "Grace", "grace@example.com", organization.RoleMember)
	team := f.createTeam(t, "Ops", f.owner)
	add := f.do(t, http.MethodPost, "/organization/add-team-member", map[string]string{
		"organizationId": f.org.ID, "teamId": team.ID, "userId": memberID,
	}, f.owner)
	if add.Code != http.StatusOK {
		t.Fatalf("add team member status = %d, body = %s", add.Code, add.Body.String())
	}

	remove := f.do(t, http.MethodPost, "/organization/delete-team", map[string]string{
		"organizationId": f.org.ID, "teamId": team.ID,
	}, f.owner)
	if remove.Code != http.StatusOK {
		t.Fatalf("delete team status = %d, body = %s", remove.Code, remove.Body.String())
	}
	if _, err := f.store.FindTeamMember(context.Background(), team.ID, memberID); err != canopy.ErrNotFound {
		t.Fatalf("team membership survived team deletion: %v", err)
	}
}
