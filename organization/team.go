package organization

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/ssnxd/canopy"
)

func (m *Module) handleCreateTeam(w http.ResponseWriter, r *http.Request) {
	data, ok := canopy.SessionFromContext(r.Context())
	if !ok {
		canopy.WriteError(w, canopy.ErrUnauthorized)
		return
	}
	var req struct {
		OrganizationID string `json:"organizationId"`
		Name           string `json:"name"`
	}
	if !canopy.DecodeJSON(w, r, &req) {
		return
	}
	if _, err := m.authorize(r.Context(), req.OrganizationID, data.User.ID, PermissionCreateTeam); err != nil {
		canopy.WriteError(w, err)
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		canopy.WriteError(w, canopy.ErrInvalidInput)
		return
	}
	now := time.Now().UTC()
	teamID, err := newID("team")
	if err != nil {
		canopy.WriteError(w, err)
		return
	}
	team := &canopy.Team{ID: teamID, OrganizationID: req.OrganizationID, Name: name, CreatedAt: now, UpdatedAt: now}
	if err := m.store.CreateTeam(r.Context(), team); err != nil {
		canopy.WriteError(w, err)
		return
	}
	m.core.Audit(r.Context(), canopy.AuditEvent{Type: "organization.team.created", UserID: data.User.ID, Success: true})
	canopy.WriteJSON(w, http.StatusOK, team)
}

func (m *Module) handleListTeams(w http.ResponseWriter, r *http.Request) {
	data, ok := canopy.SessionFromContext(r.Context())
	if !ok {
		canopy.WriteError(w, canopy.ErrUnauthorized)
		return
	}
	orgID := r.URL.Query().Get("organizationId")
	if _, err := m.authorize(r.Context(), orgID, data.User.ID, PermissionViewTeams); err != nil {
		canopy.WriteError(w, err)
		return
	}
	teams, err := m.store.ListTeamsForOrg(r.Context(), orgID)
	if err != nil {
		canopy.WriteError(w, err)
		return
	}
	canopy.WriteJSON(w, http.StatusOK, map[string]any{"teams": teams})
}

func (m *Module) handleUpdateTeam(w http.ResponseWriter, r *http.Request) {
	data, ok := canopy.SessionFromContext(r.Context())
	if !ok {
		canopy.WriteError(w, canopy.ErrUnauthorized)
		return
	}
	var req struct {
		OrganizationID string `json:"organizationId"`
		TeamID         string `json:"teamId"`
		Name           string `json:"name"`
	}
	if !canopy.DecodeJSON(w, r, &req) {
		return
	}
	if _, err := m.authorize(r.Context(), req.OrganizationID, data.User.ID, PermissionUpdateTeam); err != nil {
		canopy.WriteError(w, err)
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		canopy.WriteError(w, canopy.ErrInvalidInput)
		return
	}
	team, err := m.teamInOrganization(r.Context(), req.OrganizationID, req.TeamID)
	if err != nil {
		canopy.WriteError(w, err)
		return
	}
	team.Name = name
	team.UpdatedAt = time.Now().UTC()
	if err := m.store.UpdateTeam(r.Context(), team); err != nil {
		canopy.WriteError(w, err)
		return
	}
	canopy.WriteJSON(w, http.StatusOK, team)
}

func (m *Module) handleDeleteTeam(w http.ResponseWriter, r *http.Request) {
	data, ok := canopy.SessionFromContext(r.Context())
	if !ok {
		canopy.WriteError(w, canopy.ErrUnauthorized)
		return
	}
	var req struct {
		OrganizationID string `json:"organizationId"`
		TeamID         string `json:"teamId"`
	}
	if !canopy.DecodeJSON(w, r, &req) {
		return
	}
	if _, err := m.authorize(r.Context(), req.OrganizationID, data.User.ID, PermissionDeleteTeam); err != nil {
		canopy.WriteError(w, err)
		return
	}
	if err := m.store.DeleteTeam(r.Context(), req.OrganizationID, req.TeamID); err != nil {
		if errors.Is(err, canopy.ErrNotFound) {
			canopy.WriteError(w, canopy.ErrTeamNotFound)
		} else {
			canopy.WriteError(w, err)
		}
		return
	}
	m.core.Audit(r.Context(), canopy.AuditEvent{Type: "organization.team.deleted", UserID: data.User.ID, Success: true})
	canopy.WriteJSON(w, http.StatusOK, map[string]bool{"success": true})
}

func (m *Module) handleAddTeamMember(w http.ResponseWriter, r *http.Request) {
	data, ok := canopy.SessionFromContext(r.Context())
	if !ok {
		canopy.WriteError(w, canopy.ErrUnauthorized)
		return
	}
	var req struct {
		OrganizationID string `json:"organizationId"`
		TeamID         string `json:"teamId"`
		UserID         string `json:"userId"`
	}
	if !canopy.DecodeJSON(w, r, &req) {
		return
	}
	if _, err := m.authorize(r.Context(), req.OrganizationID, data.User.ID, PermissionManageTeamMembers); err != nil {
		canopy.WriteError(w, err)
		return
	}
	team, err := m.teamInOrganization(r.Context(), req.OrganizationID, req.TeamID)
	if err != nil {
		canopy.WriteError(w, err)
		return
	}
	if _, err := m.store.FindMember(r.Context(), req.OrganizationID, req.UserID); err != nil {
		canopy.WriteError(w, canopy.ErrNotOrganizationMember)
		return
	}
	if _, err := m.store.FindTeamMember(r.Context(), team.ID, req.UserID); err == nil {
		canopy.WriteError(w, canopy.ErrConflict)
		return
	}
	now := time.Now().UTC()
	teamMemberID, err := newID("tmem")
	if err != nil {
		canopy.WriteError(w, err)
		return
	}
	teamMember := &canopy.TeamMember{
		ID: teamMemberID, TeamID: team.ID, OrganizationID: req.OrganizationID,
		UserID: req.UserID, CreatedAt: now,
	}
	if err := m.store.AddTeamMember(r.Context(), teamMember); err != nil {
		canopy.WriteError(w, err)
		return
	}
	m.core.Audit(r.Context(), canopy.AuditEvent{Type: "organization.team.member.added", UserID: data.User.ID, Success: true})
	canopy.WriteJSON(w, http.StatusOK, teamMember)
}

func (m *Module) handleRemoveTeamMember(w http.ResponseWriter, r *http.Request) {
	data, ok := canopy.SessionFromContext(r.Context())
	if !ok {
		canopy.WriteError(w, canopy.ErrUnauthorized)
		return
	}
	var req struct {
		OrganizationID string `json:"organizationId"`
		TeamID         string `json:"teamId"`
		UserID         string `json:"userId"`
	}
	if !canopy.DecodeJSON(w, r, &req) {
		return
	}
	if _, err := m.authorize(r.Context(), req.OrganizationID, data.User.ID, PermissionManageTeamMembers); err != nil {
		canopy.WriteError(w, err)
		return
	}
	team, err := m.teamInOrganization(r.Context(), req.OrganizationID, req.TeamID)
	if err != nil {
		canopy.WriteError(w, err)
		return
	}
	if err := m.store.RemoveTeamMember(r.Context(), team.ID, req.UserID); err != nil {
		canopy.WriteError(w, err)
		return
	}
	m.core.Audit(r.Context(), canopy.AuditEvent{Type: "organization.team.member.removed", UserID: data.User.ID, Success: true})
	canopy.WriteJSON(w, http.StatusOK, map[string]bool{"success": true})
}

func (m *Module) handleListTeamMembers(w http.ResponseWriter, r *http.Request) {
	data, ok := canopy.SessionFromContext(r.Context())
	if !ok {
		canopy.WriteError(w, canopy.ErrUnauthorized)
		return
	}
	orgID := r.URL.Query().Get("organizationId")
	teamID := r.URL.Query().Get("teamId")
	if _, err := m.authorize(r.Context(), orgID, data.User.ID, PermissionViewTeams); err != nil {
		canopy.WriteError(w, err)
		return
	}
	team, err := m.teamInOrganization(r.Context(), orgID, teamID)
	if err != nil {
		canopy.WriteError(w, err)
		return
	}
	teamMembers, err := m.store.ListTeamMembers(r.Context(), team.ID)
	if err != nil {
		canopy.WriteError(w, err)
		return
	}
	canopy.WriteJSON(w, http.StatusOK, map[string]any{"teamMembers": teamMembers})
}

// teamInOrganization loads a team and confirms it belongs to the
// organization. A missing or foreign team is reported as not found so a
// team id does not leak across tenants.
func (m *Module) teamInOrganization(ctx context.Context, orgID, teamID string) (*canopy.Team, error) {
	if teamID == "" {
		return nil, canopy.ErrInvalidInput
	}
	team, err := m.store.FindTeamByID(ctx, teamID)
	if err != nil || team.OrganizationID != orgID {
		return nil, canopy.ErrTeamNotFound
	}
	return team, nil
}
