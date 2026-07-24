package organization

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ssnxd/canopy"
)

const moduleID = "organization"

// Options configures the organization module.
type Options struct {
	Authorizer        Authorizer    // default: DefaultAuthorizer
	InvitationTTL     time.Duration // default: 7 days
	DisableUserCreate bool          // block organization creation by ordinary users
}

// Module adds organizations, members, roles, and invitations. It
// implements canopy.Module, canopy.RouteModule, and canopy.SessionValidator.
type Module struct {
	authorizer        Authorizer
	invitationTTL     time.Duration
	disableUserCreate bool

	core  canopy.Core
	store canopy.OrganizationStore
}

// New returns an organization module.
func New(o Options) *Module {
	return &Module{
		authorizer:        o.Authorizer,
		invitationTTL:     o.InvitationTTL,
		disableUserCreate: o.DisableUserCreate,
	}
}

func (m *Module) ID() string { return moduleID }

func (m *Module) Init(core canopy.Core) error {
	store, ok := core.Store().(canopy.OrganizationStore)
	if !ok {
		return fmt.Errorf("organization: store does not implement canopy.OrganizationStore")
	}
	m.core = core
	m.store = store
	if m.authorizer == nil {
		m.authorizer = DefaultAuthorizer()
	}
	if m.invitationTTL == 0 {
		m.invitationTTL = 7 * 24 * time.Hour
	}
	return nil
}

func (m *Module) Routes() []canopy.Route {
	return []canopy.Route{
		{Method: http.MethodPost, Pattern: "/organization/create", RequireSession: true, Handler: http.HandlerFunc(m.handleCreate)},
		{Method: http.MethodGet, Pattern: "/organization/list", RequireSession: true, Handler: http.HandlerFunc(m.handleList)},
		{Method: http.MethodPost, Pattern: "/organization/set-active", RequireSession: true, Handler: http.HandlerFunc(m.handleSetActive)},
		{Method: http.MethodPost, Pattern: "/organization/invite", RequireSession: true, Handler: http.HandlerFunc(m.handleInvite)},
		{Method: http.MethodPost, Pattern: "/organization/accept-invitation", RequireSession: true, Handler: http.HandlerFunc(m.handleAcceptInvitation)},
		{Method: http.MethodGet, Pattern: "/organization/members", RequireSession: true, Handler: http.HandlerFunc(m.handleListMembers)},
		{Method: http.MethodPost, Pattern: "/organization/update-member-role", RequireSession: true, Handler: http.HandlerFunc(m.handleUpdateMemberRole)},
		{Method: http.MethodPost, Pattern: "/organization/remove-member", RequireSession: true, Handler: http.HandlerFunc(m.handleRemoveMember)},
	}
}

// ValidateSession clears an active organization when the session user is no
// longer a member. ActiveOrganizationID is session preference state, not an
// authorization decision.
func (m *Module) ValidateSession(ctx context.Context, data *canopy.SessionData) error {
	orgID := data.Session.ActiveOrganizationID
	if orgID == "" {
		return nil
	}
	if _, err := m.store.FindMember(ctx, orgID, data.User.ID); err == nil {
		return nil
	} else if !errors.Is(err, canopy.ErrNotFound) {
		return err
	}
	data.Session.ActiveOrganizationID = ""
	data.Session.UpdatedAt = time.Now().UTC()
	return m.core.Store().UpdateSession(ctx, &data.Session)
}

func (m *Module) handleCreate(w http.ResponseWriter, r *http.Request) {
	data, ok := canopy.SessionFromContext(r.Context())
	if !ok {
		canopy.WriteError(w, canopy.ErrUnauthorized)
		return
	}
	if m.disableUserCreate {
		canopy.WriteError(w, canopy.ErrForbidden)
		return
	}
	var req struct {
		Name string `json:"name"`
		Slug string `json:"slug"`
	}
	if !canopy.DecodeJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		canopy.WriteError(w, canopy.ErrInvalidInput)
		return
	}
	slug := slugify(req.Slug)
	if slug == "" {
		slug = slugify(req.Name)
	}
	if slug == "" {
		canopy.WriteError(w, canopy.ErrInvalidInput)
		return
	}
	if _, err := m.store.FindOrganizationBySlug(r.Context(), slug); err == nil {
		canopy.WriteError(w, canopy.ErrConflict)
		return
	}
	now := time.Now().UTC()
	orgID, err := newID("org")
	if err != nil {
		canopy.WriteError(w, err)
		return
	}
	org := &canopy.Organization{ID: orgID, Name: strings.TrimSpace(req.Name), Slug: slug, CreatedAt: now, UpdatedAt: now}
	if err := m.store.CreateOrganization(r.Context(), org); err != nil {
		canopy.WriteError(w, err)
		return
	}
	memberID, err := newID("mem")
	if err != nil {
		canopy.WriteError(w, err)
		return
	}
	if err := m.store.CreateMember(r.Context(), &canopy.Member{
		ID: memberID, OrganizationID: org.ID, UserID: data.User.ID, Role: RoleOwner, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		canopy.WriteError(w, err)
		return
	}
	m.core.Audit(r.Context(), canopy.AuditEvent{Type: "organization.created", UserID: data.User.ID, Success: true})
	canopy.WriteJSON(w, http.StatusOK, org)
}

func (m *Module) handleList(w http.ResponseWriter, r *http.Request) {
	data, ok := canopy.SessionFromContext(r.Context())
	if !ok {
		canopy.WriteError(w, canopy.ErrUnauthorized)
		return
	}
	orgs, err := m.store.ListOrganizationsForUser(r.Context(), data.User.ID)
	if err != nil {
		canopy.WriteError(w, err)
		return
	}
	canopy.WriteJSON(w, http.StatusOK, map[string]any{"organizations": orgs})
}

func (m *Module) handleSetActive(w http.ResponseWriter, r *http.Request) {
	data, ok := canopy.SessionFromContext(r.Context())
	if !ok {
		canopy.WriteError(w, canopy.ErrUnauthorized)
		return
	}
	var req struct {
		OrganizationID string `json:"organizationId"`
	}
	if !canopy.DecodeJSON(w, r, &req) {
		return
	}
	member, err := m.store.FindMember(r.Context(), req.OrganizationID, data.User.ID)
	if err != nil {
		canopy.WriteError(w, canopy.ErrNotOrganizationMember)
		return
	}
	session := data.Session
	session.ActiveOrganizationID = req.OrganizationID
	session.UpdatedAt = time.Now().UTC()
	if err := m.core.Store().UpdateSession(r.Context(), &session); err != nil {
		canopy.WriteError(w, err)
		return
	}
	canopy.WriteJSON(w, http.StatusOK, map[string]any{
		"activeOrganizationId": req.OrganizationID,
		"role":                 member.Role,
	})
}

func (m *Module) handleInvite(w http.ResponseWriter, r *http.Request) {
	data, ok := canopy.SessionFromContext(r.Context())
	if !ok {
		canopy.WriteError(w, canopy.ErrUnauthorized)
		return
	}
	var req struct {
		OrganizationID string `json:"organizationId"`
		Email          string `json:"email"`
		Role           string `json:"role"`
	}
	if !canopy.DecodeJSON(w, r, &req) {
		return
	}
	if _, err := m.authorize(r.Context(), req.OrganizationID, data.User.ID, PermissionInviteMember); err != nil {
		canopy.WriteError(w, err)
		return
	}
	role := req.Role
	if role == "" {
		role = RoleMember
	}
	if !isAssignableRole(role) {
		canopy.WriteError(w, canopy.ErrInvalidInput)
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if !strings.Contains(email, "@") {
		canopy.WriteError(w, canopy.ErrInvalidInput)
		return
	}
	now := time.Now().UTC()
	invID, err := newID("inv")
	if err != nil {
		canopy.WriteError(w, err)
		return
	}
	invitation := &canopy.Invitation{
		ID: invID, OrganizationID: req.OrganizationID, Email: email, Role: role,
		Status: "pending", InviterID: data.User.ID, ExpiresAt: now.Add(m.invitationTTL), CreatedAt: now, UpdatedAt: now,
	}
	if err := m.store.CreateInvitation(r.Context(), invitation); err != nil {
		canopy.WriteError(w, err)
		return
	}
	m.core.Audit(r.Context(), canopy.AuditEvent{Type: "organization.member.invited", UserID: data.User.ID, Email: email, Success: true})
	canopy.WriteJSON(w, http.StatusOK, invitation)
}

func (m *Module) handleAcceptInvitation(w http.ResponseWriter, r *http.Request) {
	data, ok := canopy.SessionFromContext(r.Context())
	if !ok {
		canopy.WriteError(w, canopy.ErrUnauthorized)
		return
	}
	var req struct {
		InvitationID string `json:"invitationId"`
	}
	if !canopy.DecodeJSON(w, r, &req) {
		return
	}
	invitation, err := m.store.FindInvitation(r.Context(), req.InvitationID)
	if err != nil {
		canopy.WriteError(w, canopy.ErrInvitationInvalid)
		return
	}
	if invitation.Status != "pending" || !invitation.ExpiresAt.After(time.Now().UTC()) {
		canopy.WriteError(w, canopy.ErrInvitationInvalid)
		return
	}
	if !data.User.EmailVerified {
		canopy.WriteError(w, canopy.ErrUnverifiedEmail)
		return
	}
	if !strings.EqualFold(strings.TrimSpace(invitation.Email), strings.TrimSpace(data.User.Email)) {
		canopy.WriteError(w, canopy.ErrForbidden)
		return
	}
	now := time.Now().UTC()
	if _, err := m.store.FindMember(r.Context(), invitation.OrganizationID, data.User.ID); err != nil {
		memberID, err := newID("mem")
		if err != nil {
			canopy.WriteError(w, err)
			return
		}
		if err := m.store.CreateMember(r.Context(), &canopy.Member{
			ID: memberID, OrganizationID: invitation.OrganizationID, UserID: data.User.ID, Role: invitation.Role, CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			canopy.WriteError(w, err)
			return
		}
	}
	invitation.Status = "accepted"
	invitation.UpdatedAt = now
	if err := m.store.UpdateInvitation(r.Context(), invitation); err != nil {
		canopy.WriteError(w, err)
		return
	}
	m.core.Audit(r.Context(), canopy.AuditEvent{Type: "organization.member.joined", UserID: data.User.ID, Email: data.User.Email, Success: true})
	canopy.WriteJSON(w, http.StatusOK, map[string]any{
		"organizationId": invitation.OrganizationID,
		"role":           invitation.Role,
	})
}

func (m *Module) handleListMembers(w http.ResponseWriter, r *http.Request) {
	data, ok := canopy.SessionFromContext(r.Context())
	if !ok {
		canopy.WriteError(w, canopy.ErrUnauthorized)
		return
	}
	orgID := r.URL.Query().Get("organizationId")
	if _, err := m.authorize(r.Context(), orgID, data.User.ID, PermissionViewMembers); err != nil {
		canopy.WriteError(w, err)
		return
	}
	members, err := m.store.ListMembers(r.Context(), orgID)
	if err != nil {
		canopy.WriteError(w, err)
		return
	}
	canopy.WriteJSON(w, http.StatusOK, map[string]any{"members": members})
}

func (m *Module) handleUpdateMemberRole(w http.ResponseWriter, r *http.Request) {
	data, ok := canopy.SessionFromContext(r.Context())
	if !ok {
		canopy.WriteError(w, canopy.ErrUnauthorized)
		return
	}
	var req struct {
		OrganizationID string `json:"organizationId"`
		UserID         string `json:"userId"`
		Role           string `json:"role"`
	}
	if !canopy.DecodeJSON(w, r, &req) {
		return
	}
	actor, err := m.authorize(r.Context(), req.OrganizationID, data.User.ID, PermissionUpdateMemberRole)
	if err != nil {
		canopy.WriteError(w, err)
		return
	}
	if !isAssignableRole(req.Role) {
		canopy.WriteError(w, canopy.ErrInvalidInput)
		return
	}
	target, err := m.store.FindMember(r.Context(), req.OrganizationID, req.UserID)
	if err != nil {
		canopy.WriteError(w, canopy.ErrNotFound)
		return
	}
	// Only an owner may change an owner.
	if target.Role == RoleOwner && actor.Role != RoleOwner {
		canopy.WriteError(w, canopy.ErrForbidden)
		return
	}
	target.Role = req.Role
	target.UpdatedAt = time.Now().UTC()
	if err := m.store.UpdateMember(r.Context(), target); err != nil {
		canopy.WriteError(w, err)
		return
	}
	canopy.WriteJSON(w, http.StatusOK, target)
}

func (m *Module) handleRemoveMember(w http.ResponseWriter, r *http.Request) {
	data, ok := canopy.SessionFromContext(r.Context())
	if !ok {
		canopy.WriteError(w, canopy.ErrUnauthorized)
		return
	}
	var req struct {
		OrganizationID string `json:"organizationId"`
		UserID         string `json:"userId"`
	}
	if !canopy.DecodeJSON(w, r, &req) {
		return
	}
	if _, err := m.authorize(r.Context(), req.OrganizationID, data.User.ID, PermissionRemoveMember); err != nil {
		canopy.WriteError(w, err)
		return
	}
	target, err := m.store.FindMember(r.Context(), req.OrganizationID, req.UserID)
	if err != nil {
		canopy.WriteError(w, canopy.ErrNotFound)
		return
	}
	// The owner cannot be removed.
	if target.Role == RoleOwner {
		canopy.WriteError(w, canopy.ErrForbidden)
		return
	}
	if err := m.store.DeleteMember(r.Context(), req.OrganizationID, req.UserID); err != nil {
		canopy.WriteError(w, err)
		return
	}
	if err := m.store.ClearActiveOrganization(r.Context(), req.OrganizationID, req.UserID); err != nil {
		canopy.WriteError(w, err)
		return
	}
	m.core.Audit(r.Context(), canopy.AuditEvent{Type: "organization.member.removed", UserID: data.User.ID, Success: true})
	canopy.WriteJSON(w, http.StatusOK, map[string]bool{"success": true})
}

// authorize loads the acting user's membership and checks a permission.
func (m *Module) authorize(ctx context.Context, orgID, userID, permission string) (*canopy.Member, error) {
	return m.Authorize(ctx, orgID, userID, permission)
}

// Authorize verifies current organization membership and permission. An
// application should call it for every tenant-scoped request rather than
// treating ActiveOrganizationID as proof of access.
func (m *Module) Authorize(ctx context.Context, orgID, userID, permission string) (*canopy.Member, error) {
	if orgID == "" {
		return nil, canopy.ErrInvalidInput
	}
	member, err := m.store.FindMember(ctx, orgID, userID)
	if err != nil {
		return nil, canopy.ErrNotOrganizationMember
	}
	if !m.authorizer.HasPermission(member.Role, permission) {
		return nil, canopy.ErrForbidden
	}
	return member, nil
}

func newID(prefix string) (string, error) {
	buf := make([]byte, 18)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return prefix + "_" + strings.ToLower(base64.RawURLEncoding.EncodeToString(buf)), nil
}

func slugify(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var b strings.Builder
	prevDash := false
	for _, r := range value {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			prevDash = false
		case r == ' ' || r == '-' || r == '_':
			if !prevDash && b.Len() > 0 {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}
