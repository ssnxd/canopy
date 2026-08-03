package canopy

import (
	"context"
	"time"
)

// Organization is a tenant that groups members.
type Organization struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// Member links a user to an organization with a role.
type Member struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organizationId"`
	UserID         string    `json:"userId"`
	Role           string    `json:"role"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

// Invitation invites an email address to join an organization with a role.
// An optional TeamID also assigns the invitee to a team on acceptance.
type Invitation struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organizationId"`
	Email          string    `json:"email"`
	Role           string    `json:"role"`
	Status         string    `json:"status"`
	InviterID      string    `json:"inviterId,omitempty"`
	TeamID         string    `json:"teamId,omitempty"`
	ExpiresAt      time.Time `json:"expiresAt"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

// Team groups organization members for scoped access. A team belongs to
// exactly one organization.
type Team struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organizationId"`
	Name           string    `json:"name"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

// TeamMember links an organization member to a team.
type TeamMember struct {
	ID             string    `json:"id"`
	TeamID         string    `json:"teamId"`
	OrganizationID string    `json:"organizationId"`
	UserID         string    `json:"userId"`
	CreatedAt      time.Time `json:"createdAt"`
}

// OrganizationStore is an optional Store capability. The organization
// module requires it.
type OrganizationStore interface {
	CreateOrganization(ctx context.Context, org *Organization) error
	// CreateOrganizationWithOwner creates both records atomically.
	CreateOrganizationWithOwner(ctx context.Context, org *Organization, owner *Member) error
	FindOrganizationByID(ctx context.Context, id string) (*Organization, error)
	FindOrganizationBySlug(ctx context.Context, slug string) (*Organization, error)
	ListOrganizationsForUser(ctx context.Context, userID string) ([]Organization, error)
	UpdateOrganization(ctx context.Context, org *Organization) error
	DeleteOrganization(ctx context.Context, id string) error

	CreateMember(ctx context.Context, member *Member) error
	FindMember(ctx context.Context, orgID, userID string) (*Member, error)
	ListMembers(ctx context.Context, orgID string) ([]Member, error)
	UpdateMember(ctx context.Context, member *Member) error
	// UpdateMemberRole updates a role atomically while ensuring at least one
	// member retains protectedRole.
	UpdateMemberRole(ctx context.Context, member *Member, protectedRole string) error
	DeleteMember(ctx context.Context, orgID, userID string) error
	ClearActiveOrganization(ctx context.Context, orgID, userID string) error
	// RemoveMemberAndClearSessions removes the member and clears that
	// organization from their active sessions atomically.
	RemoveMemberAndClearSessions(ctx context.Context, orgID, userID string, now time.Time) error

	CreateInvitation(ctx context.Context, invitation *Invitation) error
	FindInvitation(ctx context.Context, id string) (*Invitation, error)
	ListInvitationsForOrg(ctx context.Context, orgID string) ([]Invitation, error)
	UpdateInvitation(ctx context.Context, invitation *Invitation) error
	// AcceptInvitation marks a pending, unexpired invitation accepted and
	// creates the member atomically. An existing membership is preserved.
	// When the invitation carries a TeamID it also creates the team
	// membership atomically in the same operation.
	AcceptInvitation(ctx context.Context, invitationID, email string, now time.Time, member *Member) error

	CreateTeam(ctx context.Context, team *Team) error
	FindTeamByID(ctx context.Context, id string) (*Team, error)
	ListTeamsForOrg(ctx context.Context, orgID string) ([]Team, error)
	UpdateTeam(ctx context.Context, team *Team) error
	// DeleteTeam removes the team and its team memberships and clears the
	// team from pending invitations, all atomically.
	DeleteTeam(ctx context.Context, orgID, teamID string) error
	// AddTeamMember creates a team membership. The caller must have already
	// verified the user is a member of the team's organization.
	AddTeamMember(ctx context.Context, member *TeamMember) error
	FindTeamMember(ctx context.Context, teamID, userID string) (*TeamMember, error)
	ListTeamMembers(ctx context.Context, teamID string) ([]TeamMember, error)
	RemoveTeamMember(ctx context.Context, teamID, userID string) error
}

// ProtectedMemberRemovalStore is an optional OrganizationStore capability.
// A store that implements it removes a member only when the member does not
// hold the protected role at commit time.
//
// The organization module checks the role before it removes a member. That
// check alone is not safe, because a concurrent role change can commit
// between the check and the removal. An organization that loses its last
// owner cannot recover, because no route can grant the owner role again.
//
// Implement this capability on every production store. The module falls back
// to RemoveMemberAndClearSessions when a store does not implement it, and
// that path keeps the race.
type ProtectedMemberRemovalStore interface {
	// RemoveMemberAndClearSessionsProtected removes the member and clears
	// that organization from their active sessions atomically. It re-reads
	// the member role inside the same transaction. It returns ErrForbidden
	// when the member holds protectedRole, and ErrNotFound when the member
	// does not exist.
	RemoveMemberAndClearSessionsProtected(ctx context.Context, orgID, userID, protectedRole string, now time.Time) error
}
