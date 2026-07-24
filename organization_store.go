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
type Invitation struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organizationId"`
	Email          string    `json:"email"`
	Role           string    `json:"role"`
	Status         string    `json:"status"`
	InviterID      string    `json:"inviterId,omitempty"`
	ExpiresAt      time.Time `json:"expiresAt"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
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
	AcceptInvitation(ctx context.Context, invitationID, email string, now time.Time, member *Member) error
}
