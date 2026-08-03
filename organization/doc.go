// Package organization adds organizations, members, roles, and
// invitations to Canopy.
//
// The module implements canopy.Module and canopy.RouteModule. Add it
// through canopy.Config.Modules. The store must implement
// canopy.OrganizationStore.
//
// The creator of an organization becomes the owner. Roles are owner,
// admin, and member by default. A default Authorizer maps roles to
// permissions. Override it for custom access control.
//
// An invitation returns a token, which is its id. The application
// delivers the invitation to the invitee. The invitee accepts it while
// signed in with the invited email address. An invitation may carry a
// TeamID; acceptance then also adds the invitee to that team.
//
// Teams group organization members for scoped access. A team belongs to
// exactly one organization. A team membership carries no role; the
// organization role stays authoritative.
//
// The active organization is stored on the session. Read it from
// SessionData.Session.ActiveOrganizationID.
package organization
