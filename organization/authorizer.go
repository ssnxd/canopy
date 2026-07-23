package organization

// Roles. The creator of an organization becomes the owner.
const (
	RoleOwner  = "owner"
	RoleAdmin  = "admin"
	RoleMember = "member"
)

// Permissions.
const (
	PermissionUpdateOrganization = "organization:update"
	PermissionDeleteOrganization = "organization:delete"
	PermissionInviteMember       = "member:invite"
	PermissionRemoveMember       = "member:remove"
	PermissionUpdateMemberRole   = "member:update-role"
	PermissionViewMembers        = "member:view"
)

// Authorizer decides if a role may perform a permission.
type Authorizer interface {
	HasPermission(role, permission string) bool
}

// RBAC is a static role-to-permission map.
type RBAC struct {
	roles map[string]map[string]bool
}

// DefaultAuthorizer returns the owner/admin/member RBAC. The owner has
// every permission. The admin can manage members and update the
// organization. The member can view members.
func DefaultAuthorizer() Authorizer {
	all := map[string]bool{
		PermissionUpdateOrganization: true,
		PermissionDeleteOrganization: true,
		PermissionInviteMember:       true,
		PermissionRemoveMember:       true,
		PermissionUpdateMemberRole:   true,
		PermissionViewMembers:        true,
	}
	admin := map[string]bool{
		PermissionUpdateOrganization: true,
		PermissionInviteMember:       true,
		PermissionRemoveMember:       true,
		PermissionUpdateMemberRole:   true,
		PermissionViewMembers:        true,
	}
	member := map[string]bool{
		PermissionViewMembers: true,
	}
	return RBAC{roles: map[string]map[string]bool{
		RoleOwner:  all,
		RoleAdmin:  admin,
		RoleMember: member,
	}}
}

func (r RBAC) HasPermission(role, permission string) bool {
	perms, ok := r.roles[role]
	if !ok {
		return false
	}
	return perms[permission]
}

// isAssignableRole reports if role can be assigned through invite or
// role update. The owner role is not assignable this way.
func isAssignableRole(role string) bool {
	return role == RoleAdmin || role == RoleMember
}
