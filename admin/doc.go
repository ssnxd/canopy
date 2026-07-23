// Package admin adds administrator operations to Canopy.
//
// The module implements canopy.Module and canopy.RouteModule. Add it
// through canopy.Config.Modules. The store must implement
// canopy.AdminStore.
//
// An AdminAuthorizer decides who is an admin. The default treats a user
// with the role "admin" as an administrator. Override it for custom
// rules.
//
// The module can list and create users, set roles, ban and unban users,
// list and revoke sessions, and impersonate a user. A ban takes effect
// at once, because the module revokes the banned user's sessions and the
// core rejects a banned user. Impersonation records the admin on the
// session through ImpersonatedBy.
package admin
