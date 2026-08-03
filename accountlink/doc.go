// Package accountlink adds an explicit account-linking confirmation flow
// to Canopy.
//
// The module implements canopy.Module and canopy.RouteModule. Add it
// through canopy.Config.Modules.
//
// A signed-in user starts a link from an authenticated session. The module
// signs a one-time link state, binds the flow to the browser with an
// HttpOnly cookie, and sends the user to the OAuth provider. Completion
// requires the same session, a recent authentication, and a verified
// provider email that equals the session user's email. The store consumes
// the link state and creates the provider account atomically.
package accountlink
