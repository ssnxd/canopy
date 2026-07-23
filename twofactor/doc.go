// Package twofactor adds TOTP two-factor authentication to Canopy.
//
// The module implements canopy.Module, canopy.RouteModule, and
// canopy.SignInInterceptor. Add it through canopy.Config.Modules.
//
// The module stores an encrypted TOTP secret and hashed one-time backup
// codes. The default codec derives an AES-256-GCM key from the Canopy
// secret. The store must implement canopy.TwoFactorStore.
//
// When a user enables two-factor, sign-in returns a step-up challenge
// instead of a session. The client completes the challenge with a TOTP
// code or a backup code to receive the session.
package twofactor
