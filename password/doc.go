// Package password provides password hashing interfaces and Canopy's default
// Argon2id implementation.
//
// Applications can replace the default hasher by supplying a custom
// password.Hasher in canopy.Config.
package password
