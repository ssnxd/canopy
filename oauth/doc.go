// Package oauth defines provider interfaces and shared OAuth profile types used
// by Canopy.
//
// Provider implementations are responsible for constructing OAuth2
// configuration, exchanging authorization codes, refreshing provider access
// tokens, and normalizing verified provider profile data into Canopy's account
// model.
package oauth
