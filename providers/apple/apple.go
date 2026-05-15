package apple

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/ssnxd/canopy/oauth"
	"golang.org/x/oauth2"
)

type ClientSecretSource interface {
	ClientSecret(ctx context.Context) (string, error)
}

type StaticClientSecret string

func (s StaticClientSecret) ClientSecret(ctx context.Context) (string, error) {
	return string(s), nil
}

type Provider struct {
	ClientID     string
	RedirectURL  string
	SecretSource ClientSecretSource
	Scopes       []string
}

func (p Provider) ID() string { return "apple" }

func (p Provider) Config(ctx context.Context) (*oauth2.Config, error) {
	if p.SecretSource == nil {
		return nil, fmt.Errorf("apple: client secret source is required")
	}
	secret, err := p.SecretSource.ClientSecret(ctx)
	if err != nil {
		return nil, err
	}
	scopes := p.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "name"}
	}
	return &oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: secret,
		RedirectURL:  p.RedirectURL,
		Scopes:       scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://appleid.apple.com/auth/authorize",
			TokenURL: "https://appleid.apple.com/auth/token",
		},
	}, nil
}

func (p Provider) AuthCodeOptions(opts oauth.StartOptions) []oauth2.AuthCodeOption {
	out := []oauth2.AuthCodeOption{}
	if opts.PKCEVerifier != "" {
		out = append(out, oauth2.S256ChallengeOption(opts.PKCEVerifier))
	}
	return out
}

func (p Provider) Exchange(ctx context.Context, code string, verifier string) (*oauth2.Token, error) {
	cfg, err := p.Config(ctx)
	if err != nil {
		return nil, err
	}
	opts := []oauth2.AuthCodeOption{}
	if verifier != "" {
		opts = append(opts, oauth2.VerifierOption(verifier))
	}
	return cfg.Exchange(ctx, code, opts...)
}

func (p Provider) Refresh(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	cfg, err := p.Config(ctx)
	if err != nil {
		return nil, err
	}
	return cfg.TokenSource(ctx, &oauth2.Token{
		RefreshToken: refreshToken,
		Expiry:       time.Now().Add(-time.Minute),
	}).Token()
}

func (p Provider) Profile(ctx context.Context, token *oauth2.Token, nonce string) (*oauth.Profile, error) {
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, fmt.Errorf("apple: missing id_token")
	}
	issuer, err := oidc.NewProvider(ctx, "https://appleid.apple.com")
	if err != nil {
		return nil, err
	}
	verified, err := issuer.Verifier(&oidc.Config{ClientID: p.ClientID}).Verify(ctx, rawIDToken)
	if err != nil {
		return nil, err
	}
	if nonce != "" && verified.Nonce != nonce {
		return nil, fmt.Errorf("apple: invalid nonce")
	}
	var claims struct {
		Subject       string          `json:"sub"`
		Email         string          `json:"email"`
		EmailVerified json.RawMessage `json:"email_verified"`
	}
	if err := verified.Claims(&claims); err != nil {
		return nil, err
	}
	var expPtr *time.Time
	if !token.Expiry.IsZero() {
		exp := token.Expiry
		expPtr = &exp
	}
	scope, _ := token.Extra("scope").(string)
	return &oauth.Profile{
		ProviderID:           p.ID(),
		AccountID:            claims.Subject,
		Email:                claims.Email,
		EmailVerified:        parseAppleBool(claims.EmailVerified),
		IDToken:              rawIDToken,
		AccessToken:          token.AccessToken,
		RefreshToken:         token.RefreshToken,
		Scope:                scope,
		AccessTokenExpiresAt: expPtr,
	}, nil
}

func parseAppleBool(raw json.RawMessage) bool {
	var b bool
	if err := json.Unmarshal(raw, &b); err == nil {
		return b
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s == "true"
	}
	return false
}
