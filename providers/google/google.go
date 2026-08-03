package google

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/ssnxd/canopy/oauth"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type Provider struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
}

func (p Provider) ID() string { return "google" }

func (p Provider) Validate() error {
	if p.ClientID == "" || p.ClientSecret == "" {
		return fmt.Errorf("google: client id and client secret are required")
	}
	redirect, err := url.Parse(p.RedirectURL)
	if err != nil || redirect.Host == "" || (redirect.Scheme != "https" && redirect.Scheme != "http") {
		return fmt.Errorf("google: redirect URL must be an absolute HTTP(S) URL")
	}
	if len(p.Scopes) > 0 && !slices.Contains(p.Scopes, "openid") {
		return fmt.Errorf("google: custom scopes must include openid")
	}
	return nil
}

func (p Provider) Config(ctx context.Context) (*oauth2.Config, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	scopes := p.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile"}
	}
	return &oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		RedirectURL:  p.RedirectURL,
		Scopes:       scopes,
		Endpoint:     google.Endpoint,
	}, nil
}

func (p Provider) AuthCodeOptions(opts oauth.StartOptions) []oauth2.AuthCodeOption {
	out := []oauth2.AuthCodeOption{oauth2.AccessTypeOffline}
	if opts.PKCEVerifier != "" {
		out = append(out, oauth2.S256ChallengeOption(opts.PKCEVerifier))
	}
	if opts.RedirectURL != "" {
		// AuthCodeURL writes redirect_uri from the configuration first, then
		// applies these options. This option replaces that value.
		// ExchangeWithRedirect sends the same value at the token exchange.
		out = append(out, oauth2.SetAuthURLParam("redirect_uri", opts.RedirectURL))
	}
	return out
}

func (p Provider) Exchange(ctx context.Context, code string, verifier string) (*oauth2.Token, error) {
	return p.ExchangeWithRedirect(ctx, code, verifier, "")
}

// ExchangeWithRedirect implements oauth.RedirectExchanger. It sends
// redirectURL as the redirect_uri of the token exchange. An empty redirectURL
// keeps the configured redirect URL.
func (p Provider) ExchangeWithRedirect(ctx context.Context, code string, verifier string, redirectURL string) (*oauth2.Token, error) {
	cfg, err := p.Config(ctx)
	if err != nil {
		return nil, err
	}
	if redirectURL != "" {
		cfg.RedirectURL = redirectURL
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
		return nil, fmt.Errorf("google: missing id_token")
	}
	issuer, err := oauth.DiscoverProvider(ctx, "https://accounts.google.com")
	if err != nil {
		return nil, err
	}
	verified, err := issuer.Verifier(&oidc.Config{ClientID: p.ClientID}).Verify(ctx, rawIDToken)
	if err != nil {
		return nil, err
	}
	if nonce != "" && verified.Nonce != nonce {
		return nil, fmt.Errorf("google: invalid nonce")
	}
	var claims struct {
		Subject       string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
		Picture       string `json:"picture"`
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
		EmailVerified:        claims.EmailVerified,
		Name:                 claims.Name,
		Image:                claims.Picture,
		IDToken:              rawIDToken,
		AccessToken:          token.AccessToken,
		RefreshToken:         token.RefreshToken,
		Scope:                scope,
		AccessTokenExpiresAt: expPtr,
	}, nil
}
