package oauth

import (
	"context"
	"time"

	"golang.org/x/oauth2"
)

type StartOptions struct {
	State        string
	Nonce        string
	PKCEVerifier string
	CallbackURL  string
	Scopes       []string
}

type Profile struct {
	ProviderID            string
	AccountID             string
	Email                 string
	EmailVerified         bool
	Name                  string
	Image                 string
	IDToken               string
	AccessToken           string
	RefreshToken          string
	Scope                 string
	AccessTokenExpiresAt  *time.Time
	RefreshTokenExpiresAt *time.Time
}

type Provider interface {
	ID() string
	Config(ctx context.Context) (*oauth2.Config, error)
	AuthCodeOptions(StartOptions) []oauth2.AuthCodeOption
	Exchange(ctx context.Context, code string, verifier string) (*oauth2.Token, error)
	Refresh(ctx context.Context, refreshToken string) (*oauth2.Token, error)
	Profile(ctx context.Context, token *oauth2.Token, nonce string) (*Profile, error)
}
