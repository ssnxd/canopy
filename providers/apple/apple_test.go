package apple

import (
	"context"
	"testing"
)

func TestProviderValidatesConfiguration(t *testing.T) {
	valid := Provider{
		ClientID: "client", SecretSource: StaticClientSecret("secret"),
		RedirectURL: "https://app.example.test/auth/callback/apple",
	}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := valid.Config(context.Background()); err != nil {
		t.Fatal(err)
	}
	for name, provider := range map[string]Provider{
		"missing client id":    {SecretSource: StaticClientSecret("secret"), RedirectURL: valid.RedirectURL},
		"missing source":       {ClientID: "client", RedirectURL: valid.RedirectURL},
		"relative redirect":    {ClientID: "client", SecretSource: StaticClientSecret("secret"), RedirectURL: "/callback"},
		"missing openid scope": {ClientID: "client", SecretSource: StaticClientSecret("secret"), RedirectURL: valid.RedirectURL, Scopes: []string{"email"}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := provider.Validate(); err == nil {
				t.Fatal("Validate() error = nil")
			}
		})
	}
	emptySecret := valid
	emptySecret.SecretSource = StaticClientSecret("")
	if _, err := emptySecret.Config(context.Background()); err == nil {
		t.Fatal("Config() accepted an empty client secret")
	}
}
