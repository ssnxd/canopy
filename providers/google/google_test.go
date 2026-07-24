package google

import (
	"context"
	"testing"
)

func TestProviderValidatesConfiguration(t *testing.T) {
	valid := Provider{
		ClientID: "client", ClientSecret: "secret",
		RedirectURL: "https://app.example.test/auth/callback/google",
	}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := valid.Config(context.Background()); err != nil {
		t.Fatal(err)
	}
	for name, provider := range map[string]Provider{
		"missing client id":    {ClientSecret: "secret", RedirectURL: valid.RedirectURL},
		"missing secret":       {ClientID: "client", RedirectURL: valid.RedirectURL},
		"relative redirect":    {ClientID: "client", ClientSecret: "secret", RedirectURL: "/callback"},
		"missing openid scope": {ClientID: "client", ClientSecret: "secret", RedirectURL: valid.RedirectURL, Scopes: []string{"email"}},
		"unsupported redirect": {ClientID: "client", ClientSecret: "secret", RedirectURL: "javascript:alert(1)"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := provider.Validate(); err == nil {
				t.Fatal("Validate() error = nil")
			}
		})
	}
}
