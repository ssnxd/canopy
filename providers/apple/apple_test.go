package apple

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/ssnxd/canopy/oauth"
	"golang.org/x/oauth2"
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

// captureTransport answers a token request with a static token and records
// the form that the request sent.
type captureTransport struct {
	form url.Values
}

func (c *captureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	form, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, err
	}
	c.form = form
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body: io.NopCloser(strings.NewReader(
			`{"access_token":"token","token_type":"Bearer","expires_in":3600}`)),
		Request: req,
	}, nil
}

func TestProviderRedirectOverrideAppliesToAuthorizationAndExchange(t *testing.T) {
	provider := Provider{
		ClientID: "client", SecretSource: StaticClientSecret("secret"),
		RedirectURL: "https://app.example.test/auth/callback/apple",
	}
	override := "https://app.example.test/auth/link-social/callback/apple"
	cfg, err := provider.Config(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	authURL := cfg.AuthCodeURL("state", provider.AuthCodeOptions(oauth.StartOptions{
		PKCEVerifier: "verifier", RedirectURL: override,
	})...)
	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	if got := parsed.Query().Get("redirect_uri"); got != override {
		t.Fatalf("authorization redirect_uri = %q, want %q", got, override)
	}

	transport := &captureTransport{}
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{Transport: transport})
	if _, err := provider.ExchangeWithRedirect(ctx, "code", "verifier", override); err != nil {
		t.Fatal(err)
	}
	if got := transport.form.Get("redirect_uri"); got != override {
		t.Fatalf("exchange redirect_uri = %q, want %q", got, override)
	}
	if got := transport.form.Get("code_verifier"); got != "verifier" {
		t.Fatalf("exchange code_verifier = %q", got)
	}
}

func TestProviderWithoutOverrideUsesConfiguredRedirect(t *testing.T) {
	provider := Provider{
		ClientID: "client", SecretSource: StaticClientSecret("secret"),
		RedirectURL: "https://app.example.test/auth/callback/apple",
	}
	cfg, err := provider.Config(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	authURL := cfg.AuthCodeURL("state", provider.AuthCodeOptions(oauth.StartOptions{})...)
	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	if got := parsed.Query().Get("redirect_uri"); got != provider.RedirectURL {
		t.Fatalf("authorization redirect_uri = %q, want %q", got, provider.RedirectURL)
	}

	transport := &captureTransport{}
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{Transport: transport})
	if _, err := provider.Exchange(ctx, "code", ""); err != nil {
		t.Fatal(err)
	}
	if got := transport.form.Get("redirect_uri"); got != provider.RedirectURL {
		t.Fatalf("exchange redirect_uri = %q, want %q", got, provider.RedirectURL)
	}
}
