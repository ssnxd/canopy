package oauth

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
)

func TestDiscoverProviderCachesSuccessfulDiscovery(t *testing.T) {
	var requests atomic.Int32
	original := discoverOIDCProvider
	discoverOIDCProvider = func(ctx context.Context, issuer string) (*oidc.Provider, error) {
		requests.Add(1)
		return &oidc.Provider{}, nil
	}
	defer func() { discoverOIDCProvider = original }()

	for range 2 {
		if _, err := DiscoverProvider(context.Background(), "https://cache-test.example"); err != nil {
			t.Fatal(err)
		}
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("discovery requests = %d, want 1", got)
	}
}
