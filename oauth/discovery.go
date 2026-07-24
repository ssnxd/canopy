package oauth

import (
	"context"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
)

var discoveryCache = struct {
	sync.RWMutex
	providers map[string]*oidc.Provider
}{
	providers: map[string]*oidc.Provider{},
}

var discoverOIDCProvider = oidc.NewProvider

// DiscoverProvider returns a cached successful OIDC discovery result.
// Failed and canceled discovery attempts are not cached.
func DiscoverProvider(ctx context.Context, issuer string) (*oidc.Provider, error) {
	discoveryCache.RLock()
	provider := discoveryCache.providers[issuer]
	discoveryCache.RUnlock()
	if provider != nil {
		return provider, nil
	}
	discovered, err := discoverOIDCProvider(ctx, issuer)
	if err != nil {
		return nil, err
	}
	discoveryCache.Lock()
	if provider = discoveryCache.providers[issuer]; provider == nil {
		discoveryCache.providers[issuer] = discovered
		provider = discovered
	}
	discoveryCache.Unlock()
	return provider, nil
}
