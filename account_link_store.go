package canopy

import (
	"context"
	"time"
)

// AccountLinkStore is an optional Store capability. The account-link
// module uses it for an atomic link confirmation. A store advertises it
// by implementing this method.
type AccountLinkStore interface {
	// CreateLinkedAccount atomically consumes the one-time link-confirmation
	// verification and creates the provider account for the existing user.
	// ErrNotFound: token missing/expired/consumed. ErrConflict: account exists.
	CreateLinkedAccount(ctx context.Context, identifier, value string, now time.Time, account *Account) error
}
