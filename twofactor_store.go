package canopy

import (
	"context"
	"time"
)

// TwoFactor is the stored two-factor state for a user. Secret is the
// encrypted TOTP secret. The two-factor module owns the encryption.
type TwoFactor struct {
	UserID    string
	Secret    string
	Enabled   bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

// TwoFactorStore is an optional Store capability. The two-factor module
// requires it. A store advertises it by implementing these methods.
type TwoFactorStore interface {
	GetTwoFactor(ctx context.Context, userID string) (*TwoFactor, error)
	UpsertTwoFactor(ctx context.Context, tf *TwoFactor) error
	DeleteTwoFactor(ctx context.Context, userID string) error
	// ReplaceBackupCodes replaces all backup code hashes for the user.
	ReplaceBackupCodes(ctx context.Context, userID string, codeHashes []string) error
	// ConsumeBackupCode removes one backup code hash. It reports if a
	// code was removed. The removal must be atomic.
	ConsumeBackupCode(ctx context.Context, userID, codeHash string) (bool, error)
}
