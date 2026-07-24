package canopy

import (
	"context"
	"time"
)

// TwoFactor is the stored two-factor state for a user. Secret is the
// encrypted TOTP secret. The two-factor module owns the encryption.
type TwoFactor struct {
	UserID  string
	Secret  string
	Enabled bool
	// LastTOTPStep is the most recent accepted TOTP counter. A new code must
	// have a greater counter to prevent replay.
	LastTOTPStep int64
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// TwoFactorStore is an optional Store capability. The two-factor module
// requires it. A store advertises it by implementing these methods.
type TwoFactorStore interface {
	GetTwoFactor(ctx context.Context, userID string) (*TwoFactor, error)
	UpsertTwoFactor(ctx context.Context, tf *TwoFactor) error
	// EnableTwoFactor stores enabled state and replaces backup codes
	// atomically.
	EnableTwoFactor(ctx context.Context, tf *TwoFactor, codeHashes []string) error
	DeleteTwoFactor(ctx context.Context, userID string) error
	// ReplaceBackupCodes replaces all backup code hashes for the user.
	ReplaceBackupCodes(ctx context.Context, userID string, codeHashes []string) error
	// ConsumeBackupCode removes one backup code hash. It reports if a
	// code was removed. The removal must be atomic.
	ConsumeBackupCode(ctx context.Context, userID, codeHash string) (bool, error)
	// ConsumeTOTPStep records counter when it is newer than the last accepted
	// counter. It must compare and update atomically.
	ConsumeTOTPStep(ctx context.Context, userID string, counter int64) (bool, error)
}
