package canopy

import (
	"context"
	"time"
)

type Store interface {
	FindUserByID(ctx context.Context, id string) (*User, error)
	FindUserByEmail(ctx context.Context, email string) (*User, error)
	CreateUser(ctx context.Context, user *User) error
	UpdateUser(ctx context.Context, user *User) error

	FindAccount(ctx context.Context, providerID, accountID string) (*Account, error)
	FindAccountByUserProvider(ctx context.Context, userID, providerID string) (*Account, error)
	CreateAccount(ctx context.Context, account *Account) error
	UpdateAccount(ctx context.Context, account *Account) error

	CreateSession(ctx context.Context, session *Session) error
	FindSessionByToken(ctx context.Context, token string) (*SessionData, error)
	UpdateSession(ctx context.Context, session *Session) error
	DeleteSessionByToken(ctx context.Context, token string) error
	DeleteUserSessions(ctx context.Context, userID string) error
	DeleteExpiredSessions(ctx context.Context, now time.Time) error

	CreateVerification(ctx context.Context, verification *Verification) error
	ReplaceVerification(ctx context.Context, verification *Verification) error
	ConsumeVerification(ctx context.Context, identifier, value string, now time.Time) (*Verification, error)
	DeleteVerificationsByIdentifier(ctx context.Context, identifier string) error
	DeleteExpiredVerifications(ctx context.Context, now time.Time) error
}
