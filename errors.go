package canopy

import "errors"

var (
	ErrInvalidCredentials         = errors.New("canopy: invalid credentials")
	ErrSignupDisabled             = errors.New("canopy: signup disabled")
	ErrUnverifiedEmail            = errors.New("canopy: unverified email")
	ErrInvalidState               = errors.New("canopy: invalid state")
	ErrInvalidToken               = errors.New("canopy: invalid token")
	ErrExpiredToken               = errors.New("canopy: expired token")
	ErrProviderFailure            = errors.New("canopy: provider failure")
	ErrStorageFailure             = errors.New("canopy: storage failure")
	ErrRateLimited                = errors.New("canopy: rate limited")
	ErrAccountLinking             = errors.New("canopy: account linking required")
	ErrNoRefreshToken             = errors.New("canopy: no provider refresh token")
	ErrProviderTokenRefreshFailed = errors.New("canopy: provider token refresh failed")
	ErrProviderAccountNotFound    = errors.New("canopy: provider account not found")
	ErrNotFound                   = errors.New("canopy: not found")
	ErrConflict                   = errors.New("canopy: conflict")
	ErrInvalidInput               = errors.New("canopy: invalid input")
	ErrUnauthorized               = errors.New("canopy: unauthorized")
)
