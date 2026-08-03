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
	ErrAccountLinking             = errors.New("canopy: account linking required")
	ErrAccountLinkMismatch        = errors.New("canopy: provider email does not match account")
	ErrNoRefreshToken             = errors.New("canopy: no provider refresh token")
	ErrProviderTokenRefreshFailed = errors.New("canopy: provider token refresh failed")
	ErrProviderAccountNotFound    = errors.New("canopy: provider account not found")
	ErrNotFound                   = errors.New("canopy: not found")
	ErrConflict                   = errors.New("canopy: conflict")
	ErrInvalidInput               = errors.New("canopy: invalid input")
	ErrUnauthorized               = errors.New("canopy: unauthorized")
	ErrForbidden                  = errors.New("canopy: forbidden")
	ErrUserBanned                 = errors.New("canopy: user banned")
	ErrInvalidTwoFactorCode       = errors.New("canopy: invalid two-factor code")
	ErrRecentAuthentication       = errors.New("canopy: recent authentication required")
	ErrOrganizationNotFound       = errors.New("canopy: organization not found")
	ErrNotOrganizationMember      = errors.New("canopy: not organization member")
	ErrTeamNotFound               = errors.New("canopy: team not found")
	ErrInvitationInvalid          = errors.New("canopy: invitation invalid")
	ErrLastOrganizationOwner      = errors.New("canopy: organization must retain an owner")
)

// ValidationError describes invalid request fields while remaining compatible
// with errors.Is(err, ErrInvalidInput).
type ValidationError struct {
	Fields map[string]string
}

func (e *ValidationError) Error() string {
	return ErrInvalidInput.Error()
}

func (e *ValidationError) Unwrap() error {
	return ErrInvalidInput
}

// InvalidFields returns a typed validation error with machine-readable field
// messages. The map is copied so callers may safely reuse it.
func InvalidFields(fields map[string]string) error {
	copied := make(map[string]string, len(fields))
	for field, message := range fields {
		copied[field] = message
	}
	return &ValidationError{Fields: copied}
}
