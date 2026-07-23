package canopy

import "context"

// UserQuery filters and pages a user listing for the admin module.
type UserQuery struct {
	Limit  int
	Offset int
	Search string
}

// AdminStore is an optional Store capability. The admin module requires
// it for listing users and their sessions.
type AdminStore interface {
	// ListUsers returns a page of users and the total count.
	ListUsers(ctx context.Context, q UserQuery) (users []User, total int, err error)
	ListUserSessions(ctx context.Context, userID string) ([]Session, error)
}
