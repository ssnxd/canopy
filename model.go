package canopy

import "time"

const ProviderEmailPassword = "email-password"

type User struct {
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	Email         string     `json:"email"`
	EmailVerified bool       `json:"emailVerified"`
	Image         string     `json:"image,omitempty"`
	Role          string     `json:"role,omitempty"`
	Banned        bool       `json:"banned"`
	BanReason     string     `json:"banReason,omitempty"`
	BanExpiresAt  *time.Time `json:"banExpiresAt,omitempty"`
	CreatedAt     time.Time  `json:"createdAt"`
	UpdatedAt     time.Time  `json:"updatedAt"`
}

type Session struct {
	ID                   string    `json:"id"`
	UserID               string    `json:"userId"`
	Token                string    `json:"-"`
	ExpiresAt            time.Time `json:"expiresAt"`
	IPAddress            string    `json:"ipAddress,omitempty"`
	UserAgent            string    `json:"userAgent,omitempty"`
	ActiveOrganizationID string    `json:"activeOrganizationId,omitempty"`
	ImpersonatedBy       string    `json:"impersonatedBy,omitempty"`
	CreatedAt            time.Time `json:"createdAt"`
	UpdatedAt            time.Time `json:"updatedAt"`
}

type Account struct {
	ID                    string     `json:"id"`
	UserID                string     `json:"userId"`
	AccountID             string     `json:"accountId"`
	ProviderID            string     `json:"providerId"`
	AccessToken           string     `json:"-"`
	RefreshToken          string     `json:"-"`
	AccessTokenExpiresAt  *time.Time `json:"accessTokenExpiresAt,omitempty"`
	RefreshTokenExpiresAt *time.Time `json:"refreshTokenExpiresAt,omitempty"`
	Scope                 string     `json:"scope,omitempty"`
	IDToken               string     `json:"-"`
	Password              string     `json:"-"`
	CreatedAt             time.Time  `json:"createdAt"`
	UpdatedAt             time.Time  `json:"updatedAt"`
}

type Verification struct {
	ID         string    `json:"id"`
	Identifier string    `json:"identifier"`
	Value      string    `json:"-"`
	ExpiresAt  time.Time `json:"expiresAt"`
	CreatedAt  time.Time `json:"createdAt"`
	UpdatedAt  time.Time `json:"updatedAt"`
}

type SessionData struct {
	User    User    `json:"user"`
	Session Session `json:"session"`
}
