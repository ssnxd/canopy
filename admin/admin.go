package admin

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ssnxd/canopy"
)

const moduleID = "admin"

const defaultImpersonationParentCookieName = "canopy.impersonation_parent"

// AdminAuthorizer decides if a session may use the admin API.
type AdminAuthorizer interface {
	IsAdmin(ctx context.Context, data canopy.SessionData) bool
}

// RoleAuthorizer treats a user as an admin when the user role is in the
// list.
type RoleAuthorizer struct {
	Roles []string
}

func (a RoleAuthorizer) IsAdmin(ctx context.Context, data canopy.SessionData) bool {
	for _, role := range a.Roles {
		if data.User.Role == role {
			return true
		}
	}
	return false
}

// Options configures the admin module.
type Options struct {
	// Authorizer decides who is an admin. The default is a RoleAuthorizer
	// built from AdminRoles.
	Authorizer AdminAuthorizer
	// AdminRoles lists the user roles that grant admin access. The
	// default is ["admin"]. It is used only when Authorizer is nil.
	AdminRoles []string
	// ImpersonationParentCookieName is the HttpOnly cookie that preserves
	// proof of the original admin session during impersonation.
	ImpersonationParentCookieName string
}

// userAccountCreator is the optional atomic provisioning capability.
type userAccountCreator interface {
	CreateUserAccount(ctx context.Context, user *canopy.User, account *canopy.Account) error
}

// Module adds admin operations: list and create users, set roles, ban and
// unban, list and revoke sessions, and impersonation. It implements
// canopy.Module and canopy.RouteModule.
type Module struct {
	authorizer                    AdminAuthorizer
	impersonationParentCookieName string

	core  canopy.Core
	store canopy.AdminStore
}

// New returns an admin module.
func New(o Options) *Module {
	authorizer := o.Authorizer
	if authorizer == nil {
		roles := o.AdminRoles
		if len(roles) == 0 {
			roles = []string{"admin"}
		}
		authorizer = RoleAuthorizer{Roles: roles}
	}
	parentCookieName := o.ImpersonationParentCookieName
	if parentCookieName == "" {
		parentCookieName = defaultImpersonationParentCookieName
	}
	return &Module{
		authorizer:                    authorizer,
		impersonationParentCookieName: parentCookieName,
	}
}

func (m *Module) ID() string { return moduleID }

func (m *Module) Init(core canopy.Core) error {
	store, ok := core.Store().(canopy.AdminStore)
	if !ok {
		return fmt.Errorf("admin: store does not implement canopy.AdminStore")
	}
	m.core = core
	m.store = store
	return nil
}

func (m *Module) Routes() []canopy.Route {
	return []canopy.Route{
		{Method: http.MethodGet, Pattern: "/admin/users", RequireSession: true, Handler: http.HandlerFunc(m.handleListUsers)},
		{Method: http.MethodPost, Pattern: "/admin/create-user", RequireSession: true, Handler: http.HandlerFunc(m.handleCreateUser)},
		{Method: http.MethodPost, Pattern: "/admin/set-role", RequireSession: true, Handler: http.HandlerFunc(m.handleSetRole)},
		{Method: http.MethodPost, Pattern: "/admin/ban-user", RequireSession: true, Handler: http.HandlerFunc(m.handleBanUser)},
		{Method: http.MethodPost, Pattern: "/admin/unban-user", RequireSession: true, Handler: http.HandlerFunc(m.handleUnbanUser)},
		{Method: http.MethodGet, Pattern: "/admin/user-sessions", RequireSession: true, Handler: http.HandlerFunc(m.handleUserSessions)},
		{Method: http.MethodPost, Pattern: "/admin/revoke-user-sessions", RequireSession: true, Handler: http.HandlerFunc(m.handleRevokeUserSessions)},
		{Method: http.MethodPost, Pattern: "/admin/impersonate", RequireSession: true, Handler: http.HandlerFunc(m.handleImpersonate)},
		{Method: http.MethodPost, Pattern: "/admin/stop-impersonating", RequireSession: true, Handler: http.HandlerFunc(m.handleStopImpersonating)},
	}
}

func (m *Module) requireAdmin(w http.ResponseWriter, r *http.Request) (*canopy.SessionData, bool) {
	data, ok := canopy.SessionFromContext(r.Context())
	if !ok {
		canopy.WriteError(w, canopy.ErrUnauthorized)
		return nil, false
	}
	if !m.authorizer.IsAdmin(r.Context(), *data) {
		canopy.WriteError(w, canopy.ErrForbidden)
		return nil, false
	}
	return data, true
}

func (m *Module) handleListUsers(w http.ResponseWriter, r *http.Request) {
	if _, ok := m.requireAdmin(w, r); !ok {
		return
	}
	query := canopy.UserQuery{Search: r.URL.Query().Get("q")}
	query.Limit, _ = strconv.Atoi(r.URL.Query().Get("limit"))
	query.Offset, _ = strconv.Atoi(r.URL.Query().Get("offset"))
	if query.Limit <= 0 || query.Limit > 200 {
		query.Limit = 50
	}
	if query.Offset < 0 {
		query.Offset = 0
	}
	users, total, err := m.store.ListUsers(r.Context(), query)
	if err != nil {
		canopy.WriteError(w, err)
		return
	}
	canopy.WriteJSON(w, http.StatusOK, map[string]any{"users": users, "total": total})
}

func (m *Module) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	if _, ok := m.requireAdmin(w, r); !ok {
		return
	}
	var req struct {
		Name     string `json:"name"`
		Email    string `json:"email"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if !canopy.DecodeJSON(w, r, &req) {
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	cfg := m.core.Config()
	if strings.TrimSpace(req.Name) == "" || !strings.Contains(email, "@") ||
		len(req.Password) < cfg.PasswordMinLength || len(req.Password) > cfg.PasswordMaxLength {
		canopy.WriteError(w, canopy.ErrInvalidInput)
		return
	}
	if existing, err := m.core.Store().FindUserByEmail(r.Context(), email); err == nil && existing != nil {
		canopy.WriteError(w, canopy.ErrConflict)
		return
	}
	hash, err := cfg.PasswordHasher.Hash(r.Context(), req.Password)
	if err != nil {
		canopy.WriteError(w, err)
		return
	}
	now := time.Now().UTC()
	userID, err := newID("usr")
	if err != nil {
		canopy.WriteError(w, err)
		return
	}
	accountID, err := newID("acc")
	if err != nil {
		canopy.WriteError(w, err)
		return
	}
	user := &canopy.User{ID: userID, Name: strings.TrimSpace(req.Name), Email: email, EmailVerified: true, Role: strings.TrimSpace(req.Role), CreatedAt: now, UpdatedAt: now}
	account := &canopy.Account{ID: accountID, UserID: userID, AccountID: email, ProviderID: canopy.ProviderEmailPassword, Password: hash, CreatedAt: now, UpdatedAt: now}
	if err := m.createUserAccount(r.Context(), user, account); err != nil {
		canopy.WriteError(w, err)
		return
	}
	m.core.Audit(r.Context(), canopy.AuditEvent{Type: "admin.user.created", Email: email, Success: true})
	canopy.WriteJSON(w, http.StatusOK, user)
}

func (m *Module) createUserAccount(ctx context.Context, user *canopy.User, account *canopy.Account) error {
	if creator, ok := m.core.Store().(userAccountCreator); ok {
		return creator.CreateUserAccount(ctx, user, account)
	}
	if err := m.core.Store().CreateUser(ctx, user); err != nil {
		return err
	}
	return m.core.Store().CreateAccount(ctx, account)
}

func (m *Module) handleSetRole(w http.ResponseWriter, r *http.Request) {
	if _, ok := m.requireAdmin(w, r); !ok {
		return
	}
	var req struct {
		UserID string `json:"userId"`
		Role   string `json:"role"`
	}
	if !canopy.DecodeJSON(w, r, &req) {
		return
	}
	user, err := m.core.Store().FindUserByID(r.Context(), req.UserID)
	if err != nil {
		canopy.WriteError(w, canopy.ErrNotFound)
		return
	}
	user.Role = strings.TrimSpace(req.Role)
	user.UpdatedAt = time.Now().UTC()
	if err := m.core.Store().UpdateUser(r.Context(), user); err != nil {
		canopy.WriteError(w, err)
		return
	}
	m.core.Audit(r.Context(), canopy.AuditEvent{Type: "admin.user.role_set", UserID: user.ID, Success: true})
	canopy.WriteJSON(w, http.StatusOK, user)
}

func (m *Module) handleBanUser(w http.ResponseWriter, r *http.Request) {
	if _, ok := m.requireAdmin(w, r); !ok {
		return
	}
	var req struct {
		UserID           string `json:"userId"`
		Reason           string `json:"reason"`
		ExpiresInSeconds int64  `json:"expiresInSeconds"`
	}
	if !canopy.DecodeJSON(w, r, &req) {
		return
	}
	user, err := m.core.Store().FindUserByID(r.Context(), req.UserID)
	if err != nil {
		canopy.WriteError(w, canopy.ErrNotFound)
		return
	}
	now := time.Now().UTC()
	user.Banned = true
	user.BanReason = strings.TrimSpace(req.Reason)
	user.BanExpiresAt = nil
	if req.ExpiresInSeconds > 0 {
		expires := now.Add(time.Duration(req.ExpiresInSeconds) * time.Second)
		user.BanExpiresAt = &expires
	}
	user.UpdatedAt = now
	if err := m.core.Store().UpdateUser(r.Context(), user); err != nil {
		canopy.WriteError(w, err)
		return
	}
	// Revoke the banned user's sessions so the ban takes effect at once.
	if err := m.core.Store().DeleteUserSessions(r.Context(), user.ID); err != nil {
		canopy.WriteError(w, err)
		return
	}
	m.core.Audit(r.Context(), canopy.AuditEvent{Type: "admin.user.banned", UserID: user.ID, Success: true})
	canopy.WriteJSON(w, http.StatusOK, user)
}

func (m *Module) handleUnbanUser(w http.ResponseWriter, r *http.Request) {
	if _, ok := m.requireAdmin(w, r); !ok {
		return
	}
	var req struct {
		UserID string `json:"userId"`
	}
	if !canopy.DecodeJSON(w, r, &req) {
		return
	}
	user, err := m.core.Store().FindUserByID(r.Context(), req.UserID)
	if err != nil {
		canopy.WriteError(w, canopy.ErrNotFound)
		return
	}
	user.Banned = false
	user.BanReason = ""
	user.BanExpiresAt = nil
	user.UpdatedAt = time.Now().UTC()
	if err := m.core.Store().UpdateUser(r.Context(), user); err != nil {
		canopy.WriteError(w, err)
		return
	}
	m.core.Audit(r.Context(), canopy.AuditEvent{Type: "admin.user.unbanned", UserID: user.ID, Success: true})
	canopy.WriteJSON(w, http.StatusOK, user)
}

func (m *Module) handleUserSessions(w http.ResponseWriter, r *http.Request) {
	if _, ok := m.requireAdmin(w, r); !ok {
		return
	}
	userID := r.URL.Query().Get("userId")
	if userID == "" {
		canopy.WriteError(w, canopy.ErrInvalidInput)
		return
	}
	sessions, err := m.store.ListUserSessions(r.Context(), userID)
	if err != nil {
		canopy.WriteError(w, err)
		return
	}
	canopy.WriteJSON(w, http.StatusOK, map[string]any{"sessions": sessions})
}

func (m *Module) handleRevokeUserSessions(w http.ResponseWriter, r *http.Request) {
	if _, ok := m.requireAdmin(w, r); !ok {
		return
	}
	var req struct {
		UserID string `json:"userId"`
	}
	if !canopy.DecodeJSON(w, r, &req) {
		return
	}
	if req.UserID == "" {
		canopy.WriteError(w, canopy.ErrInvalidInput)
		return
	}
	if err := m.core.Store().DeleteUserSessions(r.Context(), req.UserID); err != nil {
		canopy.WriteError(w, err)
		return
	}
	m.core.Audit(r.Context(), canopy.AuditEvent{Type: "admin.user.sessions_revoked", UserID: req.UserID, Success: true})
	canopy.WriteJSON(w, http.StatusOK, map[string]bool{"success": true})
}

func (m *Module) handleImpersonate(w http.ResponseWriter, r *http.Request) {
	admin, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	if admin.Session.ImpersonatedBy != "" {
		canopy.WriteError(w, canopy.ErrForbidden)
		return
	}
	var req struct {
		UserID string `json:"userId"`
	}
	if !canopy.DecodeJSON(w, r, &req) {
		return
	}
	target, err := m.core.Store().FindUserByID(r.Context(), req.UserID)
	if err != nil {
		canopy.WriteError(w, canopy.ErrNotFound)
		return
	}
	data, token, err := m.core.IssueSession(r.Context(), *target, canopy.SessionOptions{
		ImpersonatedBy: admin.User.ID,
		IPAddress:      requestIP(r),
		UserAgent:      r.UserAgent(),
	})
	if err != nil {
		canopy.WriteError(w, err)
		return
	}
	m.setImpersonationParentCookie(w, admin.Session.Token)
	m.core.Config().Session.SetCookie(w, token, nil)
	m.core.Audit(r.Context(), canopy.AuditEvent{Type: "admin.impersonation.started", UserID: admin.User.ID, Success: true})
	canopy.WriteJSON(w, http.StatusOK, data)
}

func (m *Module) handleStopImpersonating(w http.ResponseWriter, r *http.Request) {
	data, ok := canopy.SessionFromContext(r.Context())
	if !ok {
		canopy.WriteError(w, canopy.ErrUnauthorized)
		return
	}
	if data.Session.ImpersonatedBy == "" {
		canopy.WriteError(w, canopy.ErrInvalidInput)
		return
	}
	parentCookie, err := r.Cookie(m.impersonationParentCookieName)
	if err != nil || parentCookie.Value == "" {
		canopy.WriteError(w, canopy.ErrUnauthorized)
		return
	}
	parentRequest := r.Clone(r.Context())
	parentRequest.Header.Set("Authorization", "Bearer "+parentCookie.Value)
	parent, err := m.core.Authenticate(parentRequest)
	if err != nil || parent.User.ID != data.Session.ImpersonatedBy || !m.authorizer.IsAdmin(r.Context(), *parent) {
		canopy.WriteError(w, canopy.ErrUnauthorized)
		return
	}
	if err := m.core.Store().DeleteSessionByToken(r.Context(), data.Session.Token); err != nil {
		canopy.WriteError(w, err)
		return
	}
	rememberMe := false
	m.core.Config().Session.SetCookie(w, parentCookie.Value, &rememberMe)
	m.clearImpersonationParentCookie(w)
	m.core.Audit(r.Context(), canopy.AuditEvent{Type: "admin.impersonation.stopped", UserID: parent.User.ID, Success: true})
	canopy.WriteJSON(w, http.StatusOK, parent)
}

func (m *Module) setImpersonationParentCookie(w http.ResponseWriter, token string) {
	cfg := m.core.Config()
	http.SetCookie(w, &http.Cookie{
		Name:     m.impersonationParentCookieName,
		Value:    token,
		Path:     cfg.Session.CookiePath,
		Domain:   cfg.Session.CookieDomain,
		HttpOnly: true,
		Secure:   cfg.Session.Secure,
		SameSite: cfg.Session.SameSite,
		MaxAge:   int(cfg.Session.Expiry.Seconds()),
		Expires:  time.Now().Add(cfg.Session.Expiry),
	})
}

func (m *Module) clearImpersonationParentCookie(w http.ResponseWriter) {
	cfg := m.core.Config()
	http.SetCookie(w, &http.Cookie{
		Name:     m.impersonationParentCookieName,
		Value:    "",
		Path:     cfg.Session.CookiePath,
		Domain:   cfg.Session.CookieDomain,
		HttpOnly: true,
		Secure:   cfg.Session.Secure,
		SameSite: cfg.Session.SameSite,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}

func newID(prefix string) (string, error) {
	buf := make([]byte, 18)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return prefix + "_" + strings.ToLower(base64.RawURLEncoding.EncodeToString(buf)), nil
}

func requestIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
