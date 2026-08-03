package canopy

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

type httpHandler struct {
	api *Service
	cfg Config
	mux *http.ServeMux
}

type requestSession struct {
	Data  *SessionData
	Token string
}

func newHandler(api *Service, cfg Config) http.Handler {
	h := &httpHandler{api: api, cfg: cfg, mux: http.NewServeMux()}
	h.mux.HandleFunc("POST /sign-up/email", h.signUpEmail)
	h.mux.HandleFunc("POST /sign-in/email", h.signInEmail)
	h.mux.HandleFunc("POST /send-verification-email", h.sendVerificationEmail)
	h.mux.HandleFunc("POST /verify-email", h.verifyEmail)
	h.mux.HandleFunc("GET /verify-email", h.verifyEmail)
	h.mux.HandleFunc("POST /request-password-reset", h.requestPasswordReset)
	h.mux.HandleFunc("POST /reset-password", h.resetPassword)
	h.mux.HandleFunc("POST /sign-in/social", h.signInSocial)
	h.mux.HandleFunc("GET /callback/{provider}", h.oauthCallback)
	h.mux.HandleFunc("POST /callback/{provider}", h.oauthCallback)
	h.mux.HandleFunc("POST /refresh-provider-token", h.refreshProviderToken)
	h.mux.HandleFunc("POST /sign-out", h.signOut)
	h.mux.HandleFunc("GET /get-session", h.getSession)
	h.mux.HandleFunc("POST /get-session", h.getSession)
	h.mountModules()
	return h
}

// mountModules registers the routes that each RouteModule contributes.
// It wraps a route with a session check when the route requires one.
func (h *httpHandler) mountModules() {
	for _, module := range h.cfg.Modules {
		routeModule, ok := module.(RouteModule)
		if !ok {
			continue
		}
		for _, route := range routeModule.Routes() {
			handler := route.Handler
			if route.RequireSession {
				handler = h.requireSession(handler)
			}
			h.mux.Handle(route.Method+" "+route.Pattern, handler)
		}
	}
}

// requireSession resolves the session before it runs next. It returns
// unauthorized when no session is present. The session is available
// through SessionFromContext.
func (h *httpHandler) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := h.api.Authenticate(r)
		if err != nil {
			writeError(w, ErrUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(ContextWithSession(r.Context(), data)))
	})
}

func twoFactorResponse(challenge *StepUpChallenge) map[string]any {
	return map[string]any{
		"twoFactorRequired": true,
		"token":             challenge.Token,
		"methods":           challenge.Methods,
	}
}

func (h *httpHandler) sendVerificationEmail(w http.ResponseWriter, r *http.Request) {
	var req SendEmailVerificationInput
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := h.api.SendEmailVerification(r.Context(), req); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

func (h *httpHandler) verifyEmail(w http.ResponseWriter, r *http.Request) {
	var req VerifyEmailInput
	if r.Method == http.MethodGet {
		req.Token = r.URL.Query().Get("token")
	} else if !decodeJSON(w, r, &req) {
		return
	}
	user, err := h.api.VerifyEmail(r.Context(), req)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, user)
}

func (h *httpHandler) requestPasswordReset(w http.ResponseWriter, r *http.Request) {
	var req RequestPasswordResetInput
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := h.api.RequestPasswordReset(r.Context(), req); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

func (h *httpHandler) resetPassword(w http.ResponseWriter, r *http.Request) {
	var req ResetPasswordInput
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := h.api.ResetPassword(r.Context(), req); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

func (h *httpHandler) refreshProviderToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProviderID string `json:"providerId"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	session, err := h.sessionFromRequest(r)
	if err != nil {
		writeError(w, ErrUnauthorized)
		return
	}
	out, err := h.api.RefreshProviderToken(r.Context(), RefreshProviderTokenInput{
		UserID:     session.Data.User.ID,
		ProviderID: req.ProviderID,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *httpHandler) signInSocial(w http.ResponseWriter, r *http.Request) {
	var req SignInSocialInput
	if !decodeJSON(w, r, &req) {
		return
	}
	out, binding, err := h.api.SignInSocial(r.Context(), req)
	if err != nil {
		writeError(w, err)
		return
	}
	h.setOAuthStateCookie(w, binding)
	writeJSON(w, http.StatusOK, out)
}

func (h *httpHandler) oauthCallback(w http.ResponseWriter, r *http.Request) {
	out, err := h.finishOAuthBrowserFlow(w, r)
	if err != nil {
		writeError(w, err)
		return
	}
	h.clearOAuthStateCookie(w)
	if out.Result.Challenge != nil {
		writeJSON(w, http.StatusOK, twoFactorResponse(out.Result.Challenge))
		return
	}
	h.cfg.Session.SetCookie(w, out.Result.Token, out.RememberMe)
	if out.CallbackURL != "" {
		http.Redirect(w, r, out.CallbackURL, http.StatusFound)
		return
	}
	writeJSON(w, http.StatusOK, out.Result.Session)
}

func (h *httpHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if !h.cfg.CheckOrigin(r) {
		writeError(w, ErrUnauthorized)
		return
	}
	if h.cfg.BasePath != "/" {
		if !strings.HasPrefix(r.URL.Path, h.cfg.BasePath+"/") {
			http.NotFound(w, r)
			return
		}
		r = r.Clone(r.Context())
		urlCopy := *r.URL
		urlCopy.Path = strings.TrimPrefix(urlCopy.Path, h.cfg.BasePath)
		urlCopy.RawPath = ""
		r.URL = &urlCopy
	}
	h.mux.ServeHTTP(w, r)
}

func (h *httpHandler) signUpEmail(w http.ResponseWriter, r *http.Request) {
	var req SignUpEmailInput
	if !decodeJSON(w, r, &req) {
		return
	}
	req.IPAddress = h.api.ClientIP(r)
	req.UserAgent = r.UserAgent()
	data, token, err := h.api.SignUpEmail(r.Context(), req)
	if err != nil {
		writeError(w, err)
		return
	}
	h.cfg.Session.SetCookie(w, token, req.RememberMe)
	writeJSON(w, http.StatusOK, data)
}

func (h *httpHandler) signInEmail(w http.ResponseWriter, r *http.Request) {
	var req SignInEmailInput
	if !decodeJSON(w, r, &req) {
		return
	}
	req.IPAddress = h.api.ClientIP(r)
	req.UserAgent = r.UserAgent()
	result, err := h.api.SignInEmail(r.Context(), req)
	if err != nil {
		writeError(w, err)
		return
	}
	if result.Challenge != nil {
		writeJSON(w, http.StatusOK, twoFactorResponse(result.Challenge))
		return
	}
	h.cfg.Session.SetCookie(w, result.Token, req.RememberMe)
	writeJSON(w, http.StatusOK, result.Session)
}

func (h *httpHandler) signOut(w http.ResponseWriter, r *http.Request) {
	session, _ := h.sessionFromRequest(r)
	token := ""
	if session != nil {
		token = session.Token
	}
	if err := h.api.SignOut(r.Context(), token); err != nil {
		writeError(w, err)
		return
	}
	h.cfg.Session.ClearCookie(w)
	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

func (h *httpHandler) getSession(w http.ResponseWriter, r *http.Request) {
	session, err := h.sessionFromRequest(r)
	if err != nil {
		writeJSON(w, http.StatusOK, nil)
		return
	}
	writeJSON(w, http.StatusOK, session.Data)
}

func (h *httpHandler) sessionFromRequest(r *http.Request) (*requestSession, error) {
	token := requestToken(r, h.cfg.Session.CookieName)
	data, err := h.api.GetSession(r.Context(), token)
	if err != nil {
		return nil, err
	}
	return &requestSession{Data: data, Token: token}, nil
}

func (h *httpHandler) finishOAuthBrowserFlow(w http.ResponseWriter, r *http.Request) (*OAuthCallbackResult, error) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	if err := r.ParseForm(); err != nil {
		return nil, ErrInvalidInput
	}
	provider := r.PathValue("provider")
	state := r.Form.Get("state")
	code := r.Form.Get("code")
	if provider == "" || state == "" || code == "" {
		return nil, ErrInvalidInput
	}
	cookie, err := r.Cookie(h.cfg.OAuthStateCookieName)
	if err != nil {
		return nil, ErrInvalidState
	}
	return h.api.oauthCallback(r.Context(), OAuthCallbackInput{
		Provider:     provider,
		Code:         code,
		State:        state,
		StateBinding: cookie.Value,
		IPAddress:    h.api.ClientIP(r),
		UserAgent:    r.UserAgent(),
	})
}

func (h *httpHandler) setOAuthStateCookie(w http.ResponseWriter, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     h.cfg.OAuthStateCookieName,
		Value:    value,
		Path:     h.cfg.Session.CookiePath,
		Domain:   h.cfg.Session.CookieDomain,
		HttpOnly: true,
		Secure:   h.cfg.Session.Secure,
		SameSite: h.cfg.Session.SameSite,
		MaxAge:   int(h.cfg.OAuthStateTTL.Seconds()),
		Expires:  time.Now().Add(h.cfg.OAuthStateTTL),
	})
}

func (h *httpHandler) clearOAuthStateCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     h.cfg.OAuthStateCookieName,
		Value:    "",
		Path:     h.cfg.Session.CookiePath,
		Domain:   h.cfg.Session.CookieDomain,
		HttpOnly: true,
		Secure:   h.cfg.Session.Secure,
		SameSite: h.cfg.Session.SameSite,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}

// maxRequestBodyBytes limits the size of a request body that Canopy decodes.
// This stops a large body from exhausting server memory.
const maxRequestBodyBytes = 1 << 20 // 1 MiB

// WriteJSON writes a JSON response. A module handler uses it for a
// response shape that matches the core handler.
func WriteJSON(w http.ResponseWriter, status int, body any) {
	writeJSON(w, status, body)
}

// WriteError writes a typed error as a JSON error envelope. A module
// handler uses it for an error shape that matches the core handler.
func WriteError(w http.ResponseWriter, err error) {
	writeError(w, err)
}

// DecodeJSON decodes a size-limited JSON request body into dst. It writes
// an error response and returns false on failure. A module handler uses
// it for the same body limit and error shape as the core handler.
func DecodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	return decodeJSON(w, r, dst)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeError(w, InvalidFields(map[string]string{"body": "must be valid JSON with known fields"}))
		return false
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeError(w, InvalidFields(map[string]string{"body": "must contain exactly one JSON value"}))
		return false
	}
	return true
}

func bearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		return strings.TrimSpace(auth[7:])
	}
	return ""
}

func requestToken(r *http.Request, cookieName string) string {
	if token := bearerToken(r); token != "" {
		return token
	}
	if cookie, err := r.Cookie(cookieName); err == nil {
		return cookie.Value
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	code := "BAD_REQUEST"
	message := "Invalid request"
	switch {
	case errors.Is(err, ErrInvalidInput):
		status, code, message = http.StatusBadRequest, "INVALID_INPUT", "Invalid input"
	case errors.Is(err, ErrInvalidState):
		status, code, message = http.StatusBadRequest, "INVALID_STATE", "Invalid state"
	case errors.Is(err, ErrInvalidCredentials):
		status, code, message = http.StatusUnauthorized, "INVALID_CREDENTIALS", "Invalid email or password"
	case errors.Is(err, ErrInvalidToken):
		status, code, message = http.StatusBadRequest, "INVALID_TOKEN", "Invalid token"
	case errors.Is(err, ErrExpiredToken):
		status, code, message = http.StatusBadRequest, "EXPIRED_TOKEN", "Expired token"
	case errors.Is(err, ErrUnauthorized):
		status, code, message = http.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized"
	case errors.Is(err, ErrSignupDisabled):
		status, code, message = http.StatusForbidden, "SIGNUP_DISABLED", "Sign up is disabled"
	case errors.Is(err, ErrUnverifiedEmail):
		status, code, message = http.StatusForbidden, "UNVERIFIED_EMAIL", "Email is not verified"
	case errors.Is(err, ErrConflict):
		status, code, message = http.StatusConflict, "CONFLICT", "Resource already exists"
	case errors.Is(err, ErrAccountLinking):
		status, code, message = http.StatusConflict, "ACCOUNT_LINKING_REQUIRED", "Account linking requires explicit confirmation"
	case errors.Is(err, ErrNoRefreshToken):
		status, code, message = http.StatusConflict, "NO_REFRESH_TOKEN", "No provider refresh token is available"
	case errors.Is(err, ErrProviderAccountNotFound):
		status, code, message = http.StatusNotFound, "PROVIDER_ACCOUNT_NOT_FOUND", "Provider account was not found"
	case errors.Is(err, ErrProviderTokenRefreshFailed):
		status, code, message = http.StatusBadGateway, "PROVIDER_TOKEN_REFRESH_FAILED", "Provider token refresh failed"
	case errors.Is(err, ErrProviderFailure):
		status, code, message = http.StatusBadGateway, "PROVIDER_FAILURE", "Provider request failed"
	case errors.Is(err, ErrUserBanned):
		status, code, message = http.StatusForbidden, "USER_BANNED", "User is banned"
	case errors.Is(err, ErrForbidden):
		status, code, message = http.StatusForbidden, "FORBIDDEN", "Forbidden"
	case errors.Is(err, ErrInvalidTwoFactorCode):
		status, code, message = http.StatusUnauthorized, "INVALID_TWO_FACTOR_CODE", "Invalid two-factor code"
	case errors.Is(err, ErrRecentAuthentication):
		status, code, message = http.StatusForbidden, "RECENT_AUTHENTICATION_REQUIRED", "Recent authentication is required"
	case errors.Is(err, ErrOrganizationNotFound):
		status, code, message = http.StatusNotFound, "ORGANIZATION_NOT_FOUND", "Organization was not found"
	case errors.Is(err, ErrTeamNotFound):
		status, code, message = http.StatusNotFound, "TEAM_NOT_FOUND", "Team was not found"
	case errors.Is(err, ErrNotOrganizationMember):
		status, code, message = http.StatusForbidden, "NOT_ORGANIZATION_MEMBER", "Not a member of the organization"
	case errors.Is(err, ErrInvitationInvalid):
		status, code, message = http.StatusBadRequest, "INVITATION_INVALID", "Invitation is invalid"
	case errors.Is(err, ErrLastOrganizationOwner):
		status, code, message = http.StatusConflict, "LAST_ORGANIZATION_OWNER", "Organization must retain an owner"
	case errors.Is(err, ErrNotFound):
		status, code, message = http.StatusNotFound, "NOT_FOUND", "Resource was not found"
	case errors.Is(err, ErrStorageFailure):
		status, code, message = http.StatusInternalServerError, "STORAGE_FAILURE", "Storage operation failed"
	}
	body := map[string]any{"code": code, "message": message}
	var validation *ValidationError
	if errors.As(err, &validation) && len(validation.Fields) > 0 {
		body["fields"] = validation.Fields
	}
	writeJSON(w, status, map[string]any{"error": body})
}
