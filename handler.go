package canopy

import (
	"encoding/json"
	"errors"
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
	return h
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
	out, err := h.finishOAuthBrowserFlow(r)
	if err != nil {
		writeError(w, err)
		return
	}
	h.clearOAuthStateCookie(w)
	h.cfg.Session.SetCookie(w, out.Token, out.RememberMe)
	if out.CallbackURL != "" {
		http.Redirect(w, r, out.CallbackURL, http.StatusFound)
		return
	}
	writeJSON(w, http.StatusOK, out.Data)
}

func (h *httpHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.cfg.CheckOrigin(r) {
		writeError(w, ErrUnauthorized)
		return
	}
	h.mux.ServeHTTP(w, r)
}

func (h *httpHandler) signUpEmail(w http.ResponseWriter, r *http.Request) {
	var req SignUpEmailInput
	if !decodeJSON(w, r, &req) {
		return
	}
	req.IPAddress = requestIP(r)
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
	req.IPAddress = requestIP(r)
	req.UserAgent = r.UserAgent()
	data, token, err := h.api.SignInEmail(r.Context(), req)
	if err != nil {
		writeError(w, err)
		return
	}
	h.cfg.Session.SetCookie(w, token, req.RememberMe)
	writeJSON(w, http.StatusOK, data)
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

func (h *httpHandler) finishOAuthBrowserFlow(r *http.Request) (*oauthCallbackResult, error) {
	provider := r.PathValue("provider")
	state := r.FormValue("state")
	code := r.FormValue("code")
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
		IPAddress:    requestIP(r),
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

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeError(w, ErrInvalidInput)
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
	}
	writeJSON(w, status, map[string]any{
		"error": map[string]string{
			"code":    code,
			"message": message,
		},
	})
}
