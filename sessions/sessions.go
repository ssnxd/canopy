package sessions

import (
	"net/http"
	"time"
)

type Config struct {
	CookieName           string
	CookiePath           string
	CookieDomain         string
	CookiePrefix         string
	Secure               bool
	SameSite             http.SameSite
	Expiry               time.Duration
	UpdateAge            time.Duration
	BrowserSessionMaxAge time.Duration

	// AbsoluteMaxAge caps the total lifetime of a session. A session
	// cannot live past this age even with regular use.
	AbsoluteMaxAge time.Duration
	// DisableAbsoluteExpiry turns off the absolute lifetime cap.
	DisableAbsoluteExpiry bool
}

func (c *Config) SetDefaults(production bool) {
	if c.CookieName == "" {
		if c.CookiePrefix != "" {
			c.CookieName = c.CookiePrefix + ".session_token"
		} else {
			c.CookieName = "canopy.session_token"
		}
	}
	if c.CookiePath == "" {
		c.CookiePath = "/"
	}
	if c.SameSite == 0 {
		c.SameSite = http.SameSiteLaxMode
	}
	if production {
		c.Secure = true
	}
	if c.Expiry == 0 {
		c.Expiry = 7 * 24 * time.Hour
	}
	if c.UpdateAge == 0 {
		c.UpdateAge = 24 * time.Hour
	}
	if c.BrowserSessionMaxAge == 0 {
		c.BrowserSessionMaxAge = c.Expiry
	}
	if c.AbsoluteMaxAge == 0 {
		c.AbsoluteMaxAge = 30 * 24 * time.Hour
	}
}

func (c Config) SetCookie(w http.ResponseWriter, token string, rememberMe *bool) {
	c.SetDefaults(c.Secure)
	cookie := &http.Cookie{
		Name:     c.CookieName,
		Value:    token,
		Path:     c.CookiePath,
		Domain:   c.CookieDomain,
		HttpOnly: true,
		Secure:   c.Secure,
		SameSite: c.SameSite,
	}
	if rememberMe == nil || *rememberMe {
		cookie.Expires = time.Now().Add(c.Expiry)
		cookie.MaxAge = int(c.Expiry.Seconds())
	}
	http.SetCookie(w, cookie)
}

func (c Config) ClearCookie(w http.ResponseWriter) {
	c.SetDefaults(c.Secure)
	http.SetCookie(w, &http.Cookie{
		Name:     c.CookieName,
		Value:    "",
		Path:     c.CookiePath,
		Domain:   c.CookieDomain,
		HttpOnly: true,
		Secure:   c.Secure,
		SameSite: c.SameSite,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}
