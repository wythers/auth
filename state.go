package auth

import (
	"crypto/sha256"
	"net"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/securecookie"
	"golang.org/x/net/publicsuffix"
)

const (

	// SessionHalfAuthKey is used for sessions that have been authenticated by
	// the remember module. This serves as a way to force full authentication
	// by denying half-authed users acccess to sensitive areas.
	Auth_Comfirmed = "comfirmed"
	// SessionLastAction is the session key to retrieve the
	// last action of a user.
	Auth_LastAction = "last_action"

	Auth_ResetToken = "reset_token"
	// Session2FA is set when a user has been authenticated with a second factor
	Auth_2FA = "2fa"
	// Session2FAAuthToken is a random token set in the session to be verified
	// by e-mail.
	Auth_2FAAuthToken = "2fa_auth_token"
	// Session2FAAuthed is in the session (and set to "true") when the user
	// has successfully verified the token sent via e-mail in the two factor
	// e-mail authentication process.
	Auth_2FAAuthed = "2fa_authed"
	// SessionOAuth2State is the xsrf protection key for oauth.
	Auth_OAuth2State = "oauth2_state"
	// SessionOAuth2Params is the additional settings for oauth
	// like redirection/remember.
	Auth_OAuth2Params = "oauth2_params"

	Auth_CSRFToken = "csrf_token"
)

// ClientStateEventKind is an enum.
type ClientStateEventKind int

// ClientStateEvent kinds
const (
	// ClientStateEventPut means you should put the key-value pair into the
	// client state.
	ClientStateEventPut ClientStateEventKind = iota
	// ClientStateEventPut means you should delete the key-value pair from the
	// client state.
	ClientStateEventDel
	// ClientStateEventDelAll means you should delete EVERY key-value pair from
	// the client state - though a whitelist of keys that should not be deleted
	// may be passed through as a comma separated list of keys in
	// the ClientStateEvent.Key field.
	ClientStateEventDelAll
)

// ClientState represents the client's current state and can answer queries
// about it.
type State map[string]any

func (s State) Get(key string) (any, bool) {
	val, ok := s[key]
	return val, ok
}

func (s State) Set(key string, value any) {
	s[key] = value
}

func (s State) Del(key string) {
	delete(s, key)
}

// NewResponse wraps the ResponseWriter with a ClientStateResponseWriter
func (e *Engine) NewState(c *gin.Context) State {
	return State{}
}

// ClientStateReadWriter is used to create a cookie storer from an http request.
// Keep in mind security considerations for your implementation, Secure,
// HTTP-Only, etc flags.
//
// There's two major uses for this. To create session storage, and remember me
// cookies.
type StateReadWriter interface {
	// ReadState should return a map like structure allowing it to look up
	// any values in the current session, or any cookie in the request
	Load(string) (State, error)
	// WriteState can sometimes be called with a nil ClientState in the event
	// that no ClientState was read in from LoadClientState
	Save(State) error
}

// LoadClientState loads the state from sessions and cookies
// into the ResponseWriter for later use.
// func (e *Engine) LoadClientState(pid string) (State, error) {
// 	if e.Storage.StateStorer == nil {
// 		panic("auth db is not set")
// 	}

// 	state, err := e.Storage.StateStorer.Load(pid)
// 	if err != nil {
// 		return nil, err
// 	}

// 	return state, nil
// }

func IsFullyAuthed(c *gin.Context) bool {
	comfirmed, ok := c.Get(string(Auth_Comfirmed))

	if !ok {
		return false
	}

	return comfirmed.(bool)
}

// IsTwoFactored returns false if the user doesn't have a Session2FA
// in his session.
func IsTwoFactored(c *gin.Context) bool {
	twoFactored, ok := c.Get(string(Auth_2FA))
	if !ok {
		return false
	}

	return twoFactored.(bool)
}

// DelAllSession deletes all variables in the session except for those on
// the whitelist.
//
// The whitelist is typically provided directly from the authboss config.
//
// This is the best way to ensure the session is cleaned up after use for
// a given user. An example is when a user is expired or logged out this method
// is called.
// func (e *Engine) UpdateAuthState(c *gin.Context, whitelist []string) error {
// 	state, ok := c.Get(string(CTXKeyAuthState))
// 	if !ok {
// 		return errors.New("auth state not found in context")
// 	}

// 	var tmp State = make(map[string]any)
// 	for _, key := range whitelist {
// 		val, ok := state.(State).Get(key)
// 		if ok {
// 			tmp[key] = val
// 		}
// 	}

// 	err := e.Storage.StateStorer.Save(tmp)
// 	if err != nil {
// 		return err
// 	}

// 	c.Set(string(CTXKeyAuthState), tmp)
// 	return nil
// }

// func SetJwtHeader(c *gin.Context, token string) {
// 	if token != "" {
// 		c.Header("Authorization", "Bearer "+token)
// 	}
// }

func SetState(c *gin.Context, key string, value any) {
	state, ok := c.Get(string(CTXKeyAuthState))
	if !ok {
		c.Set(string(CTXKeyAuthState), State{key: value})
		return
	}

	state.(State).Set(key, value)
}

// SetAccessToken 使用与 ParseMiddleware 相同的 securecookie 编码规则
// 接收 Engine 与 pid，并自动设置跨站 Cookie 属性：
// - SameSite=None, Secure=true, HttpOnly=true, Path=/
// - Domain 基于请求 Host 的 eTLD+1；若为 localhost/IP，则使用 HostOnly
// - MaxAge 使用 e.Config.CookieMaxAge（秒），为空则默认 15 分钟
func SetAccessToken(c *gin.Context, e *Engine, pid string) error {
	hashKey := e.Config.CookieSecret
	encKey := sha256.Sum256(append([]byte("enc:"), e.Config.CookieSecret...))
	sc := securecookie.New(hashKey, encKey[:])

	payload := struct {
		PID string
	}{PID: pid}

	encoded, err := sc.Encode("access_token", payload)
	if err != nil {
		return err
	}

	domain := baseDomain(c.Request.Host)

	c.SetSameSite(http.SameSiteNoneMode)
	maxAge := e.Config.CookieMaxAge
	if maxAge == 0 {
		maxAge = 15 * 60
	}

	c.SetCookie("access_token", encoded, maxAge, "/", domain, true, true)
	return nil
}

func ClearAccessToken(c *gin.Context, e *Engine) {
	domain := baseDomain(c.Request.Host)
	c.SetSameSite(http.SameSiteNoneMode)
	c.SetCookie("access_token", "", -1, "/", domain, true, true)
}

func baseDomain(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if net.ParseIP(host) != nil || host == "localhost" {
		return ""
	}
	if d, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		return d
	}
	return ""
}
