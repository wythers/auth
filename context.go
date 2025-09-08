package auth

import (
	"context"

	"github.com/gin-gonic/gin"
)

type contextKey string

// CTX Keys for authboss
const (
	CTXKeyPID  contextKey = "pid"
	CTXKeyUser contextKey = "user"

	CTXKeyAuthState contextKey = "auth_state"
	// CTXKeyCookieState  contextKey = "cookie"
	CTXKeyMail      contextKey = "mail"
	CTXKeyEmailData contextKey = "email_data"

	CTXKeyResetCode   contextKey = "reset_code"
	CTXKeyResetToken  contextKey = "reset_token"
	CTXKeyNewPassword contextKey = "new_password"

	CTXKeyCSRFToken contextKey = "csrf"

	// CTXKeyData is a context key for the accumulating
	// map[string]interface{} (authboss.HTMLData) to pass to the
	// renderer
	// CTXKeyData contextKey = "data"

	// CTXKeyValues is to pass the data submitted from API request or form
	// along in the context in case modules need it. The only module that needs
	// user information currently is remember so only auth/oauth2 are currently
	// going to use this.
	// CTXKeyValues contextKey = "values"
)

func (c contextKey) String() string {
	return "auth ctx key " + string(c)
}

// CurrentUserID retrieves the current user from the session.
// TODO(aarondl): This method never returns an error, one day we'll change
// the function signature.
func (a *Engine) CurrentUserID(c *gin.Context) (string, error) {
	if pid, ok := c.Get(string(CTXKeyPID)); ok {
		return pid.(string), nil
	}
	return "", ErrPIDNotFound
}

// CurrentUser retrieves the current user from the session and the database.
// Before the user is loaded from the database the context key is checked.
// If the session doesn't have the user ID ErrUserNotFound will be returned.
func (e *Engine) CurrentUser(c *gin.Context) (User, error) {
	if user, ok := c.Get(string(CTXKeyUser)); ok {
		return user.(User), nil
	}

	pid, err := e.CurrentUserID(c)
	if err != nil {
		return nil, err
	}

	user, err := e.currentUser(c.Request.Context(), pid)
	if err != nil {
		return nil, err
	}

	c.Set(string(CTXKeyUser), user)
	return user, nil
}

func (e *Engine) CurrentUserByPID(c *gin.Context, pid string) (User, error) {
	if user, ok := c.Get(string(CTXKeyUser)); ok {
		return user.(User), nil
	}

	user, err := e.currentUser(c.Request.Context(), pid)
	if err != nil {
		return nil, err
	}

	c.Set(string(CTXKeyUser), user)
	return user, nil
}

func (e *Engine) currentUser(ctx context.Context, pid string) (User, error) {
	return e.Storage.Server.Load(ctx, pid)
}
