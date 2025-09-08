// Package auth implements password based user logins.
package login

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/wythers/auth"
	"github.com/wythers/auth/lock"
	"go.uber.org/zap"
)

const (
	PageLogin = "login"
)

type Requester interface {
	GetPID() string
	GetPassword() string
}

func init() {
	// auth.RegisterModule("login", auth.Module(Handler[auth.UserValuer]))
}

func Handler[Req Requester](e *auth.Engine, collectMiddleware ...gin.HandlerFunc) []gin.HandlerFunc {
	if len(collectMiddleware) == 0 {
		collectMiddleware = []gin.HandlerFunc{auth.DefaultCollectMiddleware}
	}

	middlewares := []gin.HandlerFunc{
		LoggedInMiddleware(e),
		ValidateMiddleware[Req](e),
		LoginStateMiddleware(e),
	}

	return append(middlewares, collectMiddleware...)
}

func WhoAmIHandler(e *auth.Engine, collectMiddleware ...gin.HandlerFunc) []gin.HandlerFunc {
	if len(collectMiddleware) == 0 {
		collectMiddleware = []gin.HandlerFunc{auth.DefaultCollectMiddleware}
	}

	middlewares := []gin.HandlerFunc{
		LoggedInMiddleware(e),
	}

	return append(middlewares, collectMiddleware...)
}

func LoggedInMiddleware(e *auth.Engine) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger := e.RequestLogger()

		user, err := e.CurrentUser(c)
		if err == nil {
			logger.Info("user already logged in",
				zap.String("pid", user.GetPID()),
				zap.String("method", c.Request.Method),
				zap.String("path", c.Request.URL.Path),
				zap.String("remote_addr", c.ClientIP()))
		}

		if err != nil && err != auth.ErrPIDNotFound {
			logger.Error("failed to load current user in login middleware",
				zap.Error(err),
				zap.String("method", c.Request.Method),
				zap.String("path", c.Request.URL.Path),
				zap.String("remote_addr", c.ClientIP()),
				zap.String("user_agent", c.GetHeader("User-Agent")))
			c.AbortWithStatus(http.StatusInternalServerError)
		}
	}
}

func ValidateMiddleware[Req Requester](e *auth.Engine) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger := e.RequestLogger()

		_, err := e.CurrentUser(c)
		if err == nil {
			return
		}

		if err != auth.ErrPIDNotFound {
			logger.Error("failed to load current user during login validation",
				zap.Error(err),
				zap.String("method", c.Request.Method),
				zap.String("path", c.Request.URL.Path),
				zap.String("remote_addr", c.ClientIP()),
				zap.String("user_agent", c.GetHeader("User-Agent")))
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		var creds Req
		if err := c.ShouldBind(&creds); err != nil {
			logger.Error("failed to bind login credentials",
				zap.Error(err),
				zap.String("method", c.Request.Method),
				zap.String("path", c.Request.URL.Path),
				zap.String("remote_addr", c.ClientIP()),
				zap.String("content_type", c.GetHeader("Content-Type")))
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}

		pid := creds.GetPID()
		pidUser, err := e.CurrentUserByPID(c, pid)
		if err == auth.ErrUserNotFound {
			logger.Warn("login attempt with non-existent user",
				zap.String("pid", pid),
				zap.String("remote_addr", c.ClientIP()),
				zap.String("user_agent", c.GetHeader("User-Agent")),
				zap.String("method", c.Request.Method))
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		} else if err != nil {
			logger.Error("failed to load user by PID during login",
				zap.Error(err),
				zap.String("pid", pid),
				zap.String("remote_addr", c.ClientIP()),
				zap.String("method", c.Request.Method))
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		if lock.IsLockedLogin(pidUser) {
			logger.Warn("login attempt on locked account",
				zap.String("pid", pid),
				zap.String("remote_addr", c.ClientIP()),
				zap.String("user_agent", c.GetHeader("User-Agent")),
				zap.String("lock_reason", "too_many_failed_attempts"))
			c.AbortWithStatus(http.StatusLocked)
			return
		}

		authUser := auth.MustBeAuthable(pidUser)
		password := authUser.GetPassword()

		if err := e.Utils.Hasher.CompareHashAndPassword(password, creds.GetPassword()); err != nil {
			logger.Warn("login failed due to invalid password",
				zap.String("pid", pid),
				zap.String("remote_addr", c.ClientIP()),
				zap.String("user_agent", c.GetHeader("User-Agent")),
				zap.Error(err),
				zap.String("action", "incrementing_failed_attempts"))
			lock.UpdatedLoginLockedState(e, c, pidUser, false)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		lock.UpdatedLoginLockedState(e, c, pidUser, true)
		c.Set(string(auth.CTXKeyPID), pid)
		c.Set(string(auth.CTXKeyUser), pidUser)
		auth.SetAccessToken(c, e, pid)
	}
}

func LoginStateMiddleware(e *auth.Engine) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger := e.RequestLogger()

		user, err := e.CurrentUser(c)
		if err == auth.ErrPIDNotFound {
			pid := c.MustGet(string(auth.CTXKeyPID)).(string)
			logger.Warn("login state check failed - PID not found",
				zap.String("pid", pid),
				zap.String("remote_addr", c.ClientIP()),
				zap.String("method", c.Request.Method),
				zap.String("path", c.Request.URL.Path))
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		if err != nil {
			logger.Error("failed to load user during login state check",
				zap.Error(err),
				zap.String("remote_addr", c.ClientIP()),
				zap.String("method", c.Request.Method),
				zap.String("path", c.Request.URL.Path))
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		comfirmedUser := auth.MustBeConfirmable(user)
		logger.Info("login state check completed successfully",
			zap.String("pid", user.GetPID()),
			zap.Bool("confirmed", comfirmedUser.GetConfirmed()),
			zap.String("remote_addr", c.ClientIP()))
		auth.SetState(c, auth.Auth_Comfirmed, comfirmedUser.GetConfirmed())

	}
}

func WhoAmIMiddleware(e *auth.Engine) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := c.MustGet(string(auth.CTXKeyUser)).(auth.User)
		c.Set(string(auth.CTXKeyPID), user.GetPID())
		c.Set(string(auth.CTXKeyUser), user)

		comfirmedUser := auth.MustBeConfirmable(user)
		auth.SetState(c, auth.Auth_Comfirmed, comfirmedUser.GetConfirmed())
	}
}
