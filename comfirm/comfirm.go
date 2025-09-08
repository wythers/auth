package comfirm

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/wythers/auth"
	"go.uber.org/zap"
)

const (
	PageComfirm = "comfirm"
)

type Requester interface {
	GetPID() string
	GetCode() string
}

func init() {
	// auth.RegisterModule("comfirm", auth.Module(Handler[auth.User]))
}

func Handler[Req Requester](e *auth.Engine, collectMiddleware ...gin.HandlerFunc) []gin.HandlerFunc {
	if len(collectMiddleware) == 0 {
		collectMiddleware = []gin.HandlerFunc{auth.DefaultCollectMiddleware}
	}

	middlewares := []gin.HandlerFunc{
		UserHereMiddleware(e),
		ValidateMiddleware[Req](e),
	}

	return append(middlewares, collectMiddleware...)
}

func Middleware(e *auth.Engine) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger := e.RequestLogger()

		user, err := e.CurrentUser(c)
		if err == auth.ErrPIDNotFound {
			logger.Warn("confirm middleware - user not found in session",
				zap.Error(err),
				zap.String("remote_addr", c.ClientIP()),
				zap.String("method", c.Request.Method),
				zap.String("path", c.Request.URL.Path))
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		if err != nil {
			logger.Error("confirm middleware - failed to load current user",
				zap.Error(err),
				zap.String("remote_addr", c.ClientIP()),
				zap.String("method", c.Request.Method),
				zap.String("path", c.Request.URL.Path),
				zap.String("user_agent", c.GetHeader("User-Agent")))
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		comfirmableUser := auth.MustBeConfirmable(user)
		if comfirmableUser.GetConfirmed() {
			logger.Info("user already confirmed - allowing access",
				zap.String("pid", user.GetPID()),
				zap.String("remote_addr", c.ClientIP()))
			auth.SetState(c, auth.Auth_Comfirmed, comfirmableUser.GetConfirmed())
			return
		}

		logger.Warn("access denied - user not confirmed",
			zap.String("pid", user.GetPID()),
			zap.String("remote_addr", c.ClientIP()),
			zap.String("method", c.Request.Method),
			zap.String("path", c.Request.URL.Path))
		c.AbortWithStatus(http.StatusUnauthorized)
	}
}

func UserHereMiddleware(e *auth.Engine) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger := e.RequestLogger()

		_, err := e.CurrentUser(c)
		if err == auth.ErrPIDNotFound {
			logger.Warn("user here middleware - user not found in session",
				zap.Error(err),
				zap.String("remote_addr", c.ClientIP()),
				zap.String("method", c.Request.Method),
				zap.String("path", c.Request.URL.Path))
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		if err != nil {
			logger.Error("user here middleware - failed to load current user",
				zap.Error(err),
				zap.String("remote_addr", c.ClientIP()),
				zap.String("method", c.Request.Method),
				zap.String("path", c.Request.URL.Path),
				zap.String("user_agent", c.GetHeader("User-Agent")))
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
	}
}

func ValidateMiddleware[Req Requester](e *auth.Engine) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger := e.RequestLogger()

		var verifier Req
		if err := c.ShouldBind(&verifier); err != nil {
			logger.Error("failed to bind confirmation verifier",
				zap.Error(err),
				zap.String("remote_addr", c.ClientIP()),
				zap.String("method", c.Request.Method),
				zap.String("path", c.Request.URL.Path),
				zap.String("content_type", c.GetHeader("Content-Type")))
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}

		user, err := e.CurrentUser(c)
		if err == auth.ErrPIDNotFound {
			logger.Warn("confirm validation - user not found in session",
				zap.Error(err),
				zap.String("remote_addr", c.ClientIP()),
				zap.String("method", c.Request.Method),
				zap.String("path", c.Request.URL.Path))
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		if err != nil {
			logger.Error("confirm validation - failed to load current user",
				zap.Error(err),
				zap.String("remote_addr", c.ClientIP()),
				zap.String("method", c.Request.Method),
				zap.String("path", c.Request.URL.Path),
				zap.String("user_agent", c.GetHeader("User-Agent")))
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		comfirmableUser := auth.MustBeConfirmable(user)
		// if comfirmableUser.GetConfirmed() {
		// 	logger.Info("user already comfirmed")
		// 	auth.SetState(c, auth.Auth_Comfirmed, comfirmableUser.GetConfirmed())
		// 	return
		// }

		stored := comfirmableUser.GetConfirmVerifier()
		if stored == "" {
			logger.Error("confirm validation - stored verifier is empty",
				zap.String("pid", user.GetPID()),
				zap.String("remote_addr", c.ClientIP()),
				zap.String("method", c.Request.Method),
				zap.String("path", c.Request.URL.Path))
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		if !e.Utils.OneTimeCodeGenerator.Compare(stored, verifier.GetCode()) {
			logger.Warn("confirm validation failed - invalid verification code",
				zap.String("pid", user.GetPID()),
				zap.String("provided_code", verifier.GetCode()),
				zap.String("remote_addr", c.ClientIP()),
				zap.String("user_agent", c.GetHeader("User-Agent")),
				zap.String("method", c.Request.Method))
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}

		comfirmableUser.PutConfirmed(true)
		comfirmableUser.PutConfirmVerifier("")

		auth.SetState(c, auth.Auth_Comfirmed, comfirmableUser.GetConfirmed())
	}
}
