package recover

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wythers/auth"
	"github.com/wythers/auth/lock"
	"github.com/wythers/auth/mail"
	"go.uber.org/zap"
)

const (
	PageRecover = "recover"

	RecoverPasswordHTML = "recover_password_html"
	RecoverPasswordTxt  = "recover_password_txt"

	DataRecoverCode = "code"
)

type Requester interface {
	GetPID() string
}

type RequestWithCoder interface {
	Requester
	GetCode() string
}

type RequestWithTokener interface {
	Requester
	GetToken() string
	GetPassword() string
}

func init() {
	// auth.RegisterModule("login", auth.Module(Handler[auth.UserValuer]))
}

// /auth/recover/password/email
func ResetByEmailHandler[Req Requester](e *auth.Engine, collectMiddleware ...gin.HandlerFunc) []gin.HandlerFunc {
	if len(collectMiddleware) == 0 {
		collectMiddleware = []gin.HandlerFunc{auth.DefaultCollectMiddleware}
	}

	middlewares := []gin.HandlerFunc{
		//	login.LoggedInMiddleware(e),
		ValidateMiddleware[Req](e),
		SendRecoverEmailMiddleware(e),
		mail.Middleware(e),
	}

	middlewares = append(middlewares, collectMiddleware...)

	return middlewares
}

func ResetCodeHandler[Req RequestWithCoder](e *auth.Engine, collectMiddleware ...gin.HandlerFunc) []gin.HandlerFunc {
	if len(collectMiddleware) == 0 {
		collectMiddleware = []gin.HandlerFunc{auth.DefaultCollectMiddleware}
	}

	middlewares := []gin.HandlerFunc{
		ValidateMiddleware[Req](e),
		VerifyMiddleware(e),
	}

	return append(middlewares, collectMiddleware...)
}

func ResetPasswordHandler[Req RequestWithTokener](e *auth.Engine, collectMiddleware ...gin.HandlerFunc) []gin.HandlerFunc {
	if len(collectMiddleware) == 0 {
		collectMiddleware = []gin.HandlerFunc{auth.DefaultCollectMiddleware}
	}

	middlewares := []gin.HandlerFunc{
		ValidateMiddleware[Req](e),
		ResetPasswordMiddleware(e),
	}

	return append(middlewares, collectMiddleware...)
}

func ValidateMiddleware[Req Requester](e *auth.Engine) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger := e.RequestLogger()

		// _, err := e.CurrentUser(c)
		// if err == nil {
		// 	return
		// }

		var r Req
		if err := c.ShouldBind(&r); err != nil {
			logger.Error("failed to bind password recovery request",
				zap.Error(err),
				zap.String("remote_addr", c.ClientIP()),
				zap.String("method", c.Request.Method),
				zap.String("path", c.Request.URL.Path),
				zap.String("content_type", c.GetHeader("Content-Type")),
				zap.String("user_agent", c.GetHeader("User-Agent")))
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}
		it, err := e.CurrentUserByPID(c, r.GetPID())
		if err == auth.ErrUserNotFound {
			logger.Warn("password recovery attempt for non-existent user",
				zap.String("pid", r.GetPID()),
				zap.String("remote_addr", c.ClientIP()),
				zap.String("user_agent", c.GetHeader("User-Agent")),
				zap.String("method", c.Request.Method))
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		if err != nil {
			logger.Error("failed to load user during password recovery",
				zap.String("pid", r.GetPID()),
				zap.Error(err),
				zap.String("remote_addr", c.ClientIP()),
				zap.String("method", c.Request.Method),
				zap.String("user_agent", c.GetHeader("User-Agent")))
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		if rc, ok := WithCode(r); ok {
			code := rc.GetCode()
			if code != "" {
				c.Set(string(auth.CTXKeyResetCode), code)
			}
		}

		if rt, ok := WithToken(r); ok {
			if rt.GetToken() != "" && rt.GetPassword() != "" {
				c.Set(string(auth.CTXKeyResetToken), rt.GetToken())
				c.Set(string(auth.CTXKeyNewPassword), rt.GetPassword())
			}
		}

		_ = auth.MustBeRecoverable(it)
		c.Set(string(auth.CTXKeyPID), it.GetPID())
		//c.Set(string(auth.CTXKeyUser), it)
	}
}

func SendRecoverEmailMiddleware(e *auth.Engine) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger := e.RequestLogger()

		user := c.MustGet(string(auth.CTXKeyUser)).(auth.RecoverableUser)

		if lock.IsLockedRecover(user) {
			logger.Warn("password recovery attempt on locked account",
				zap.String("pid", user.GetPID()),
				zap.String("remote_addr", c.ClientIP()),
				zap.String("user_agent", c.GetHeader("User-Agent")),
				zap.String("lock_reason", "too_many_recovery_attempts"))
			c.AbortWithStatus(http.StatusLocked) // 423 Locked
			return
		}

		plain, stored, err := e.Utils.OneTimeCodeGenerator.Generate()
		if err != nil {
			logger.Error("failed to generate recovery confirmation code",
				zap.Error(err),
				zap.String("remote_addr", c.ClientIP()),
				zap.String("method", c.Request.Method),
				zap.String("path", c.Request.URL.Path))
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		user.PutRecoverVerifier(stored)
		user.PutRecoverExpiry(time.Now().UTC().Add(e.Config.RecoverTokenDuration))
		if err := e.Storage.Server.Save(c.Request.Context(), user); err != nil {
			logger.Error("failed to save user with recovery verifier",
				zap.String("pid", user.GetPID()),
				zap.Error(err),
				zap.String("remote_addr", c.ClientIP()),
				zap.String("method", c.Request.Method))
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		to := user.GetEmail()
		if to == "" {
			logger.Error("password recovery email failed - user email is empty",
				zap.String("pid", user.GetPID()),
				zap.String("remote_addr", c.ClientIP()),
				zap.String("method", c.Request.Method))
			c.AbortWithStatus(http.StatusUnprocessableEntity) // 422 Unprocessable Entity for incomplete user data
			return
		}

		email := auth.Email{
			To:       []string{to},
			From:     e.Config.MailFrom,
			FromName: e.Config.MailFromName,
			Subject:  e.Config.MailSubjectPrefix + "Recover Account",
		}
		md := map[string]auth.HTMLData{
			RecoverPasswordHTML: {
				DataRecoverCode: plain,
			},
			RecoverPasswordTxt: {
				DataRecoverCode: plain,
			},
		}

		c.Set(string(auth.CTXKeyMail), &email)
		c.Set(string(auth.CTXKeyEmailData), md)

		lock.UpdatedRecoverLockedState(e, c, user, false)

		//	auth.SetAccessToken(c, e, user.GetPID())
	}
}

func VerifyMiddleware(e *auth.Engine) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger := e.RequestLogger()

		code, ok := c.Get(string(auth.CTXKeyResetCode))
		if !ok {
			logger.Error("password recovery verification failed - reset code is empty",
				zap.String("remote_addr", c.ClientIP()),
				zap.String("method", c.Request.Method),
				zap.String("path", c.Request.URL.Path))
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}
		user := c.MustGet(string(auth.CTXKeyUser)).(auth.RecoverableUser)

		if time.Now().UTC().After(user.GetRecoverExpiry()) {
			logger.Warn("password recovery verification failed - reset code expired",
				zap.String("pid", user.GetPID()),
				zap.Time("expired_at", user.GetRecoverExpiry()),
				zap.String("remote_addr", c.ClientIP()),
				zap.String("user_agent", c.GetHeader("User-Agent")))
			c.AbortWithStatus(http.StatusUnauthorized) // 401 Unauthorized for expired tokens
			return
		}

		if !e.Utils.OneTimeCodeGenerator.Compare(user.GetRecoverVerifier(), code.(string)) {
			logger.Warn("password recovery verification failed - invalid reset code",
				zap.String("pid", user.GetPID()),
				zap.String("provided_code", code.(string)),
				zap.String("remote_addr", c.ClientIP()),
				zap.String("user_agent", c.GetHeader("User-Agent")),
				zap.String("method", c.Request.Method))
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}

		user.PutRecoverVerifier("")
		user.PutRecoverExpiry(time.Now().UTC().Add(-e.Config.RecoverTokenDuration))

		plain, stored, err := e.Utils.OneTimeSha512TokenGenerator.Generate()
		if err != nil {
			logger.Error("failed to generate password reset token",
				zap.String("pid", user.GetPID()),
				zap.Error(err),
				zap.String("remote_addr", c.ClientIP()),
				zap.String("method", c.Request.Method))
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		user.PutResetToken(stored)
		user.PutResetTokenExpiry(time.Now().UTC().Add(e.Config.RecoverTokenDuration))
		if err := e.Storage.Server.Save(c.Request.Context(), user); err != nil {
			logger.Error("failed to save user with reset token",
				zap.String("pid", user.GetPID()),
				zap.Error(err),
				zap.String("remote_addr", c.ClientIP()),
				zap.String("method", c.Request.Method))
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		c.Set(string(auth.CTXKeyResetToken), plain)
		c.Set(string(auth.CTXKeyUser), user)
		auth.SetState(c, auth.Auth_ResetToken, plain)
	}
}

func ResetPasswordMiddleware(e *auth.Engine) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger := e.RequestLogger()
		recoverableUser := c.MustGet(string(auth.CTXKeyUser)).(auth.RecoverableUser)

		// Get the user-provided token from ValidateMiddleware, not the generated token from VerifyMiddleware
		token, ok := c.Get(string(auth.CTXKeyResetToken))
		if !ok {
			logger.Error("password reset failed - reset token is empty",
				zap.String("remote_addr", c.ClientIP()),
				zap.String("method", c.Request.Method),
				zap.String("path", c.Request.URL.Path))
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}
		rawToken := token.(string)

		if time.Now().UTC().After(recoverableUser.GetResetTokenExpiry()) {
			logger.Warn("password reset failed - reset token expired",
				zap.String("pid", recoverableUser.GetPID()),
				zap.Time("expired_at", recoverableUser.GetResetTokenExpiry()),
				zap.String("remote_addr", c.ClientIP()),
				zap.String("user_agent", c.GetHeader("User-Agent")))
			c.AbortWithStatus(http.StatusUnauthorized) // 401 Unauthorized for expired tokens
			return
		}

		if !e.Utils.OneTimeSha512TokenGenerator.Compare(recoverableUser.GetResetToken(), rawToken) {
			logger.Warn("password reset failed - invalid reset token",
				zap.String("pid", recoverableUser.GetPID()),
				zap.String("stored_token", recoverableUser.GetResetToken()),
				zap.String("provided_token", rawToken),
				zap.String("remote_addr", c.ClientIP()),
				zap.String("user_agent", c.GetHeader("User-Agent")),
				zap.String("method", c.Request.Method))
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}

		recoverableUser.PutResetToken("")
		recoverableUser.PutResetTokenExpiry(time.Now().UTC().Add(-e.Config.RecoverTokenDuration))

		ps := c.MustGet(string(auth.CTXKeyNewPassword)).(string)

		hash, err := e.Utils.Hasher.GenerateHash(ps)
		if err != nil {
			logger.Error("failed to generate password hash during reset",
				zap.String("pid", recoverableUser.GetPID()),
				zap.Error(err),
				zap.String("remote_addr", c.ClientIP()),
				zap.String("method", c.Request.Method))
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		recoverableUser.PutPassword(hash)
		if err := e.Storage.Server.Save(c.Request.Context(), recoverableUser); err != nil {
			logger.Error("failed to save user with new password",
				zap.String("pid", recoverableUser.GetPID()),
				zap.Error(err),
				zap.String("remote_addr", c.ClientIP()),
				zap.String("method", c.Request.Method))
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		logger.Info("password reset completed successfully",
			zap.String("pid", recoverableUser.GetPID()),
			zap.String("remote_addr", c.ClientIP()),
			zap.String("user_agent", c.GetHeader("User-Agent")))
	}
}

func WithCode(r Requester) (RequestWithCoder, bool) {
	rc, ok := r.(RequestWithCoder)
	return rc, ok
}

func WithToken(r Requester) (RequestWithTokener, bool) {
	rt, ok := r.(RequestWithTokener)
	return rt, ok
}
