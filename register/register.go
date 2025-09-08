package register

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/wythers/auth"
	"github.com/wythers/auth/login"
	"github.com/wythers/auth/mail"
	"go.uber.org/zap"
)

const (
	PageRegister = "register"

	RegisterConfirmHTML = "register_confirm_html"
	RegisterConfirmTxt  = "register_confirm_txt"

	DataCode = "code"
)

type Requester interface {
	GetPID() string
}

type RequestWithPassworder interface {
	Requester
	GetPassword() string
}

func init() {
	// auth.RegisterModule("login", auth.Module(Handler[auth.UserValuer]))
}

func Handler[Req RequestWithPassworder](e *auth.Engine, collectMiddleware ...gin.HandlerFunc) []gin.HandlerFunc {
	if len(collectMiddleware) == 0 {
		collectMiddleware = []gin.HandlerFunc{auth.DefaultCollectMiddleware}
	}

	middlewares := []gin.HandlerFunc{
		ValidateMiddleware[Req](e),
		SendConfirmEmailMiddleware(e),
		mail.Middleware(e),
	}

	return append(middlewares, collectMiddleware...)
}

func ResendMailHanlder(e *auth.Engine) []gin.HandlerFunc {
	return []gin.HandlerFunc{
		login.LoggedInMiddleware(e),
		SendConfirmEmailMiddleware(e),
		mail.Middleware(e),
	}
}

func CheckPIDMiddleware[Req Requester](e *auth.Engine) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger := e.RequestLogger()

		var r Req
		if err := c.ShouldBind(&r); err != nil {
			logger.Error("failed to bind user", zap.Error(err))
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}

		_, err := e.CurrentUserByPID(c, r.GetPID())
		if err == nil {
			logger.Error("user already exists", zap.String("pid", r.GetPID()))
			c.AbortWithStatus(http.StatusConflict) // 409 Conflict
			return
		}

		if err != auth.ErrPIDNotFound {
			logger.Error("failed to get user by pid", zap.String("pid", r.GetPID()), zap.Error(err))
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}

		c.Status(http.StatusOK)
	}
}

func ValidateMiddleware[Req RequestWithPassworder](e *auth.Engine) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger := e.RequestLogger()

		var r Req
		if err := c.ShouldBind(&r); err != nil {
			logger.Error("failed to bind registration request",
				zap.Error(err),
				zap.String("remote_addr", c.ClientIP()),
				zap.String("method", c.Request.Method),
				zap.String("path", c.Request.URL.Path),
				zap.String("content_type", c.GetHeader("Content-Type")),
				zap.String("user_agent", c.GetHeader("User-Agent")))
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}

		_, err := e.CurrentUserByPID(c, r.GetPID())
		if err == nil {
			logger.Warn("registration attempt with existing user",
				zap.String("pid", r.GetPID()),
				zap.String("remote_addr", c.ClientIP()),
				zap.String("user_agent", c.GetHeader("User-Agent")),
				zap.String("method", c.Request.Method))
			c.AbortWithStatus(http.StatusConflict) // 409 Conflict
			return
		}

		if err != auth.ErrPIDNotFound {
			logger.Error("failed to check user existence during registration",
				zap.String("pid", r.GetPID()),
				zap.Error(err),
				zap.String("remote_addr", c.ClientIP()),
				zap.String("method", c.Request.Method),
				zap.String("user_agent", c.GetHeader("User-Agent")))
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		password := r.GetPassword()
		passwordHash, err := e.Utils.Hasher.GenerateHash(password)
		if err != nil {
			logger.Error("failed to generate password hash during registration",
				zap.String("pid", r.GetPID()),
				zap.Error(err),
				zap.String("remote_addr", c.ClientIP()),
				zap.String("method", c.Request.Method))
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		store := e.Storage.Server
		authableUser := auth.MustBeAuthable(store.New(c.Request.Context(), r.GetPID()))
		authableUser.PutPassword(passwordHash)

		if err := store.Create(c.Request.Context(), authableUser); err != nil {
			logger.Error("failed to create user in database during registration",
				zap.String("pid", authableUser.GetPID()),
				zap.Error(err),
				zap.String("remote_addr", c.ClientIP()),
				zap.String("method", c.Request.Method))
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		c.Set(string(auth.CTXKeyPID), authableUser.GetPID())
		c.Set(string(auth.CTXKeyUser), authableUser)
		auth.SetState(c, auth.Auth_Comfirmed, false)
	}
}

func SendConfirmEmailMiddleware(e *auth.Engine) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger := e.RequestLogger()

		plain, stored, err := e.Utils.OneTimeCodeGenerator.Generate()
		if err != nil {
			logger.Error("failed to generate confirmation code for registration",
				zap.Error(err),
				zap.String("remote_addr", c.ClientIP()),
				zap.String("method", c.Request.Method),
				zap.String("path", c.Request.URL.Path))
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		user := c.MustGet(string(auth.CTXKeyUser)).(auth.ConfirmableUser)
		user.PutConfirmVerifier(stored)
		user.PutConfirmed(false)
		if err := e.Storage.Server.Save(c.Request.Context(), user); err != nil {
			logger.Error("failed to save user with confirmation verifier",
				zap.String("pid", user.GetPID()),
				zap.Error(err),
				zap.String("remote_addr", c.ClientIP()),
				zap.String("method", c.Request.Method))
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		to := user.GetEmail()
		if to == "" {
			logger.Error("registration confirmation email failed - user email is empty",
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
			Subject:  e.Config.MailSubjectPrefix + "Confirm New Account",
		}
		md := map[string]auth.HTMLData{
			RegisterConfirmHTML: {
				DataCode: plain,
			},
			RegisterConfirmTxt: {
				DataCode: plain,
			},
		}

		c.Set(string(auth.CTXKeyMail), &email)
		c.Set(string(auth.CTXKeyEmailData), md)

		auth.SetAccessToken(c, e, user.GetPID())
	}
}
