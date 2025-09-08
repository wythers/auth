package main

import (
	"os"

	"github.com/gin-gonic/gin"
	"github.com/wythers/auth"
	"github.com/wythers/auth/comfirm"
	"github.com/wythers/auth/limit"
	"github.com/wythers/auth/login"
	"github.com/wythers/auth/logout"
	"github.com/wythers/auth/mail"
	"github.com/wythers/auth/nocsrf"
	cover "github.com/wythers/auth/recover"
	"github.com/wythers/auth/register"
	"go.uber.org/zap"
)

func main() {
	mailRender := &MailRender{}
	err := mailRender.Load("template")
	if err != nil {
		panic(err)
	}

	// init auth engine
	e := auth.New(
		auth.WithLogger(zap.NewExample()),
		auth.WithCookieSecret("test"),
		auth.WithRootURL("http://localhost:8080"),
		auth.WithRateLimit("3-S", "redis://localhost:6379/0", nil),
		auth.WithServer(&Store{}),
		auth.WithRenderer(mailRender),
		auth.WithMailer(mail.NewLogMailer(os.Stdout)),
		auth.WithMailConfig(
			"no-reply@example.com",
			"Auth System",
			"[Auth] ",
		),
	)

	c := gin.Default()
	c.ForwardedByClientIP = true

	// use limit middleware globally
	c.Use(limit.Middleware(e))
	c.Use(nocsrf.Middleware(e)...)
	auth.RegisterCustomValidators()

	/*
		auth group
	*/
	{
		authGroup := c.Group("/auth", e.AuthMiddlewares()...)

		// 🔓 public operations - no CSRF
		{
			// use default CollectMiddleware (no parameters)
			authGroup.POST("/login", login.Handler[LoginRequest](e)...)
			authGroup.POST("/register", register.Handler[RegisterRequestWithPassworder](e)...)
			authGroup.POST("/register/check", register.CheckPIDMiddleware[RegisterRequest](e))
			authGroup.POST("/confirm", comfirm.Handler[ComfirmRequest](e)...)
			authGroup.POST("/recover/password/email", cover.ResetByEmailHandler[RecoverRequest](e)...)
			authGroup.POST("/recover/password/code", cover.ResetCodeHandler[RecoverRequestWithCode](e)...)
		}

		// 🔒 operations that need CSRF protection
		csrfGroup := authGroup.Group("", nocsrf.MustNoCSRFMiddleware(e)...)
		{
			// logout - prevent malicious logout
			csrfGroup.POST("/logout", logout.Handler(e))

			// password reset - actual password modification operation
			csrfGroup.POST("/recover/password/reset", cover.ResetPasswordHandler[RecoverRequestWithToken](e)...)

			// resend email - operation for logged-in users
			csrfGroup.POST("/register/resend", register.ResendMailHanlder(e)...)
		}
	}

	c.Run(":8080")
}
