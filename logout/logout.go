package logout

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/wythers/auth"
	"go.uber.org/zap"
)

const (
	PageLogout = "logout"
)

func init() {
	// auth.RegisterModule("logout", auth.Module(Handler[auth.User]))
}

func Handler(e *auth.Engine) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger := e.RequestLogger()
		_, err := e.CurrentUser(c)
		if err != nil {
			return
		}

		auth.ClearAccessToken(c, e)
		logger.Info("user logged out", zap.String("pid", c.MustGet(string(auth.CTXKeyPID)).(string)))
		c.Status(http.StatusOK)
	}
}
