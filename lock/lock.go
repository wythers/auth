package lock

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wythers/auth"
	"go.uber.org/zap"
)

func init() {
	// auth.RegisterModule("login", auth.Module(Handler[auth.UserValuer]))
}

func IsLockedLogin(user auth.User) bool {
	lu, ok := user.(auth.LoginLockableUser)
	if !ok {
		return false
	}

	if lu.GetLoginLockedUntil().After(time.Now().UTC()) {
		return true
	}

	return false
}

func IsLockedRecover(user auth.User) bool {
	ru, ok := user.(auth.RecoverLockableUser)
	if !ok {
		return false
	}

	if ru.GetRecoverLockedUntil().After(time.Now().UTC()) {
		return true
	}

	return false
}

func UpdatedLoginLockedState(e *auth.Engine, c *gin.Context, user auth.User, success bool) {
	logger := e.RequestLogger()
	lu, ok := user.(auth.LoginLockableUser)
	if !ok {
		return
	}

	if !success {
		last := lu.GetLoginLastAttempt()
		attempts := lu.GetLoginAttemptCount()
		attempts++

		if time.Now().UTC().Sub(last) <= e.Config.LoginLockWindow {
			if attempts >= e.Config.LoginAttempts {
				lu.PutLoginLockedUntil(time.Now().UTC().Add(e.Config.LoginLockDuration))
				logger.Info("user locked", zap.String("pid", lu.GetPID()))
			}

			lu.PutLoginAttemptCount(attempts)
		} else {
			lu.PutLoginAttemptCount(1)
		}
	}
	lu.PutLoginLastAttempt(time.Now().UTC())

	if err := e.Storage.Server.Save(c, user); err != nil {
		logger.Error("failed to update user", zap.Error(err))
	}
}

func UpdatedRecoverLockedState(e *auth.Engine, c *gin.Context, user auth.User, success bool) {
	logger := e.RequestLogger()
	ru, ok := user.(auth.RecoverLockableUser)
	if !ok {
		return
	}

	if !success {
		last := ru.GetRecoverLastAttempt()
		attempts := ru.GetRecoverAttemptCount()
		attempts++

		if time.Now().UTC().Sub(last) <= e.Config.RecoverLockWindow {
			if attempts >= e.Config.RecoverAttempts {
				ru.PutRecoverLockedUntil(time.Now().UTC().Add(e.Config.RecoverLockDuration))
				logger.Info("user locked", zap.String("pid", ru.GetPID()))
			}

			ru.PutRecoverAttemptCount(attempts)
		} else {
			ru.PutRecoverAttemptCount(1)
		}
	}
	ru.PutRecoverLastAttempt(time.Now().UTC())

	if err := e.Storage.Server.Save(c, user); err != nil {
		logger.Error("failed to update user", zap.Error(err))
	}
}
