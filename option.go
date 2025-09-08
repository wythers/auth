package auth

import (
	"time"

	"go.uber.org/zap"
)

type Option func(*Engine)

func WithRootURL(rootURL string) Option {
	return func(e *Engine) {
		e.Config.RootURL = rootURL
	}
}

func WithServer(server ServerStorer) Option {
	return func(e *Engine) {
		e.Storage.Server = server
	}
}

func WithRenderer(renderer Renderer) Option {
	return func(e *Engine) {
		e.HTMLRenderer = renderer
	}
}

func WithMailer(mailer Mailer) Option {
	return func(e *Engine) {
		e.Mailer = mailer
	}
}

func WithMailConfig(mailFrom, mailFromName, mailSubjectPrefix string) Option {
	return func(e *Engine) {
		e.Config.MailFrom = mailFrom
		e.Config.MailFromName = mailFromName
		e.Config.MailSubjectPrefix = mailSubjectPrefix
	}
}

func WithRecoverConfig(tokenDuration, lockWindow, lockDuration time.Duration, attempts int) Option {
	return func(e *Engine) {
		e.Config.RecoverTokenDuration = tokenDuration
		e.Config.RecoverLockWindow = lockWindow
		e.Config.RecoverLockDuration = lockDuration
		e.Config.RecoverAttempts = attempts
	}
}

func WithLoginConfig(lockWindow, lockDuration time.Duration, attempts int) Option {
	return func(e *Engine) {
		e.Config.LoginLockWindow = lockWindow
		e.Config.LoginLockDuration = lockDuration
		e.Config.LoginAttempts = attempts
	}
}

func WithRateLimit(rateFormat, redisURL string, excludedKeyFunc func(string) bool) Option {
	return func(e *Engine) {
		e.Config.NewRateFormat = rateFormat
		e.Config.LimitRedisURL = redisURL
		e.Config.LimitExcludedKey = excludedKeyFunc
	}
}

func WithCookieConfig(maxAge int) Option {
	return func(e *Engine) {
		e.Config.CookieMaxAge = maxAge
	}
}

func WithBCryptCost(cost int) Option {
	return func(e *Engine) {
		e.Utils.Hasher = setHasher(cost)
	}
}

func WithLogger(logger *zap.Logger) Option {
	return func(e *Engine) {
		e.Logger = logger
	}
}

func WithCookieSecret(cookieSecret string) Option {
	return func(e *Engine) {
		e.Config.CookieSecret = setCookieSecret(cookieSecret)
	}
}

func WithHasher(hasher Hasher) Option {
	return func(e *Engine) {
		e.Utils.Hasher = hasher
	}
}

func WithOneTimeCodeGenerator(generator OneTimeTokenGenerator) Option {
	return func(e *Engine) {
		e.Utils.OneTimeCodeGenerator = generator
	}
}

func WithOneTimeSha512TokenGenerator(generator OneTimeTokenGenerator) Option {
	return func(e *Engine) {
		e.Utils.OneTimeSha512TokenGenerator = generator
	}
}
