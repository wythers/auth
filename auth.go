package auth

import (
	"crypto/sha256"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/securecookie"
	"go.uber.org/zap"
)

var (
	salt = []byte("authboss")
	Auth *Engine
)

type Engine struct {
	Storage struct {
		Server ServerStorer
	}

	Config struct {
		RootURL string

		CookieSecret []byte
		CookieMaxAge int

		RecoverTokenDuration time.Duration

		LoginLockWindow   time.Duration
		LoginLockDuration time.Duration
		LoginAttempts     int

		RecoverLockWindow   time.Duration
		RecoverLockDuration time.Duration
		RecoverAttempts     int

		// S: second, M: minute, H: hour, D: day, for example: 3-M equals 3 requests per minute
		NewRateFormat    string
		LimitRedisURL    string
		LimitExcludedKey func(string) bool

		MailFrom          string
		MailFromName      string
		MailSubjectPrefix string
	}

	HTMLRenderer Renderer

	Mailer Mailer

	Utils struct {
		// Hasher hashes passwords into hashes
		Hasher Hasher

		OneTimeCodeGenerator OneTimeTokenGenerator

		OneTimeSha512TokenGenerator OneTimeTokenGenerator
	}

	Logger *zap.Logger
}

func (e *Engine) AuthMiddlewares() []gin.HandlerFunc {
	return []gin.HandlerFunc{
		e.ParseMiddleware,
		//		e.LoadAuthStateMiddleware,
	}
}

func (e *Engine) RequestLogger() *zap.Logger {
	return e.Logger
}

func New(options ...Option) *Engine {
	engine := &Engine{
		Storage: struct {
			Server ServerStorer
			//		StateStorer StateReadWriter
		}{
			Server: nil,
			//			StateStorer: nil,
		},

		HTMLRenderer: nil,
		Mailer:       nil,

		Config: struct {
			RootURL      string
			CookieSecret []byte
			CookieMaxAge int

			RecoverTokenDuration time.Duration

			LoginLockWindow   time.Duration
			LoginLockDuration time.Duration
			LoginAttempts     int

			RecoverLockWindow   time.Duration
			RecoverLockDuration time.Duration
			RecoverAttempts     int

			// You can also use the simplified format "<limit>-<period>"", with the given
			// periods:
			//
			// * "S": second
			// * "M": minute
			// * "H": hour
			// * "D": day
			//
			// Examples:
			//
			// * 5 reqs/second: "5-S"
			// * 10 reqs/minute: "10-M"
			// * 1000 reqs/hour: "1000-H"
			// * 2000 reqs/day: "2000-D"
			NewRateFormat    string
			LimitRedisURL    string
			LimitExcludedKey func(string) bool

			MailFrom          string
			MailFromName      string
			MailSubjectPrefix string
		}{
			RootURL:      "",
			CookieSecret: setCookieSecret("auth"),
			CookieMaxAge: 0,

			RecoverTokenDuration: 10 * time.Minute,

			LoginLockWindow:   10 * time.Minute,
			LoginLockDuration: 10 * time.Minute,
			LoginAttempts:     10,

			RecoverLockWindow:   10 * time.Minute,
			RecoverLockDuration: 10 * time.Minute,
			RecoverAttempts:     10,

			NewRateFormat:    "3-S",
			LimitRedisURL:    "redis://localhost:6379/0",
			LimitExcludedKey: nil,

			MailFrom:          "",
			MailFromName:      "",
			MailSubjectPrefix: "",
		},
		Utils: struct {
			Hasher                      Hasher
			OneTimeCodeGenerator        OneTimeTokenGenerator
			OneTimeSha512TokenGenerator OneTimeTokenGenerator
		}{
			Hasher:                      setHasher(3),
			OneTimeCodeGenerator:        setOneTimeCodeGenerator(),
			OneTimeSha512TokenGenerator: setOneTimeSha512TokenGenerator(64),
		},
		Logger: nil,
	}

	for _, option := range options {
		option(engine)
	}

	return engine
}

func (e *Engine) ParseMiddleware(c *gin.Context) {
	logger := e.RequestLogger()

	raw, err := c.Cookie("access_token")
	if err == nil && raw != "" {
		hashKey := e.Config.CookieSecret
		encKey := sha256.Sum256(append([]byte("enc:"), e.Config.CookieSecret...))
		sc := securecookie.New(hashKey, encKey[:])

		var payload struct {
			PID string `json:"pid"`
		}
		if decErr := sc.Decode("access_token", raw, &payload); decErr == nil && payload.PID != "" {
			c.Set(string(CTXKeyPID), payload.PID)
			return
		} else if decErr != nil {
			logger.Info("failed to decode access_token cookie", zap.Error(decErr))
		}
		return
	}

	// logger.Info("access_token cookie not found or empty")
}

// DefaultCollectMiddleware default collect middleware
// user can pass in a custom collectMiddleware to replace this default implementation
func DefaultCollectMiddleware(c *gin.Context) {
	// try to get authentication state
	state, hasState := c.Get(string(CTXKeyAuthState))

	// try to get user PID
	pid, hasPID := c.Get(string(CTXKeyPID))

	response := gin.H{
		"code":    http.StatusOK,
		"message": "success",
	}

	// if there is a user PID, add it to the response
	if hasPID {
		response["pid"] = pid
	}

	// if there is an authentication state, add it to the response
	if hasState {
		response[string(CTXKeyAuthState)] = state
	}

	c.JSON(http.StatusOK, response)
}

func setCookieSecret(key string) []byte {
	if key == "" {
		panic("CookieSecret is null")
	}
	saltHash := sha256.Sum256([]byte(salt))
	raw := append([]byte(key), saltHash[:]...)
	secret := sha256.Sum256(raw)

	return secret[:]
}

func setHasher(BCryptCost int) Hasher {
	return NewBCryptHasher(BCryptCost)
}

func setOneTimeCodeGenerator() OneTimeTokenGenerator {
	return &DefaultOneTimeCodeGenerator{}
}

func setOneTimeSha512TokenGenerator(tokenSize int) OneTimeTokenGenerator {
	return &DefaultOneTimeSha512TokenGenerator{
		TokenSize: tokenSize,
	}
}
