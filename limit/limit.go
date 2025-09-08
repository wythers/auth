package limit

import (
	"net/http"

	"github.com/gin-gonic/gin"
	libredis "github.com/redis/go-redis/v9"
	"github.com/wythers/auth"

	limiter "github.com/ulule/limiter/v3"
	mgin "github.com/ulule/limiter/v3/drivers/middleware/gin"
	sredis "github.com/ulule/limiter/v3/drivers/store/redis"
)

// router.ForwardedByClientIP = true
func Middleware(e *auth.Engine) gin.HandlerFunc {

	// Define a limit rate to 4 requests per hour.
	rate, err := limiter.NewRateFromFormatted(e.Config.NewRateFormat)
	if err != nil {
		panic(err)
	}

	// Create a redis client.
	// redis://localhost:6379/0
	option, err := libredis.ParseURL(e.Config.LimitRedisURL)
	if err != nil {
		panic(err)
	}
	client := libredis.NewClient(option)

	// Create a store with the redis client.
	store, err := sredis.NewStore(client)
	if err != nil {
		panic(err)
	}

	// Create a new middleware with the limiter instance.
	// middleware := mgin.NewMiddleware(limiter.New(store, rate))

	m := &mgin.Middleware{
		Limiter:        limiter.New(store, rate),
		OnError:        MustHandled,
		OnLimitReached: LimitReached,
		KeyGetter:      KeyGetter,
		ExcludedKey:    e.Config.LimitExcludedKey,
	}

	return m.Handle
}

func LimitReached(c *gin.Context) {
	c.Status(http.StatusTooManyRequests)
}

func MustHandled(c *gin.Context, err error) {
	panic(err)
}

func KeyGetter(c *gin.Context) string {
	return c.ClientIP()
}
