package limit

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/wythers/auth"
)

func TestLimitMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Logf("Starting limit middleware tests with Redis URL: redis://localhost:6379/0")

	e := auth.New(auth.WithRateLimit("3-S", "redis://localhost:6379/0", nil))

	tests := []struct {
		name          string
		clientIP      string
		numRequests   int
		expectedCodes []int
		sleepBetween  time.Duration
	}{
		{
			name:          "Normal requests within limit",
			clientIP:      "127.0.0.1",
			numRequests:   3,
			expectedCodes: []int{http.StatusOK, http.StatusOK, http.StatusOK},
			sleepBetween:  0,
		},
		{
			name:        "Exceed rate limit",
			clientIP:    "192.168.1.1",
			numRequests: 5,
			expectedCodes: []int{
				http.StatusOK,
				http.StatusOK,
				http.StatusOK,              // 前3次成功
				http.StatusTooManyRequests, // 第4次被限流
				http.StatusTooManyRequests, // 第5次被限流
			},
			sleepBetween: 0,
		},
		{
			name:        "Rate limit reset after wait",
			clientIP:    "192.168.1.2",
			numRequests: 5,
			expectedCodes: []int{
				http.StatusOK,
				http.StatusOK,
				http.StatusOK,              // 前3次快速请求成功
				http.StatusTooManyRequests, // 第4次被限流
				http.StatusOK,              // 等待后成功
			},
			sleepBetween: time.Second, // 只在第4次请求后等待
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("=== Test case: %s ===", tt.name)
			t.Logf("Client IP: %s", tt.clientIP)
			t.Logf("Number of requests: %d", tt.numRequests)
			t.Logf("Expected status codes: %v", tt.expectedCodes)
			t.Logf("Sleep between requests: %v", tt.sleepBetween)

			router := gin.New()
			router.ForwardedByClientIP = true
			router.Use(Middleware(e))

			router.GET("/test", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"status": "success"})
			})

			var actualCodes []int

			for i := 0; i < tt.numRequests; i++ {
				t.Logf("Making request %d/%d", i+1, tt.numRequests)

				req := httptest.NewRequest("GET", "/test", nil)
				req.RemoteAddr = tt.clientIP + ":12345"

				w := httptest.NewRecorder()
				router.ServeHTTP(w, req)

				actualCodes = append(actualCodes, w.Code)

				// 记录响应头信息
				t.Logf("Response status: %d", w.Code)
				t.Logf("X-RateLimit-Limit: %s", w.Header().Get("X-RateLimit-Limit"))
				t.Logf("X-RateLimit-Remaining: %s", w.Header().Get("X-RateLimit-Remaining"))
				t.Logf("X-RateLimit-Reset: %s", w.Header().Get("X-RateLimit-Reset"))

				// 只在第4次请求后等待
				if i == 3 && tt.sleepBetween > 0 {
					t.Logf("Sleeping for %v after request %d", tt.sleepBetween, i+1)
					time.Sleep(tt.sleepBetween)
				}
			}

			t.Logf("Expected codes: %v", tt.expectedCodes)
			t.Logf("Actual codes:   %v", actualCodes)

			if !assert.Equal(t, tt.expectedCodes, actualCodes) {
				t.Errorf("Status codes mismatch. Expected %v but got %v",
					tt.expectedCodes, actualCodes)
			}
		})
	}
}

func TestLimitMiddlewareErrors(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Log("Testing error handling scenarios")

	t.Run("Invalid rate format", func(t *testing.T) {
		t.Log("Testing with invalid rate format 'invalid'")
		e := auth.New(auth.WithRateLimit("3-S", "redis://localhost:6379/0", nil))
		e.Config.NewRateFormat = "invalid"

		assert.Panics(t, func() {
			t.Log("Expecting panic with invalid rate format")
			Middleware(e)
		})
		t.Log("Successfully caught panic for invalid rate format")
	})

	t.Run("Invalid Redis URL", func(t *testing.T) {
		t.Log("Testing with invalid Redis URL 'invalid://url'")
		e := auth.New(auth.WithRateLimit("3-S", "redis://localhost:6379/0", nil))
		e.Config.LimitRedisURL = "invalid://url"

		assert.Panics(t, func() {
			t.Log("Expecting panic with invalid Redis URL")
			Middleware(e)
		})
		t.Log("Successfully caught panic for invalid Redis URL")
	})
}

func TestLimitMiddlewareHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Log("Testing response headers")

	e := auth.New(auth.WithRateLimit("3-S", "redis://localhost:6379/0", nil))
	e.Config.NewRateFormat = "3-S"
	e.Config.LimitRedisURL = "redis://localhost:6379/0"

	router := gin.New()
	router.Use(Middleware(e))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "success"})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	w := httptest.NewRecorder()

	t.Log("Making test request")
	router.ServeHTTP(w, req)

	t.Logf("Response Headers:")
	t.Logf("  X-RateLimit-Limit: %s", w.Header().Get("X-RateLimit-Limit"))
	t.Logf("  X-RateLimit-Remaining: %s", w.Header().Get("X-RateLimit-Remaining"))
	t.Logf("  X-RateLimit-Reset: %s", w.Header().Get("X-RateLimit-Reset"))

	assert.NotEmpty(t, w.Header().Get("X-RateLimit-Limit"), "X-RateLimit-Limit should not be empty")
	assert.NotEmpty(t, w.Header().Get("X-RateLimit-Remaining"), "X-RateLimit-Remaining should not be empty")
	assert.NotEmpty(t, w.Header().Get("X-RateLimit-Reset"), "X-RateLimit-Reset should not be empty")
}
