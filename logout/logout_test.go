package logout

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/securecookie"
	"github.com/wythers/auth"
	"go.uber.org/zap"
)

type mockUser struct{ PID string }

func (u *mockUser) GetPID() string    { return u.PID }
func (u *mockUser) PutPID(pid string) { u.PID = pid }

type mockServer struct{}

func (m *mockServer) Load(_ context.Context, pid string) (auth.User, error) {
	if pid == "testuser" {
		return &mockUser{PID: pid}, nil
	}
	return nil, auth.ErrUserNotFound
}
func (m *mockServer) Save(_ context.Context, _ auth.User) error { return nil }

func (m *mockServer) New(_ context.Context, _ string) auth.User {
	return &mockUser{PID: "testuser"}
}

func (m *mockServer) Create(_ context.Context, _ auth.User) error {
	return nil
}

func TestLogout_ClearsAccessTokenCookie(t *testing.T) {
	gin.SetMode(gin.TestMode)

	e := &auth.Engine{}
	e.Storage.Server = &mockServer{}
	e.Config.CookieSecret = []byte("test-cookie-secret")
	e.Config.CookieMaxAge = 900
	e.Logger, _ = zap.NewDevelopment()

	r := gin.New()
	// 解析 pid 用于通过 e.CurrentUser(c)
	r.Use(e.ParseMiddleware)
	r.POST("/logout", Handler(e))

	// 构造加密的 access_token Cookie，载荷含 pid
	hashKey := e.Config.CookieSecret
	encKey := sha256.Sum256(append([]byte("enc:"), e.Config.CookieSecret...))
	sc := securecookie.New(hashKey, encKey[:])
	val, err := sc.Encode("access_token", struct{ PID string }{PID: "testuser"})
	if err != nil {
		t.Fatalf("encode cookie failed: %v", err)
	}

	req := httptest.NewRequest("POST", "/logout", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: val})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// 响应 JSON
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json unmarshal failed: %v", err)
	}
	if resp["code"].(float64) != 200 {
		t.Errorf("expected code 200, got %v", resp["code"])
	}
	if resp["message"].(string) != "success" {
		t.Errorf("expected message 'success', got %v", resp["message"])
	}

	// 校验清除 Cookie
	cookies := w.Result().Cookies()
	cleared := false
	for _, ck := range cookies {
		if ck.Name == "access_token" {
			if ck.Value == "" && ck.MaxAge <= 0 {
				cleared = true
				break
			}
		}
	}
	if !cleared {
		t.Fatalf("expected cleared access_token cookie, got headers=%v", w.Header())
	}
}
