package login

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"crypto/sha256"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/securecookie"
	"github.com/wythers/auth"
	"go.uber.org/zap"
)

type mockUser struct {
	PID       string
	Password  string
	Email     string
	Confirmed bool
	Verifier  string
}

func (u mockUser) GetPID() string      { return u.PID }
func (u mockUser) GetPassword() string { return u.Password }
func (u mockUser) State() map[string]any {
	return map[string]any{
		auth.Auth_Comfirmed: true,
	}
}

func (u *mockUser) PutPID(pid string)     { u.PID = pid }
func (u *mockUser) PutPassword(pw string) { u.Password = pw }

// ConfirmableUser 实现
func (u mockUser) GetEmail() string                    { return u.Email }
func (u mockUser) GetConfirmed() bool                  { return u.Confirmed }
func (u mockUser) GetConfirmVerifier() (string, error) { return u.Verifier, nil }
func (u *mockUser) PutEmail(email string) error        { u.Email = email; return nil }
func (u *mockUser) PutConfirmed(confirmed bool)        { u.Confirmed = confirmed }
func (u *mockUser) PutConfirmVerifier(verifier string) { u.Verifier = verifier }

// mock UserValuer interface
var _ Requester = (*mockUser)(nil)

// 新增：账号密码登录并发放 Cookie 的测试
func TestLoginHandler_PasswordLogin_SetsCookie(t *testing.T) {
	gin.SetMode(gin.TestMode)

	e := &auth.Engine{}
	e.Storage.Server = &mockUserServer{}
	e.Utils.Hasher = &mockHasher{}
	e.Logger, _ = zap.NewDevelopment()
	e.Config.CookieSecret = []byte("test-cookie-secret")
	e.Config.RootURL = "https://api.example.com"

	r := gin.New()
	// 使用 ParseMiddleware 从 Cookie 解出 pid
	r.Use(e.ParseMiddleware)
	r.POST("/login", Handler[mockUser](e)...) // 不需要额外中间件设置 pid

	body := `{"pid":"testuser","password":"password"}`
	req := httptest.NewRequest("POST", "/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	cookies := w.Result().Cookies()
	found := false
	for _, ck := range cookies {
		if ck.Name == "access_token" && ck.Value != "" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected access_token cookie to be set, got headers=%v", w.Header())
	}

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
}

func TestLoginHandler_WithAccessTokenCookie(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// mock Engine
	e := &auth.Engine{}
	e.Storage.Server = &mockUserServer{}
	e.Utils.Hasher = &mockHasher{}
	e.Logger, _ = zap.NewDevelopment()
	// 配置 CookieSecret 供 ParseMiddleware 与测试编码使用
	e.Config.CookieSecret = []byte("test-cookie-secret")

	r := gin.New()
	// 使用 ParseMiddleware 从 Cookie 解出 pid
	r.Use(e.ParseMiddleware)
	r.POST("/login", Handler[mockUser](e)...) // 不需要额外中间件设置 pid

	// 构造加密的 access_token Cookie，载荷含 pid
	hashKey := e.Config.CookieSecret
	encKey := sha256.Sum256(append([]byte("enc:"), e.Config.CookieSecret...))
	sc := securecookie.New(hashKey, encKey[:])
	val, err := sc.Encode("access_token", struct{ PID string }{PID: "testuser"})
	if err != nil {
		t.Fatalf("encode cookie failed: %v", err)
	}

	req := httptest.NewRequest("POST", "/login", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: val})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

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
}

type mockUserServer struct{}

func (m *mockUserServer) Load(_ context.Context, pid string) (auth.User, error) {
	if pid == "testuser" {
		return &mockUser{PID: "testuser", Password: "password", Confirmed: true}, nil
	}

	return nil, errors.New("user not found")
}
func (m *mockUserServer) Save(_ context.Context, _ auth.User) error {
	return nil
}

type mockHasher struct{}

func (m *mockHasher) CompareHashAndPassword(hash, password string) error {
	if hash == password {
		return nil
	}
	return errors.New("invalid password")
}

func (m *mockHasher) GenerateHash(password string) (string, error) {
	return password, nil
}

func (m *mockUserServer) New(_ context.Context, _ string) auth.User {
	return &mockUser{PID: "testuser", Password: "password", Confirmed: true}
}

func (m *mockUserServer) Create(_ context.Context, _ auth.User) error {
	return nil
}
