package comfirm

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/securecookie"
	"github.com/wythers/auth"
	"go.uber.org/zap"
)

type PIDandCode struct {
	PID  string `json:"pid"`
	Code string `json:"code"`
}

func (p PIDandCode) GetPID() string  { return p.PID }
func (p PIDandCode) GetCode() string { return p.Code }

type mockUser struct {
	PID       string
	Confirmed bool
	Verifier  string
}

func (u *mockUser) GetPID() string              { return u.PID }
func (u *mockUser) PutPID(pid string)           { u.PID = pid }
func (u *mockUser) GetConfirmed() bool          { return u.Confirmed }
func (u *mockUser) PutConfirmed(b bool)         { u.Confirmed = b }
func (u *mockUser) GetConfirmVerifier() string  { return u.Verifier }
func (u *mockUser) PutConfirmVerifier(v string) { u.Verifier = v }

func (u *mockUser) GetEmail() (email string) { return "" }
func (u *mockUser) PutEmail(email string)    {}

// GetConfirmSelector() (selector string)
// PutConfirmSelector(selector string)

var _ auth.ConfirmableUser = (*mockUser)(nil)

func TestComfirmHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)

	e := &auth.Engine{}
	e.Storage.Server = &mockUserServer{}
	e.Config.CookieSecret = []byte("testsecret")
	e.Utils.OneTimeCodeGenerator = &auth.DefaultOneTimeCodeGenerator{}
	e.Logger, _ = zap.NewDevelopment()

	r := gin.New()
	r.Use(e.ParseMiddleware)
	r.POST("/comfirm", Handler[PIDandCode](e)...)

	// 构造加密的 access_token Cookie，载荷含 pid
	hashKey := e.Config.CookieSecret
	encKey := sha256.Sum256(append([]byte("enc:"), e.Config.CookieSecret...))
	sc := securecookie.New(hashKey, encKey[:])
	val, err := sc.Encode("access_token", struct{ PID string }{PID: "testuser"})
	if err != nil {
		t.Fatalf("encode cookie failed: %v", err)
	}

	// 测试验证码正确
	body := `{"code":"123456"}`
	req := httptest.NewRequest("POST", "/comfirm", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
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

	// 测试验证码错误
	// body = `{"code":"654321"}`
	// req = httptest.NewRequest("POST", "/comfirm", strings.NewReader(body))
	// req.Header.Set("Content-Type", "application/json")
	// w = httptest.NewRecorder()
	// // 重新设置 context
	// r.Use(func(c *gin.Context) {
	// 	c.Set(string(auth.CTXKeyPID), "testuser")
	// })
	// r.ServeHTTP(w, req)
	// if w.Code != http.StatusOK {
	// 	t.Fatalf("expected 200, got %d", w.Code)
	// }
	// if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
	// 	t.Fatalf("json unmarshal failed: %v", err)
	// }
	// if resp["code"].(float64) == 200 {
	// 	t.Errorf("expected error code, got 200")
	// }
}

type mockUserServer struct{}

func (m *mockUserServer) Load(_ context.Context, pid string) (auth.User, error) {
	if pid == "testuser" {
		plain := "123456"
		sum := sha256.Sum256([]byte(plain))
		stored := base64.RawStdEncoding.EncodeToString(sum[:])
		return &mockUser{PID: "testuser", Verifier: stored}, nil
	}
	return nil, errors.New("user not found")
}
func (m *mockUserServer) Save(_ context.Context, _ auth.User) error {
	return nil
}

func (m *mockUserServer) New(_ context.Context, _ string) auth.User {
	return &mockUser{PID: "testuser", Verifier: "123456"}
}

func (m *mockUserServer) Create(_ context.Context, _ auth.User) error {
	return nil
}
