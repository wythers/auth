package register

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	htmlTemplate "html/template"
	textTemplate "text/template"

	"github.com/gin-gonic/gin"
	"github.com/wythers/auth"
	"github.com/wythers/auth/mail"
	"go.uber.org/zap"
)

// registerMockUser 实现 AuthableUser 与 ConfirmableUser
// 供注册流程绑定与状态存储使用
type registerMockUser struct {
	PID             string `json:"pid"`
	Password        string `json:"password"`
	Email           string `json:"email"`
	Confirmed       bool
	ConfirmVerifier string
}

func (u registerMockUser) GetPID() string                       { return u.PID }
func (u *registerMockUser) PutPID(pid string)                   { u.PID = pid }
func (u registerMockUser) GetPassword() string                  { return u.Password }
func (u *registerMockUser) PutPassword(pw string)               { u.Password = pw }
func (u *registerMockUser) GetEmail() string                    { return u.Email }
func (u *registerMockUser) GetConfirmed() bool                  { return u.Confirmed }
func (u *registerMockUser) GetConfirmVerifier() (string, error) { return u.ConfirmVerifier, nil }
func (u *registerMockUser) PutEmail(email string) error         { u.Email = email; return nil }
func (u *registerMockUser) PutConfirmed(confirmed bool)         { u.Confirmed = confirmed }
func (u *registerMockUser) PutConfirmVerifier(v string)         { u.ConfirmVerifier = v }

// mockServer 仅实现 Save/Load（虽然注册流程只有 Save 会被调用）
// 为了便于断言，保存最后一次写入的用户副本
type mockServer struct {
	lastSaved map[string]*registerMockUser
}

func (m *mockServer) Load(_ context.Context, key string) (auth.User, error) {
	if m.lastSaved == nil {
		return nil, auth.ErrUserNotFound
	}
	if u, ok := m.lastSaved[key]; ok {
		return u, nil
	}
	return nil, auth.ErrUserNotFound
}

func (m *mockServer) Save(_ context.Context, user auth.User) error {
	if m.lastSaved == nil {
		m.lastSaved = make(map[string]*registerMockUser)
	}
	if ru, ok := user.(*registerMockUser); ok {
		// 存指针便于测试后读取变更
		m.lastSaved[ru.PID] = ru
	}
	return nil
}

func (m *mockServer) New(_ context.Context, _ string) auth.User {
	return &registerMockUser{PID: "testuser"}
}

func (m *mockServer) Create(_ context.Context, _ auth.User) error {
	return nil
}

// mockHasher 直接返回带前缀的“哈希”
type mockHasher struct{}

func (m *mockHasher) CompareHashAndPassword(hash, password string) error { return nil }
func (m *mockHasher) GenerateHash(password string) (string, error)       { return "HASH:" + password, nil }

// mockRenderer 根据模板名返回不同 content-type
// confirm_html -> text/html, confirm_txt -> text/plain
type mockRenderer struct{}

func (r *mockRenderer) Load(name string) error { return nil }

func (r *mockRenderer) Render(_ context.Context, page string, data auth.HTMLData) ([]byte, string, error) {
	var (
		out         bytes.Buffer
		contentType string
	)

	switch page {
	case RegisterConfirmHTML:
		// 使用 html/template，模板中以 .code 访问传入 map 的键
		tpl := htmlTemplate.Must(htmlTemplate.New("html").Parse(`<html><body>CONFIRM: {{.code}}</body></html>`))
		if err := tpl.Execute(&out, data); err != nil {
			return nil, "", err
		}
		contentType = "text/html"
	case RegisterConfirmTxt:
		// 使用 text/template，模板中以 .code 访问传入 map 的键
		tpl := textTemplate.Must(textTemplate.New("txt").Parse(`CONFIRM: {{.code}}`))
		if err := tpl.Execute(&out, data); err != nil {
			return nil, "", err
		}
		contentType = "text/plain"
	default:
		return []byte(""), "text/plain", nil
	}

	return out.Bytes(), contentType, nil
}

// mockMailer 通过通道捕获发送的邮件
type mockMailer struct{ ch chan auth.Email }

func (m *mockMailer) Send(_ context.Context, e auth.Email) error {
	m.ch <- e
	return nil
}

func TestRegisterHandler_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)

	e := &auth.Engine{}
	e.Storage.Server = &mockServer{}
	e.Utils.Hasher = &mockHasher{}
	e.HTMLRenderer = &mockRenderer{}
	buf := &bytes.Buffer{}
	e.Mailer = mail.NewLogMailer(buf)
	e.Logger, _ = zap.NewDevelopment()
	e.Config.MailFrom = "no-reply@example.com"
	e.Config.MailFromName = "Auth"
	e.Config.MailSubjectPrefix = "[Test] "

	r := gin.New()
	r.POST("/register", Handler[registerMockUser](e)...)

	body := `{"pid":"newuser","password":"pass123","email":"test@example.com"}`
	t.Logf("request body: %s", body)
	req := httptest.NewRequest("POST", "/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	t.Logf("response status: %d", w.Code)
	t.Logf("response body: %s", w.Body.String())

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d, body: %s", w.Code, w.Body.String())
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
	if pid := resp["pid"].(string); pid != "newuser" {
		t.Errorf("expected pid 'newuser', got %s", pid)
	}

	// 校验存储结果（密码被“哈希”、确认码写入、未确认）
	ms := e.Storage.Server.(*mockServer)
	saved := ms.lastSaved["newuser"]
	t.Logf("saved user: pid=%s password=%s confirmed=%v confirm_code=%q", saved.PID, saved.Password, saved.Confirmed, saved.ConfirmVerifier)
	if saved == nil {
		t.Fatalf("expected user saved, got nil")
	}
	if saved.Password != "HASH:pass123" {
		t.Errorf("expected password hashed, got %s", saved.Password)
	}
	if saved.Confirmed != false {
		t.Errorf("expected confirmed=false, got %v", saved.Confirmed)
	}
	if len(saved.ConfirmVerifier) != 6 {
		t.Errorf("expected 6-digit confirm code, got %q", saved.ConfirmVerifier)
	}

	// 等待异步发送完成并检查原始邮件输出
	deadline := time.After(1 * time.Second)
	for buf.Len() == 0 {
		select {
		case <-deadline:
			t.Fatalf("expected email to be sent, timed out")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
	raw := buf.String()
	t.Logf("raw email:\n%s", raw)

	if !strings.Contains(raw, "To: test@example.com") {
		t.Errorf("raw email missing To header")
	}
	if !strings.Contains(raw, "From: Auth <no-reply@example.com>") {
		t.Errorf("raw email missing From header")
	}
	if !strings.Contains(raw, "Subject: [Test] Confirm New Account") {
		t.Errorf("raw email missing Subject header")
	}
	if !strings.Contains(raw, "CONFIRM: "+saved.ConfirmVerifier) {
		t.Errorf("raw email missing confirm code in body")
	}
}
