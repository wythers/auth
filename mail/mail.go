package mail

import (
	"strings"
	"text/template"

	"github.com/gin-gonic/gin"
	"github.com/wythers/auth"
	"go.uber.org/zap"
)

func Middleware(e *auth.Engine) gin.HandlerFunc {
	return func(c *gin.Context) {
		email := c.MustGet(string(auth.CTXKeyMail)).(*auth.Email)
		data := c.MustGet(string(auth.CTXKeyEmailData)).(map[string]auth.HTMLData)

		for p, d := range data {
			by, t, err := e.HTMLRenderer.Render(c.Request.Context(), p, d)
			if err != nil {
				e.RequestLogger().Error("failed to render email", zap.Error(err))
				continue
			}
			if t == "text/plain" {
				email.TextBody = string(by)
			}
			if t == "text/html" {
				email.HTMLBody = string(by)
			}
		}

		go e.Mailer.Send(c.Request.Context(), *email)
	}
}

var emailTmpl = template.Must(template.New("email").Funcs(template.FuncMap{
	"join":           strings.Join,
	"namedAddress":   namedAddress,
	"namedAddresses": namedAddresses,
}).Parse(`To: {{namedAddresses .Mail.ToNames .Mail.To}}{{if .Mail.Cc}}
Cc: {{namedAddresses .Mail.CcNames .Mail.Cc}}{{end}}{{if .Mail.Bcc}}
Bcc: {{namedAddresses .Mail.BccNames .Mail.Bcc}}{{end}}
From: {{namedAddress .Mail.FromName .Mail.From}}
Subject: {{.Mail.Subject}}{{if .Mail.ReplyTo}}
Reply-To: {{namedAddress .Mail.ReplyToName .Mail.ReplyTo}}{{end}}
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="==============={{.Boundary}}=="
Content-Transfer-Encoding: 7bit

{{if .Mail.TextBody -}}
--==============={{.Boundary}}==
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 7bit

{{.Mail.TextBody}}
{{end -}}
{{if .Mail.HTMLBody -}}
--==============={{.Boundary}}==
Content-Type: text/html; charset=UTF-8
Content-Transfer-Encoding: 7bit

{{.Mail.HTMLBody}}
{{end -}}
--==============={{.Boundary}}==--
`))
