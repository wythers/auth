package mail

import (
	"bytes"
	"context"
	"io"

	"github.com/wythers/auth"
)

// LogMailer logs e-mails instead of sending them.
type LogMailer struct {
	io.Writer
}

// NewLogMailer creates a mailer that doesn't deliver e-mails but
// simply logs them.
func NewLogMailer(writer io.Writer) *LogMailer {
	return &LogMailer{writer}
}

// Send an e-mail
func (l LogMailer) Send(ctx context.Context, mail auth.Email) error {
	buf := &bytes.Buffer{}

	data := struct {
		Boundary string
		Mail     auth.Email
	}{
		Boundary: "284fad24nao8f4na284f2n4",
		Mail:     mail,
	}

	err := emailTmpl.Execute(buf, data)
	if err != nil {
		return err
	}

	toSend := bytes.Replace(buf.Bytes(), []byte{'\n'}, []byte{'\r', '\n'}, -1)

	_, err = l.Write(toSend)
	return err
}
