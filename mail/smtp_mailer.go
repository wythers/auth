package mail

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net/smtp"
	"strings"
	"time"

	"github.com/wythers/auth"
)

// NewSMTPMailer creates an SMTP Mailer to send emails with.
// An example usage might be something like:
//
//	NewSMTPMailer("smtp.gmail.com",
//	  smtp.PlainAuth("", "admin@yoursite.com", "password", "smtp.gmail.com"))
func NewSMTPMailer(server string, auth smtp.Auth) *SMTPMailer {
	if len(server) == 0 {
		panic("SMTP Mailer must be created with a server string.")
	}
	random := rand.New(rand.NewSource(time.Now().UnixNano()))
	return &SMTPMailer{server, auth, random}
}

// SMTPMailer uses smtp to actually send e-mails
type SMTPMailer struct {
	Server string
	Auth   smtp.Auth
	rand   *rand.Rand
}

// Send an e-mail
func (s SMTPMailer) Send(ctx context.Context, mail auth.Email) error {
	if len(mail.TextBody) == 0 && len(mail.HTMLBody) == 0 {
		return errors.New("refusing to send mail without text or html body")
	}

	buf := &bytes.Buffer{}

	data := struct {
		Boundary string
		Mail     auth.Email
	}{
		Boundary: s.boundary(),
		Mail:     mail,
	}

	err := emailTmpl.Execute(buf, data)
	if err != nil {
		return err
	}

	toSend := bytes.Replace(buf.Bytes(), []byte{'\n'}, []byte{'\r', '\n'}, -1)

	return smtp.SendMail(s.Server, s.Auth, mail.From, mail.To, toSend)
}

// boundary makes mime boundaries, these are largely useless strings that just
// need to be the same in the mime structure. We choose from the alphabet below
// and create a random string of length 23
// Example:
// 284fad24nao8f4na284f2n4
func (s SMTPMailer) boundary() string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	buf := &bytes.Buffer{}

	for i := 0; i < 23; i++ {
		buf.WriteByte(alphabet[s.rand.Int()%len(alphabet)])
	}

	return buf.String()
}

func namedAddress(name, address string) string {
	if len(name) == 0 {
		return address
	}

	return fmt.Sprintf("%s <%s>", name, address)
}

func namedAddresses(names, addresses []string) string {
	if len(names) == 0 {
		return strings.Join(addresses, ", ")
	}

	buf := &bytes.Buffer{}
	first := true

	for i, address := range addresses {
		if first {
			first = false
		} else {
			buf.WriteString(", ")
		}

		buf.WriteString(namedAddress(names[i], address))
	}

	return buf.String()
}
