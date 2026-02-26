package email

import (
	"context"
	"fmt"
	"net/smtp"
	"strings"
)

type smtpMailer struct {
	host string
	port int
	user string
	pass string
	from string
}

func (m *smtpMailer) SendMagicLink(_ context.Context, to, link string) error {
	addr := fmt.Sprintf("%s:%d", m.host, m.port)

	// Strip CRLF to prevent SMTP header injection.
	to = strings.NewReplacer("\r", "", "\n", "").Replace(to)

	body := []byte(
		"To: " + to + "\r\n" +
			"From: " + m.from + "\r\n" +
			"Subject: Your access link\r\n" +
			"Content-Type: text/plain; charset=utf-8\r\n" +
			"\r\n" +
			"Click the link below to authorize your IP address.\r\n" +
			"This link expires in 15 minutes and can only be used once.\r\n" +
			"\r\n" +
			link + "\r\n" +
			"\r\n" +
			"Bookmark this link for future access requests.\r\n",
	)

	var auth smtp.Auth
	if m.user != "" {
		auth = smtp.PlainAuth("", m.user, m.pass, m.host)
	}

	return smtp.SendMail(addr, auth, m.from, []string{to}, body)
}
