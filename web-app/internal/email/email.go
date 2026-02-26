package email

import (
	"context"
	"fmt"
)

type Mailer interface {
	SendMagicLink(ctx context.Context, to, link string) error
}

type MailerConfig struct {
	SMTPHost     string
	SMTPPort     int
	SMTPUser     string
	SMTPPass     string
	SMTPFrom     string
	ResendAPIKey string
	ResendFrom   string
}

func New(driver string, cfg MailerConfig) (Mailer, error) {
	switch driver {
	case "smtp":
		return &smtpMailer{
			host: cfg.SMTPHost,
			port: cfg.SMTPPort,
			user: cfg.SMTPUser,
			pass: cfg.SMTPPass,
			from: cfg.SMTPFrom,
		}, nil
	case "resend":
		return &resendMailer{
			apiKey: cfg.ResendAPIKey,
			from:   cfg.ResendFrom,
		}, nil
	default:
		return nil, fmt.Errorf("unknown email driver: %q", driver)
	}
}
