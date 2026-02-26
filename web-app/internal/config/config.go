package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	AdminEmails        []string
	MagicLinkSecret    []byte
	APIKeySalt         string
	EmailDriver        string
	SMTPHost           string
	SMTPPort           int
	SMTPUser           string
	SMTPPass           string
	SMTPFrom           string
	ResendAPIKey       string
	ResendFrom         string
	BaseURL            string
	SecureCookie       bool          // true when BASE_URL uses https
	TokenExpiryMinutes int
	TokenExpiry        time.Duration
	IPTTLDays          int
	DatabaseURL        string
	HTTPPort           int
	GRPCPort           int
	TrustProxy         bool
	Dev                bool
}

func Load() (*Config, error) {
	cfg := &Config{
		SMTPPort:           587,
		TokenExpiryMinutes: 15,
		IPTTLDays:          90,
		DatabaseURL:        "./data/app.db",
		HTTPPort:           8080,
		GRPCPort:           9090,
	}

	if v := os.Getenv("ADMIN_EMAILS"); v != "" {
		parts := strings.Split(v, ",")
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				cfg.AdminEmails = append(cfg.AdminEmails, p)
			}
		}
	}

	secretRaw := os.Getenv("MAGIC_LINK_SECRET")
	if secretRaw == "" {
		return nil, fmt.Errorf("MAGIC_LINK_SECRET is required")
	}
	decoded, err := base64.StdEncoding.DecodeString(secretRaw)
	if err != nil {
		// try raw URL encoding
		decoded, err = base64.RawURLEncoding.DecodeString(secretRaw)
		if err != nil {
			return nil, fmt.Errorf("MAGIC_LINK_SECRET: base64 decode failed: %w", err)
		}
	}
	if len(decoded) < 32 {
		return nil, fmt.Errorf("MAGIC_LINK_SECRET must decode to at least 32 bytes, got %d", len(decoded))
	}
	cfg.MagicLinkSecret = decoded

	cfg.APIKeySalt = os.Getenv("API_KEY_SALT")
	if cfg.APIKeySalt == "" {
		return nil, fmt.Errorf("API_KEY_SALT is required")
	}

	cfg.EmailDriver = os.Getenv("EMAIL_DRIVER")
	if cfg.EmailDriver != "smtp" && cfg.EmailDriver != "resend" {
		return nil, fmt.Errorf("EMAIL_DRIVER must be \"smtp\" or \"resend\", got %q", cfg.EmailDriver)
	}

	cfg.SMTPHost = os.Getenv("SMTP_HOST")
	if v := os.Getenv("SMTP_PORT"); v != "" {
		cfg.SMTPPort, err = strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("SMTP_PORT: %w", err)
		}
	}
	cfg.SMTPUser = os.Getenv("SMTP_USER")
	cfg.SMTPPass = os.Getenv("SMTP_PASS")
	cfg.SMTPFrom = os.Getenv("SMTP_FROM")

	cfg.ResendAPIKey = os.Getenv("RESEND_API_KEY")
	cfg.ResendFrom = os.Getenv("RESEND_FROM")

	cfg.BaseURL = os.Getenv("BASE_URL")
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("BASE_URL is required")
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	cfg.SecureCookie = strings.HasPrefix(cfg.BaseURL, "https://")

	if v := os.Getenv("TOKEN_EXPIRY_MINUTES"); v != "" {
		cfg.TokenExpiryMinutes, err = strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("TOKEN_EXPIRY_MINUTES: %w", err)
		}
	}
	cfg.TokenExpiry = time.Duration(cfg.TokenExpiryMinutes) * time.Minute

	if v := os.Getenv("IP_TTL_DAYS"); v != "" {
		cfg.IPTTLDays, err = strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("IP_TTL_DAYS: %w", err)
		}
	}

	if v := os.Getenv("DATABASE_URL"); v != "" {
		cfg.DatabaseURL = v
	}

	if v := os.Getenv("HTTP_PORT"); v != "" {
		cfg.HTTPPort, err = strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("HTTP_PORT: %w", err)
		}
	}

	if v := os.Getenv("GRPC_PORT"); v != "" {
		cfg.GRPCPort, err = strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("GRPC_PORT: %w", err)
		}
	}

	cfg.TrustProxy = os.Getenv("TRUST_PROXY") == "true"
	cfg.Dev = os.Getenv("DEV") == "true"

	return cfg, nil
}
