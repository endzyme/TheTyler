package email

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type resendMailer struct {
	apiKey string
	from   string
}

func (m *resendMailer) SendMagicLink(ctx context.Context, to, link string) error {
	payload := map[string]any{
		"from":    m.from,
		"to":      []string{to},
		"subject": "Your access link",
		"text": "Click the link below to authorize yourself.\n" +
			"This link expires in 15 minutes and can only be used once.\n\n" +
			link + "\n\n"}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("resend: marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.resend.com/emails", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("resend: new request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+m.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("resend: do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("resend: unexpected status %d: %s", resp.StatusCode, respBody)
	}

	return nil
}
