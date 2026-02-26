package session

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const CookieName = "tyler_session"

// sessionMaxAge is the server-side TTL for sessions. Must match the cookie MaxAge.
const sessionMaxAge = 30 * 24 * time.Hour

var ErrInvalid = errors.New("invalid session")

func Set(w http.ResponseWriter, secret []byte, email string, isAdmin bool, secure bool) {
	adminStr := "0"
	if isAdmin {
		adminStr = "1"
	}
	expiresAt := time.Now().Add(sessionMaxAge).Unix()
	payload := email + "|" + adminStr + "|" + strconv.FormatInt(expiresAt, 10)
	payloadEnc := base64.RawURLEncoding.EncodeToString([]byte(payload))

	mac := computeMAC(secret, payload)
	macEnc := base64.RawURLEncoding.EncodeToString(mac)

	value := payloadEnc + "." + macEnc

	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   int(sessionMaxAge / time.Second),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func Get(r *http.Request, secret []byte) (email string, isAdmin bool, err error) {
	c, err := r.Cookie(CookieName)
	if err != nil {
		return "", false, ErrInvalid
	}

	parts := strings.SplitN(c.Value, ".", 2)
	if len(parts) != 2 {
		return "", false, ErrInvalid
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", false, ErrInvalid
	}
	macBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", false, ErrInvalid
	}

	payload := string(payloadBytes)
	expected := computeMAC(secret, payload)
	if !hmac.Equal(macBytes, expected) {
		return "", false, ErrInvalid
	}

	// Payload format: email|adminFlag|expiresAtUnix
	fields := strings.SplitN(payload, "|", 3)
	if len(fields) != 3 {
		return "", false, ErrInvalid
	}
	email = fields[0]
	adminStr := fields[1]
	expiresAtStr := fields[2]

	expiresAt, err := strconv.ParseInt(expiresAtStr, 10, 64)
	if err != nil {
		return "", false, ErrInvalid
	}
	if time.Now().Unix() > expiresAt {
		return "", false, ErrInvalid
	}

	return email, adminStr == "1", nil
}

func Clear(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func computeMAC(secret []byte, payload string) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte("session:" + payload))
	return h.Sum(nil)
}
