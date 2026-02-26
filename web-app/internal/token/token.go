package token

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

var ErrExpired = errors.New("token expired")
var ErrInvalid = errors.New("token invalid")

type Token struct {
	Email  string
	IP     string
	Expiry time.Time
}

func Generate(secret []byte, email, ip string, expiry time.Time) (string, error) {
	payload := email + "|" + ip + "|" + strconv.FormatInt(expiry.Unix(), 10)
	payloadEnc := base64.RawURLEncoding.EncodeToString([]byte(payload))

	mac := computeMAC(secret, payload)
	macEnc := base64.RawURLEncoding.EncodeToString(mac)

	return payloadEnc + "." + macEnc, nil
}

func Parse(secret []byte, raw string) (*Token, error) {
	parts := strings.SplitN(raw, ".", 2)
	if len(parts) != 2 {
		return nil, ErrInvalid
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrInvalid
	}
	macBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrInvalid
	}

	payload := string(payloadBytes)
	expected := computeMAC(secret, payload)
	if !hmac.Equal(macBytes, expected) {
		return nil, ErrInvalid
	}

	fields := strings.SplitN(payload, "|", 3)
	if len(fields) != 3 {
		return nil, ErrInvalid
	}

	unixSec, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil {
		return nil, ErrInvalid
	}
	expiry := time.Unix(unixSec, 0)

	if time.Now().After(expiry) {
		return nil, fmt.Errorf("%w", ErrExpired)
	}

	return &Token{
		Email:  fields[0],
		IP:     fields[1],
		Expiry: expiry,
	}, nil
}

func computeMAC(secret []byte, payload string) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(payload))
	return h.Sum(nil)
}
