package core

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Signer makes and checks HMAC-SHA256 signed values: one-time tokens (magic link, reset, verify) and session cookies.
type Signer struct{ Key []byte }

// Claims of a signed value.
type Claims struct {
	Purpose string            `json:"p"`
	Subject string            `json:"s"` // the account address
	ID      string            `json:"j"` // unique id, for single use
	Exp     int64             `json:"e"`
	Extra   map[string]string `json:"x,omitempty"`
}

var ErrBadToken = errors.New("invalid or expired token")

func (s Signer) Sign(c Claims) string {
	b, _ := json.Marshal(c)
	p := base64.RawURLEncoding.EncodeToString(b)
	m := hmac.New(sha256.New, s.Key)
	m.Write([]byte(p))
	return p + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (s Signer) Verify(tok, purpose string) (*Claims, error) {
	i := strings.LastIndexByte(tok, '.')
	if i < 0 {
		return nil, ErrBadToken
	}
	m := hmac.New(sha256.New, s.Key)
	m.Write([]byte(tok[:i]))
	sig, err := base64.RawURLEncoding.DecodeString(tok[i+1:])
	if err != nil || !hmac.Equal(sig, m.Sum(nil)) {
		return nil, ErrBadToken
	}
	b, err := base64.RawURLEncoding.DecodeString(tok[:i])
	if err != nil {
		return nil, ErrBadToken
	}
	var c Claims
	if json.Unmarshal(b, &c) != nil || c.Purpose != purpose || c.Exp < time.Now().Unix() {
		return nil, ErrBadToken
	}
	return &c, nil
}

// New returns claims for a purpose, subject and lifetime with a fresh id.
func NewClaims(purpose, subject string, ttl time.Duration) Claims {
	return Claims{Purpose: purpose, Subject: subject, ID: RandomString(12), Exp: time.Now().Add(ttl).Unix()}
}
