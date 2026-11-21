// Package totp implements RFC 6238 time-based one-time passwords
// (compatible with Google Authenticator, Authy, Microsoft Authenticator,
// 1Password, Bitwarden, ...). Standard library only.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	Digits = 6
	Period = 30
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewSecret returns a random 160-bit base32 secret.
func NewSecret() string {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b32.EncodeToString(b)
}

func decode(secret string) ([]byte, error) {
	s := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	s = strings.TrimRight(s, "=")
	return b32.DecodeString(s)
}

// CodeAt returns the code for the given counter step.
func codeAtCounter(key []byte, counter uint64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := (uint32(sum[off])&0x7f)<<24 | uint32(sum[off+1])<<16 | uint32(sum[off+2])<<8 | uint32(sum[off+3])
	return fmt.Sprintf("%06d", v%1000000)
}

// Code returns the current code for secret at time t.
func Code(secret string, t time.Time) (string, error) {
	key, err := decode(secret)
	if err != nil {
		return "", err
	}
	return codeAtCounter(key, uint64(t.Unix())/Period), nil
}

// Validate checks code against secret allowing +-1 step of clock skew.
// It returns the matched counter so callers can reject replays
// (a counter must be strictly greater than the last used one).
func Validate(secret, code string, t time.Time) (counter uint64, ok bool) {
	code = strings.TrimSpace(code)
	if len(code) != Digits {
		return 0, false
	}
	key, err := decode(secret)
	if err != nil {
		return 0, false
	}
	now := uint64(t.Unix()) / Period
	for _, d := range []int64{0, -1, 1} {
		c := uint64(int64(now) + d)
		if subtle.ConstantTimeCompare([]byte(codeAtCounter(key, c)), []byte(code)) == 1 {
			return c, true
		}
	}
	return 0, false
}

// URI builds an otpauth:// URI for enrolment in authenticator apps.
func URI(issuer, account, secret string) string {
	label := url.PathEscape(issuer + ":" + account)
	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", fmt.Sprint(Digits))
	v.Set("period", fmt.Sprint(Period))
	return "otpauth://totp/" + label + "?" + v.Encode()
}
