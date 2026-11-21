package totp

import (
	"encoding/base32"
	"testing"
	"time"
)

// RFC 6238 appendix B test vectors (SHA1, 8 digits truncated to 6 here).
func TestRFC6238(t *testing.T) {
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	cases := map[int64]string{
		59:          "287082",
		1111111109:  "081804",
		1111111111:  "050471",
		1234567890:  "005924",
		2000000000:  "279037",
		20000000000: "353130",
	}
	for ts, want := range cases {
		got, err := Code(secret, time.Unix(ts, 0))
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("t=%d got %s want %s", ts, got, want)
		}
	}
}

func TestValidateSkew(t *testing.T) {
	s := NewSecret()
	now := time.Unix(1700000000, 0)
	prev, _ := Code(s, now.Add(-30*time.Second))
	if _, ok := Validate(s, prev, now); !ok {
		t.Fatal("previous step should validate")
	}
	old, _ := Code(s, now.Add(-90*time.Second))
	if _, ok := Validate(s, old, now); ok {
		t.Fatal("code 3 steps old must not validate")
	}
}
