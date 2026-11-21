// Package wgkey generates WireGuard Curve25519 keys (same format as `wg genkey`).
package wgkey

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
)

// Generate returns (private, public) as base64 strings.
func Generate() (string, string, error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(k.Bytes()),
		base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}

// Public derives the public key from a base64 private key.
func Public(priv string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(priv)
	if err != nil || len(b) != 32 {
		return "", errors.New("invalid private key")
	}
	k, err := ecdh.X25519().NewPrivateKey(b)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}

// PresharedKey returns a random 32-byte base64 key.
func PresharedKey() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// Valid reports whether s is a 32-byte base64 key.
func Valid(s string) bool {
	b, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(b) == 32
}

// Hex converts a base64 key to hex (the UAPI format used by wireguard-go).
func Hex(s string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != 32 {
		return "", errors.New("invalid key")
	}
	return hex.EncodeToString(b), nil
}
