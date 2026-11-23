package server

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
)

var encMagic = []byte("WG2FA-ENCRYPTED-STATE-V1\n")

const stateKDFIter = 600_000

type encFile struct {
	KDF   string `json:"kdf"`
	Iter  int    `json:"iter"`
	Salt  []byte `json:"salt"`
	Nonce []byte `json:"nonce"`
	Data  []byte `json:"data"`
}

type stateCipher struct {
	aead cipher.AEAD
	salt []byte
	iter int
}

func isEncrypted(b []byte) bool { return bytes.HasPrefix(b, encMagic) }

func newStateCipherIter(pass string, salt []byte, iter int) (*stateCipher, error) {
	if len(pass) < 16 {
		return nil, errors.New("state key must be at least 16 characters")
	}
	if salt == nil {
		salt = make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			return nil, err
		}
	}
	k, err := pbkdf2.Key(sha256.New, pass, salt, iter, 32)
	if err != nil {
		return nil, err
	}
	blk, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	a, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	return &stateCipher{aead: a, salt: salt, iter: iter}, nil
}

func newStateCipher(pass string, salt []byte) (*stateCipher, error) {
	return newStateCipherIter(pass, salt, stateKDFIter)
}

func (c *stateCipher) seal(plain []byte) ([]byte, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	f := encFile{KDF: "pbkdf2-sha256", Iter: c.iter, Salt: c.salt, Nonce: nonce,
		Data: c.aead.Seal(nil, nonce, plain, encMagic)}
	j, err := json.Marshal(f)
	if err != nil {
		return nil, err
	}
	return append(append([]byte{}, encMagic...), j...), nil
}

func decryptState(pass string, b []byte) (*stateCipher, []byte, error) {
	var f encFile
	if err := json.Unmarshal(b[len(encMagic):], &f); err != nil {
		return nil, nil, errors.New("encrypted state file is corrupt")
	}
	if f.KDF != "pbkdf2-sha256" || f.Iter < 100_000 {
		return nil, nil, errors.New("unsupported state encryption parameters")
	}
	c, err := newStateCipherIter(pass, f.Salt, f.Iter)
	if err != nil {
		return nil, nil, err
	}
	plain, err := c.aead.Open(nil, f.Nonce, f.Data, encMagic)
	if err != nil {
		return nil, nil, errors.New("cannot decrypt state: wrong WG2FA_STATE_KEY or tampered file")
	}
	return c, plain, nil
}
