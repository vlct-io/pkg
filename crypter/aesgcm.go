package crypter

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"

	"github.com/pkg/errors"
)

// AESGCM mplements the Encrypt/Decrypt methods
// using AES-GCM: https://eprint.iacr.org/2015/102.pdf
type AESGCM struct {
	//  either 16, 24, or 32 bytes to select
	// AES-128, AES-192, or AES-256.
	Key string
}

// validate interface conformity.
var _ Crypter = AESGCM{}

// Encrypt ciphers the plainData using the provided 32 bytes key
// with AES256/GCM and returns a base64 encoded string.
func (ag AESGCM) Encrypt(plainData string) (b64 string, err error) {
	_key := []byte(ag.Key)
	_cipher, err := aes.NewCipher(_key)
	if err != nil {
		return "", errors.Wrap(err, "unable to create a new cipher")
	}
	gcm, err := cipher.NewGCM(_cipher)
	if err != nil {
		return "", errors.Wrap(err, "unable to wrap cipher in GCM")
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", errors.Wrap(err, "unable to read random nonce")
	}
	cipherData := gcm.Seal(nonce, nonce, []byte(plainData), nil)
	return base64.StdEncoding.EncodeToString(cipherData), nil
}

// Decrypt deciphers the provided base64 encoded and AES/GCM ciphered
// data returning the original plainData string.
func (ag AESGCM) Decrypt(b64 string) (plainData string, err error) {
	_key := []byte(ag.Key)
	_cipher, err := aes.NewCipher(_key)
	if err != nil {
		return "", errors.Wrap(err, "unable to create a new cipher")
	}
	gcm, err := cipher.NewGCM(_cipher)
	if err != nil {
		return "", errors.Wrap(err, "unable to wrap cipher in GCM")
	}
	cipherData, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", errors.Wrap(err, "unable to decode string")
	}
	nonceSize := gcm.NonceSize()
	if len(cipherData) < nonceSize {
		return "", errors.Wrap(err, "unable to read random nonce")
	}
	nonce, cipherplainData := cipherData[:nonceSize], cipherData[nonceSize:]
	b, err := gcm.Open(nil, nonce, cipherplainData, nil)
	if err != nil {
		return "", errors.Wrap(err, "unable to decrypt and authenticate cipher text")
	}
	return string(b), nil
}
