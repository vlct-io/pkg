package aesgcm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"

	"github.com/vlct-io/pkg/crypto"

	"github.com/pkg/errors"
)

// aesgcm mplements the Encrypt/Decrypt methods
// using AES-GCM: https://eprint.iacr.org/2015/102.pdf
type aesgcm struct {
	//  either 16, 24, or 32 bytes to select
	// AES-128, AES-192, or AES-256.
	Key string
}

// validate interface conformity.
var _ crypto.Crypter = aesgcm{}

// New makes a new aes-gcm Crypter.
func New(key string) crypto.Crypter {
	return aesgcm{
		Key: key,
	}
}

// Encrypt ciphers the plainText using the provided 32 bytes key
// with AES256/GCM and returns a base64 encoded string.
func (ag aesgcm) Encrypt(plainText []byte) (cypherText []byte, err error) {
	_key := []byte(ag.Key)
	_cipher, err := aes.NewCipher(_key)
	if err != nil {
		return nil, errors.Wrap(err, "unable to create a new cipher")
	}
	gcm, err := cipher.NewGCM(_cipher)
	if err != nil {
		return nil, errors.Wrap(err, "unable to wrap cipher in GCM")
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, errors.Wrap(err, "unable to read random nonce")
	}
	return gcm.Seal(nonce, nonce, []byte(plainText), nil), nil
}

// Decrypt deciphers the provided base64 encoded and AES/GCM ciphered
// data returning the original plainText string.
func (ag aesgcm) Decrypt(cipherText []byte) (plainText []byte, err error) {
	_key := []byte(ag.Key)
	_cipher, err := aes.NewCipher(_key)
	if err != nil {
		return nil, errors.Wrap(err, "unable to create new cipher")
	}
	gcm, err := cipher.NewGCM(_cipher)
	if err != nil {
		return nil, errors.Wrap(err, "unable to wrap cipher in GCM")
	}
	nonceSize := gcm.NonceSize()
	if len(cipherText) < nonceSize {
		return nil, errors.Wrap(err, "unable to read random nonce")
	}
	nonce, cipherplainText := cipherText[:nonceSize], cipherText[nonceSize:]
	return gcm.Open(nil, nonce, cipherplainText, nil)
}
