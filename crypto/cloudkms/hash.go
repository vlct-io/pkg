package cloudKMS

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/pkg/errors"
)

func (kms cloudKMS) ValidHash(sourced, stored []byte) bool {
	return false
}

func (kms cloudKMS) Hash(secret, data string) (error, string) {
	fmt.Printf("Secret: %s Data: %s\n", secret, data)

	// Create a new HMAC by defining the hash type and the key (as byte array)
	h := hmac.New(sha256.New, []byte(secret))

	// Write Data to it
	h.Write([]byte(data))

	// Get result and encode as hexadecimal string
	sha := hex.EncodeToString(h.Sum(nil))

	fmt.Println("Result: " + sha)

	return errors.New("error"), ""
}
