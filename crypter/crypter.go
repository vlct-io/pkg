package crypter

// Crypter defines the methods for encryption and decryption of data.
type Crypter interface {
	Encrypt(plainData string) (cipherData string, err error)
	Decrypt(cipherData string) (plainData string, err error)
}
