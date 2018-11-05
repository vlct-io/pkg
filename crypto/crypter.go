package crypto

// Crypter defines the methods for encryption and decryption of data.
type Crypter interface {
	Encrypt(plainText []byte) (cipherText []byte, err error)
	Decrypt(cipherText []byte) (plainText []byte, err error)
}
