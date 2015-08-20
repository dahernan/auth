package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"io"

	"golang.org/x/crypto/scrypt"
)

func HashPassword(pass string, salt []byte) ([]byte, error) {
	return scrypt.Key([]byte(pass), salt, 16384, 8, 1, 128)
}

func SecureCompare(given, actual []byte) bool {
	return subtle.ConstantTimeCompare(given, actual) == 1
}

func GenerateRandomKey(strength int) []byte {
	k := make([]byte, strength)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		return nil
	}
	return k
}
