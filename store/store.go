package store

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"io"

	"golang.org/x/crypto/scrypt"
)

var (
	ErrEmailDuplication = errors.New("The email is already in the store")
	ErrUserNotFound     = errors.New("User not found")
	ErrWrongPassword    = errors.New("email or password is incorrent")
)

type User struct {
	Id       string
	Email    string
	Password string
	Salt     string
}

type UserRepository interface {
	Signin(email, pass string) (string, error)
	Login(email, pass string) (string, error)
	UserByEmail(email string) (User, error)
}

func NewUser(userId, email, pass string) (User, error) {
	salt := GenerateRandomKey(128)
	hpass, err := HashPassword(pass, salt)

	if err != nil {
		return User{}, err
	}
	return User{
		Id:       userId,
		Email:    email,
		Password: string(hpass),
		Salt:     string(salt),
	}, nil
}

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
