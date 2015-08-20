package store

import (
	"errors"

	"github.com/dahernan/auth/crypto"
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
	salt := crypto.GenerateRandomKey(128)
	hpass, err := crypto.HashPassword(pass, salt)

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
