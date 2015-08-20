package store

import (
	"bytes"
	"encoding/gob"
	"fmt"

	"github.com/boltdb/bolt"
	"github.com/dahernan/auth/crypto"
)

type BoltStore struct {
	db     *bolt.DB
	bucket []byte
}

func NewBoltStore(db *bolt.DB, userBucket string) (*BoltStore, error) {
	bucket := []byte(userBucket)

	err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(bucket)
		if err != nil {
			return fmt.Errorf("Creating bucket: %s", err)
		}
		return nil
	})
	return &BoltStore{db: db, bucket: bucket}, err
}

func (bs *BoltStore) UserByEmail(email string) (User, error) {
	var user User
	err := bs.db.View(func(tx *bolt.Tx) error {
		var err error
		b := tx.Bucket(bs.bucket)

		gobUser := b.Get([]byte(email))
		if gobUser == nil {
			return ErrUserNotFound
		}

		user, err = gobDecode(gobUser)
		return err
	})

	return user, err
}

func (bs *BoltStore) Signin(email, pass string) (string, error) {
	// check if the user exists
	_, err := bs.UserByEmail(email)
	if err == nil {
		return "", ErrEmailDuplication
	}

	err = bs.db.Update(func(tx *bolt.Tx) error {

		b := tx.Bucket(bs.bucket)

		// email is going to be the Id of the user
		user, err := NewUser(email, email, pass)
		if err != nil {
			return err
		}
		g, err := gobEncode(user)
		if err != nil {
			return err
		}
		err = b.Put([]byte(email), g)
		return err
	})

	if err != nil {
		return "", err
	}

	return email, nil

}

func (bs *BoltStore) Login(email, pass string) (string, error) {
	user, err := bs.UserByEmail(email)
	if err != nil {
		return "", ErrWrongPassword
	}
	passStored := user.Password
	salt := user.Salt

	hpass, err := crypto.HashPassword(pass, []byte(salt))
	if err != nil {
		return "", err
	}
	passOk := crypto.SecureCompare(hpass, []byte(passStored))
	if !passOk {
		return "", ErrWrongPassword
	}
	return user.Id, nil
}

func gobEncode(user User) ([]byte, error) {
	var buffer bytes.Buffer
	enc := gob.NewEncoder(&buffer)

	err := enc.Encode(user)
	if err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func gobDecode(b []byte) (User, error) {
	reader := bytes.NewReader(b)
	dec := gob.NewDecoder(reader)
	var u User
	err := dec.Decode(&u)
	if err != nil {
		return User{}, err
	}
	return u, nil
}
