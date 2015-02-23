package store

import (
	"testing"
	"time"

	"github.com/boltdb/bolt"
	. "github.com/smartystreets/goconvey/convey"
)

func DeleteBucket(t *testing.T, db *bolt.DB, bucket string) {
	db.Update(func(tx *bolt.Tx) error {
		err := tx.DeleteBucket([]byte(bucket))
		if err != nil {
			t.Errorf("Deleting bucket: %s", err)
			return err
		}
		return nil
	})
}

func NewDB(t *testing.T, name string) *bolt.DB {
	db, err := bolt.Open(name, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		t.Error(err)
	}
	return db
}

func TestSignIn(t *testing.T) {
	Convey("SingIn in Bolt", t, func() {
		db := NewDB(t, "testUsers.db")
		defer db.Close()

		bucket := "testBucket"
		DeleteBucket(t, db, bucket)
		bs, err := NewBoltStore(db, bucket)
		So(err, ShouldBeNil)
		So(bs, ShouldNotBeNil)

		email := "ddhhpp@test.com"
		id, err := bs.Signin(email, "123456")
		So(err, ShouldBeNil)
		So(id, ShouldEqual, email)

	})
}

func TestSignInDuplicateEmail(t *testing.T) {
	Convey("SingIn in fail because a duplicate email", t, func() {
		db := NewDB(t, "testUsers.db")
		defer db.Close()

		bucket := "testBucketDup"
		DeleteBucket(t, db, bucket)
		bs, err := NewBoltStore(db, bucket)
		So(err, ShouldBeNil)
		So(bs, ShouldNotBeNil)

		email := "ddhhpp@test.com"
		id, err := bs.Signin(email, "123456")
		So(err, ShouldBeNil)
		So(id, ShouldEqual, email)

		_, err = bs.Signin(email, "123456")
		So(err, ShouldEqual, ErrEmailDuplication)

	})
}

func TestGetUserDataByEmail(t *testing.T) {
	Convey("Gets the user data by the email", t, func() {
		db := NewDB(t, "testUsers.db")
		defer db.Close()

		bucket := "testBucketGet"
		DeleteBucket(t, db, bucket)
		bs, err := NewBoltStore(db, bucket)
		So(err, ShouldBeNil)
		So(bs, ShouldNotBeNil)

		email := "ddhhpp@test.com"
		id, err := bs.Signin(email, "123456")
		So(err, ShouldBeNil)
		So(id, ShouldEqual, email)

		user, err := bs.UserByEmail(email)
		So(err, ShouldBeNil)

		So(user.Id, ShouldEqual, email)
		So(user.Email, ShouldEqual, email)
		So(user.Password, ShouldNotBeEmpty)
		So(user.Salt, ShouldNotBeEmpty)

	})
}

func TestGetUserDataByEmailReturnUserNotFound(t *testing.T) {
	Convey("Gets the user data by the email returns an error if the user is not found", t, func() {
		db := NewDB(t, "testUsers.db")
		defer db.Close()

		bucket := "testBucketNotFound"
		DeleteBucket(t, db, bucket)
		bs, err := NewBoltStore(db, bucket)
		So(err, ShouldBeNil)
		So(bs, ShouldNotBeNil)

		email := "ddhhpp@test.com"
		_, err = bs.UserByEmail(email)
		So(err, ShouldEqual, ErrUserNotFound)

	})
}

func TestLogIn(t *testing.T) {
	Convey("Log in Bolt", t, func() {
		db := NewDB(t, "testUsers.db")
		defer db.Close()

		bucket := "testBucketLog"
		DeleteBucket(t, db, bucket)
		bs, err := NewBoltStore(db, bucket)
		So(err, ShouldBeNil)
		So(bs, ShouldNotBeNil)

		email := "ddhhpp@test.com"
		pass := "123456"
		id, err := bs.Signin(email, pass)
		So(err, ShouldBeNil)
		So(id, ShouldEqual, email)

		id, err = bs.Login(email, pass)
		So(err, ShouldBeNil)
		So(id, ShouldEqual, email)
	})
}

func TestLogInBadEmail(t *testing.T) {
	Convey("Log in returns an error if the user is not found", t, func() {
		db := NewDB(t, "testUsers.db")
		defer db.Close()

		bucket := "testBucketLogNoUser"
		DeleteBucket(t, db, bucket)
		bs, err := NewBoltStore(db, bucket)
		So(err, ShouldBeNil)
		So(bs, ShouldNotBeNil)

		email := "ddhhpp@test.com"
		pass := "123456"
		id, err := bs.Signin(email, pass)
		So(err, ShouldBeNil)
		So(id, ShouldEqual, email)

		_, err = bs.Login("no@user.com", pass)
		So(err, ShouldEqual, ErrWrongPassword)

	})
}

func TestLogInBadPass(t *testing.T) {
	Convey("Log in returns an error if the password is wrong", t, func() {
		db := NewDB(t, "testUsers.db")
		defer db.Close()

		bucket := "testBucketLogNoUser"
		DeleteBucket(t, db, bucket)
		bs, err := NewBoltStore(db, bucket)
		So(err, ShouldBeNil)
		So(bs, ShouldNotBeNil)

		email := "ddhhpp@test.com"
		pass := "123456"
		id, err := bs.Signin(email, pass)
		So(err, ShouldBeNil)
		So(id, ShouldEqual, email)

		_, err = bs.Login(email, "xyz")
		So(err, ShouldEqual, ErrWrongPassword)

	})
}
