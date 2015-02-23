package auth

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/boltdb/bolt"
	"github.com/dahernan/auth/jwt"
	"github.com/dahernan/auth/store"

	. "github.com/smartystreets/goconvey/convey"
)

var (
	// filled in init at the end of the file
	options jwt.Options
	Private string
	Public  string
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
	Convey("Singin with a http request", t, func() {

		db := NewDB(t, "testHttpUsers.db")
		defer db.Close()

		bucket := "testBucket"
		DeleteBucket(t, db, bucket)
		bs, err := store.NewBoltStore(db, bucket)
		So(err, ShouldBeNil)
		So(bs, ShouldNotBeNil)

		route := NewAuthRoute(bs, options)

		email := "ddhhpp@test.com"
		pass := "123456"

		req, err := httpRequest("POST", "http://testserver", map[string]string{
			"email":    email,
			"password": pass,
		})
		So(err, ShouldBeNil)

		w := httptest.NewRecorder()
		route.Signin(w, req)

		t.Logf("%d - %s", w.Code, w.Body.String())

		var response map[string]string
		code, err := responseToJson(w, &response)
		So(err, ShouldBeNil)
		So(code, ShouldEqual, http.StatusCreated)

		So(response["id"], ShouldEqual, email)

	})
}

func TestSignInDuplicateUser(t *testing.T) {
	Convey("Singin with a http request returns a error for duplicate user", t, func() {

		db := NewDB(t, "testHttpUsers.db")
		defer db.Close()

		bucket := "testBucket"
		DeleteBucket(t, db, bucket)
		bs, err := store.NewBoltStore(db, bucket)
		So(err, ShouldBeNil)
		So(bs, ShouldNotBeNil)

		email := "ddhhpp@test.com"
		pass := "123456"

		id, err := bs.Signin(email, pass)
		So(err, ShouldBeNil)
		So(id, ShouldNotBeEmpty)

		route := NewAuthRoute(bs, options)

		req, err := httpRequest("POST", "http://testserver", map[string]string{
			"email":    email,
			"password": pass,
		})
		So(err, ShouldBeNil)

		w := httptest.NewRecorder()
		route.Signin(w, req)

		t.Logf("%d - %s", w.Code, w.Body.String())
		So(w.Code, ShouldEqual, http.StatusBadRequest)
		So(w.Body.String(), ShouldContainSubstring, "The email is already in the store")

	})
}

func TestLogin(t *testing.T) {
	Convey("Login with a http request", t, func() {
		db := NewDB(t, "testHttpUsers.db")
		defer db.Close()

		bucket := "testBucket"
		DeleteBucket(t, db, bucket)
		bs, err := store.NewBoltStore(db, bucket)
		So(err, ShouldBeNil)
		So(bs, ShouldNotBeNil)

		route := NewAuthRoute(bs, options)

		email := "ddhhpp@test.com"
		pass := "123456"

		id, err := bs.Signin(email, pass)
		So(err, ShouldBeNil)
		So(id, ShouldNotBeEmpty)

		req, err := httpRequest("POST", "http://testserver", map[string]string{
			"email":    email,
			"password": pass,
		})
		So(err, ShouldBeNil)

		w := httptest.NewRecorder()
		route.Login(w, req)

		t.Logf("%d - %s", w.Code, w.Body.String())
		So(w.Code, ShouldEqual, http.StatusOK)

		var response map[string]string
		_, err = responseToJson(w, &response)
		So(err, ShouldBeNil)
		So(response["token"], ShouldNotBeEmpty)
	})
}

func TestLoginNoUser(t *testing.T) {
	Convey("Login with a non existing user", t, func() {
		db := NewDB(t, "testHttpUsers.db")
		defer db.Close()

		bucket := "testBucket"
		DeleteBucket(t, db, bucket)
		bs, err := store.NewBoltStore(db, bucket)
		So(err, ShouldBeNil)
		So(bs, ShouldNotBeNil)

		route := NewAuthRoute(bs, options)

		email := "ddhhpp@test.com"
		pass := "123456"

		id, err := bs.Signin(email, pass)
		So(err, ShouldBeNil)
		So(id, ShouldNotBeEmpty)

		req, err := httpRequest("POST", "http://testserver", map[string]string{
			"email":    "no@test.com",
			"password": pass,
		})
		So(err, ShouldBeNil)

		w := httptest.NewRecorder()
		route.Login(w, req)

		t.Logf("%d - %s", w.Code, w.Body.String())
		So(w.Code, ShouldEqual, http.StatusUnauthorized)
		So(w.Body.String(), ShouldContainSubstring, "Username or Password Invalid")

	})
}

func TestLoginWrongPass(t *testing.T) {
	Convey("Login with a wrong password", t, func() {
		db := NewDB(t, "testHttpUsers.db")
		defer db.Close()

		bucket := "testBucket"
		DeleteBucket(t, db, bucket)
		bs, err := store.NewBoltStore(db, bucket)
		So(err, ShouldBeNil)
		So(bs, ShouldNotBeNil)

		route := NewAuthRoute(bs, options)

		email := "ddhhpp@test.com"
		pass := "123456"

		id, err := bs.Signin(email, pass)
		So(err, ShouldBeNil)
		So(id, ShouldNotBeEmpty)

		req, err := httpRequest("POST", "http://testserver", map[string]string{
			"email":    email,
			"password": "xyz",
		})
		So(err, ShouldBeNil)

		w := httptest.NewRecorder()
		route.Login(w, req)

		t.Logf("%d - %s", w.Code, w.Body.String())
		So(w.Code, ShouldEqual, http.StatusUnauthorized)
		So(w.Body.String(), ShouldContainSubstring, "Username or Password Invalid")

	})
}

func httpRequest(method string, endpoint string, requestBody interface{}) (*http.Request, error) {
	var err error

	requestBytes := make([]byte, 0)
	if requestBody != nil {
		requestBytes, err = json.Marshal(&requestBody)
		if err != nil {
			return nil, err
		}

	}
	clientReq, err := http.NewRequest(method, endpoint, bytes.NewReader(requestBytes))
	if err != nil {
		return nil, err
	}

	clientReq.Header.Add("Content-Type", "application/json")
	clientReq.Header.Add("Accept", "application/json")

	return clientReq, err

}

func responseToJson(response *httptest.ResponseRecorder, jsonResponse interface{}) (int, error) {
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return response.Code, err
	}

	if len(body) > 0 {
		err = json.Unmarshal(body, &jsonResponse)
		if err != nil {
			return response.Code, err
		}
	}

	return response.Code, nil

}

func init() {

	// keys for testing, DO NOT USE FOR ANYTHING ELSE
	// private -> openssl genrsa -out app.rsa keysize
	// public -> openssl rsa -in app.rsa -pubout > app.rsa.pub

	Private = `-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----

`
	Public = `-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA6BeD+MrULVzgSgdEWSo9
EbZe3f2F9lWLFsuTl57HygQo51dsi9iDyUaaN6pFr0xo10PzfntnzNDeOTRzIhUQ
pdWwND8d6UF17RbUad0uCokrVHUlOycVFSyzOjUEQna70HEQ14MCfIs8DQj4raDA
x5pSSWYpBdjYj6T7qcmy1quk1xCYJHRlrZKtSECrHortRK80SfEC6uPtjBEPymed
ZnHws3wetn0PwF6YImvSHEcWnK2XoUroBSNH5uMQWqWcRbcLtwP/O6duUMZUNuVO
gEOpiDsBIrtcWF1OTN+6dGLDJg1y4O6v/fsom9PuFw93n+zy3NzgqAvVVIeVOnSU
yqAEtusD8zeLr9CbL+ZZ9Aj1Z4efGi3/11uYnuIQgbhQ4O1uK1GcalFWKnkM5hNN
zqgGfssQ3e47iQyw4e7VUzyqbbMYvnnIf9ceKT6EZ+bC19dgW+4NChDCQfrdCwG1
BYglVNzgUIzSo0/y/CD5X4xOk69YzKzSkbBG7TlDkb2LAgMBAAE=
-----END PUBLIC KEY-----

`

	options = jwt.Options{
		SigningMethod: "RS256",
		PublicKey:     Public,
		PrivateKey:    Private,
		Expiration:    3 * time.Minute,
	}

}
