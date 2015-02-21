package jwt

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
)

var (
	Private string
	Public  string
)

func TestGenerateToken(t *testing.T) {
	Convey("Generates a token with a RSA 256 key and Validate it", t, func() {

		userId := "3"
		op := Options{
			SigningMethod: "RS256",
			PublicKey:     Public,
			PrivateKey:    Private,
			Expiration:    3 * time.Minute,
		}

		token, err := GenerateJWTToken(userId, op)

		So(err, ShouldBeNil)
		So(token, ShouldNotBeNil)

		handler := func(w http.ResponseWriter, req *http.Request) {
			user, rawToken, err := ValidateToken(req, Public)

			So(err, ShouldBeNil)
			So(user, ShouldEqual, userId)
			So(rawToken, ShouldNotBeNil)

			fmt.Fprintf(w, "OK")
		}

		req, err := http.NewRequest("GET", "http://testserver", nil)
		req.Header.Add("Authorization", strings.Join([]string{"Bearer", token}, " "))

		if err != nil {
			t.Fatal(err)
		}

		w := httptest.NewRecorder()
		handler(w, req)

		t.Logf("%d - %s", w.Code, w.Body.String())

	})
}

func TestInvalidToken(t *testing.T) {
	Convey("Validate an invalid token returns an error", t, func() {

		userId := "3"
		op := Options{
			SigningMethod: "RS256",
			PublicKey:     Public,
			PrivateKey:    Private,
			Expiration:    3 * time.Minute,
		}

		token, err := GenerateJWTToken(userId, op)

		So(err, ShouldBeNil)
		So(token, ShouldNotBeNil)

		handler := func(w http.ResponseWriter, req *http.Request) {
			_, _, err := ValidateToken(req, Public)

			So(err, ShouldEqual, ErrTokenValidation)

			fmt.Fprintf(w, "OK")
		}

		req, err := http.NewRequest("GET", "http://testserver", nil)
		req.Header.Add("Authorization", strings.Join([]string{"Bearer", "ThisIsInvalid"}, " "))

		if err != nil {
			t.Fatal(err)
		}

		w := httptest.NewRecorder()
		handler(w, req)

	})
}

func TestExpiredToken(t *testing.T) {
	Convey("Validates a expiration", t, func() {

		userId := "3"
		// very short expiration time
		op := Options{
			SigningMethod: "RS256",
			PublicKey:     Public,
			PrivateKey:    Private,
			Expiration:    1 * time.Microsecond,
		}

		token, err := GenerateJWTToken(userId, op)

		So(err, ShouldBeNil)
		So(token, ShouldNotBeNil)

		handler := func(w http.ResponseWriter, req *http.Request) {
			time.Sleep(5 * time.Microsecond)
			_, _, err := ValidateToken(req, Public)

			So(err, ShouldEqual, ErrTokenExpired)

			fmt.Fprintf(w, "OK")
		}

		req, err := http.NewRequest("GET", "http://testserver", nil)
		req.Header.Add("Authorization", strings.Join([]string{"Bearer", token}, " "))

		if err != nil {
			t.Fatal(err)
		}

		w := httptest.NewRecorder()
		handler(w, req)

		t.Logf("%d - %s", w.Code, w.Body.String())

	})
}

func TestNotToken(t *testing.T) {
	Convey("Validates a nil token", t, func() {

		userId := "3"

		op := Options{
			SigningMethod: "RS256",
			PublicKey:     Public,
			PrivateKey:    Private,
			Expiration:    3 * time.Minute,
		}
		token, err := GenerateJWTToken(userId, op)

		So(err, ShouldBeNil)
		So(token, ShouldNotBeNil)

		handler := func(w http.ResponseWriter, req *http.Request) {
			time.Sleep(2 * time.Microsecond)
			_, _, err := ValidateToken(req, Public)

			So(err, ShouldEqual, ErrTokenParse)

			fmt.Fprintf(w, "OK")
		}

		req, err := http.NewRequest("GET", "http://testserver", nil)
		if err != nil {
			t.Fatal(err)
		}

		w := httptest.NewRecorder()
		handler(w, req)

		t.Logf("%d - %s", w.Code, w.Body.String())

	})
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

}
