package jwt

import (
	"errors"
	"log"
	"net/http"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

var (
	ErrTokenExpired    = errors.New("Token Expired, get a new one")
	ErrTokenValidation = errors.New("JWT Token ValidationError")
	ErrTokenParse      = errors.New("JWT Token Error Parsing the token or empty token")
	ErrTokenInvalid    = errors.New("JWT Token is not Valid")

	logOn = true
)

type Options struct {
	SigningMethod string
	PublicKey     string
	PrivateKey    string
	Expiration    time.Duration
}

// Generates a JSON Web Token given an userId (typically an id or an email), and the JWT options
// to set SigningMethod and the keys you can check
// http://github.com/dgrijalva/jwt-go
//
// In case you use an symmetric-key algorithm set PublicKey and PrivateKey equal to the SecretKey ,
func GenerateJWTToken(userId string, op Options) (string, error) {
	t := jwt.New(jwt.GetSigningMethod(op.SigningMethod))

	// set claims
	t.Claims["exp"] = time.Now().Add(op.Expiration).Unix()
	t.Claims["iat"] = time.Now().Unix()
	t.Claims["sub"] = userId

	tokenString, err := t.SignedString([]byte(op.PrivateKey))
	if err != nil {
		logError("ERROR: GenerateJWTToken: %v\n", err)
	}
	return tokenString, err

}

// Validates the token that is passed in the request with the Authorization header
// Authorization: Bearer eyJhbGciOiJub25lIn0
//
// Returns the userId, token (base64 encoded), error
func ValidateToken(r *http.Request, publicKey string) (string, string, error) {
	token, err := jwt.ParseFromRequest(r, func(token *jwt.Token) (interface{}, error) {
		return []byte(publicKey), nil
	})

	if err != nil {
		switch err.(type) {
		case *jwt.ValidationError:
			vErr := err.(*jwt.ValidationError)

			switch vErr.Errors {
			case jwt.ValidationErrorExpired:
				logError("ERROR: JWT Token Expired: %+v\n", vErr.Errors)
				return "", "", ErrTokenExpired
			default:
				logError("ERROR: JWT Token ValidationError: %+v\n", vErr.Errors)
				return "", "", ErrTokenValidation
			}
		}
		logError("ERROR: Token parse error: %v\n", err)
		return "", "", ErrTokenParse
	}

	if !token.Valid {
		return "", "", ErrTokenInvalid
	}

	// otherwise is a valid token
	userId := token.Claims["sub"].(string)

	return userId, token.Raw, nil

}

func logError(format string, err interface{}) {
	if logOn && err != nil {
		log.Printf(format, err)
	}
}
