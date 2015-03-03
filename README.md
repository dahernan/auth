# Authentication Middleware for Go Standard HTTP library and Negroni

This is a library to provides secure authentication based in JWT tokens and a implementation to store the users and the hashed passwords

## Features

* Authentication of the users via configurable store
* `net/http` compatible
* [Negroni](https://github.com/codegangsta/negroni) middleware
* Uses of JSON Web Tokens (JWT) 
* JSON interface

## Store support

* BoltDB

## Example with standard library

```go
package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/boltdb/bolt"
	"github.com/dahernan/auth"
	"github.com/dahernan/auth/jwt"
	"github.com/dahernan/auth/store"
)

func main() {
	// Using BoltDB to store the users
	db, err := bolt.Open("usersdb", 0600, &bolt.Options{})
	if err != nil {
		log.Fatalln("Can not open the database", err)
	}
	defer db.Close()

	boltStore, err := store.NewBoltStore(db, "users")
	if err != nil {
		log.Fatalln("Can not create bolt store", err)
	}

	// check github.com/dgrijalva/jwt-go for the JWT options
	options := jwt.Options{
		SigningMethod: "RS256",
		PrivateKey:    Private, // $ openssl genrsa -out app.rsa keysize
		PublicKey:     Public,  // $ openssl rsa -in app.rsa -pubout > app.rsa.pub
		Expiration:    60 * time.Minute,
	}

	// creates the route with Bolt and JWT options
	authRoute := auth.NewAuthRoute(boltStore, options)

	http.HandleFunc("/login", authRoute.Login)
	http.HandleFunc("/signin", authRoute.Signin)

	// protects this handle 
	http.Handle("/secure", authRoute.AuthHandlerFunc(SecurePlace))
	http.ListenAndServe(":1212", nil)

}

func SecurePlace(w http.ResponseWriter, req *http.Request) {
	userId := auth.GetUserId(req)
	token := auth.GetToken(req)
	fmt.Fprintf(w, "Hey %v you have a token %v", userId, token)
}
```

## Example with Negroni

```go
package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/codegangsta/negroni"
	"github.com/julienschmidt/httprouter"

	"github.com/boltdb/bolt"
	"github.com/dahernan/auth"
	"github.com/dahernan/auth/jwt"
	"github.com/dahernan/auth/store"
)

func SecurePlace(w http.ResponseWriter, req *http.Request) {
	userId := auth.GetUserId(req)
	token := auth.GetToken(req)
	fmt.Fprintf(w, "Hey %v you have a token %v", userId, token)
}

func main() {

	// Using BoltDB to store the users
	db, err := bolt.Open("usersdb", 0600, &bolt.Options{})
	if err != nil {
		log.Fatalln("Can not open the database", err)
	}
	defer db.Close()

	boltStore, err := store.NewBoltStore(db, "users")
	if err != nil {
		log.Fatalln("Can not create bolt store", err)
	}

	// check github.com/dgrijalva/jwt-go for the JWT options
	options := jwt.Options{
		SigningMethod: "RS256",
		PrivateKey:    Private, // $ openssl genrsa -out app.rsa keysize
		PublicKey:     Public,  // $ openssl rsa -in app.rsa -pubout > app.rsa.pub
		Expiration:    60 * time.Minute,
	}

	authRoute := auth.NewAuthRoute(boltStore, options)

	// authMicroservice
	authMicro := httprouter.New()
	authMicro.HandlerFunc("POST", "/login", authRoute.Login)
	authMicro.HandlerFunc("POST", "/signin", authRoute.Signin)

	n := negroni.Classic()
	n.UseHandler(authMicro)
	go n.Run(":1211")

	// the App
	router := httprouter.New()
	router.HandlerFunc("GET", "/secure", SecurePlace)

	app := negroni.Classic()
	// Use the middleware to protect this app
	app.Use(negroni.HandlerFunc(authRoute.AuthMiddleware))
	app.UseHandler(router)
	app.Run(":1212")

}
```

## API 

### Signin

```
$ curl -XPOST "http://localhost:1212/signin" -d'
> {
>    "email": "dahernan@dahernan.com",
>    "password": "justTest123"
> }'

{"id":"dahernan@dahernan.com"}

```

### Login 
```
$ curl -XPOST "http://localhost:1212/login" -d'
> {
>    "email": "dahernan@dahernan.com",
>    "password": "justTest123"
> }'

{"token":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0MjU0MDcyMTksImlhdCI6MTQyNTQwMzYxOSwic3ViIjoiZGFoZXJuYW5AZGFoZXJuYW4uY29tIn0.inRfTdlPZ4dKbHY2dHzTqmyBzLIW9_52oc8NFh_yfnrVEdCzfIAIHIVo_7cksUdUdQ4yMciy-JbuQc8hECx31a3RDNkH2iUSDaueZqM0nJaHsWdLAtO_8nz_zX6AqxPPP-cTb5Qjw3R8cmsrFTwpqTn7agDxgypn7NxFW67WIq_XcjH9Ev9VKFqC7AoV9wo2noX6l42JL_338UoNib3K--cUKTeJdCjygj-LH2TBobG9t3Wn55rFmr1oVfKMOTVx1eJpRl376tUemD-IXxCN0ZG788TLihLhXolbumnHzJ13AzriQEHTOc2GKtwT5M-DqEpj9lhV6uu6clPRFRs9O2PB82t4LkuhWra62-h9_R7fBaCN1-ni03RI-tXKUpWz1XFfcbHzCXzFOhl0fb_h_xpx-xEDKFbEE6JDQowxIIFNTIElv7kz0wke_QUddK1Lz--StMr2BS9Q3h3Xk1XC0dgHsSfZDvF-qbud-asUbaoaokNlsAm0kwUSMTJ_oBi1"}
```

### GET Secure url without Token

```
$ curl -XGET "http://localhost:1212/secure"

Error no token is provided
```

### GET Secure url with Token

```
$ curl -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0MjU0MDcyMTksImlhdCI6MTQyNTQwMzYxOSwic3ViIjoiZGFoZXJuYW5AZGFoZXJuYW4uY29tIn0.inRfTdlPZ4dKbHY2dHzTqmyBzLIW9_52oc8NFh_yfnrVEdCzfIAIHIVo_7cksUdUdQ4yMciy-JbuQc8hECx31a3RDNkH2iUSDaueZqM0nJaHsWdLAtO_8nz_zX6AqxPPP-cTb5Qjw3R8cmsrFTwpqTn7agDxgypn7NxFW67WIq_XcjH9Ev9VKFqC7AoV9wo2noX6l42JL_338UoNib3K--cUKTeJdCjygj-LH2TBobG9t3Wn55rFmr1oVfKMOTVx1eJpRl376tUemD-IXxCN0ZG788TLihLhXolbumnHzJ13AzriQEHTOc2GKtwT5M-DqEpj9lhV6uu6clPRFRs9O2PB82t4LkuhWra62-h9_R7fBaCN1-ni03RI-tXKUpWz1XFfcbHzCXzFOhl0fb_h_xpx-xEDKFbEE6JDQowxIIFNTIElv7kz0wke_QUddK1Lz--StMr2BS9Q3h3Xk1XC0dgHsSfZDvF-qbud-asUbaoaokNlsAm0kwUSMTJ_oBi1" -XGET "http://localhost:1212/secure"

Hey dahernan@dahernan.com you have a token
```

