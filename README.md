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
	http.Handle("/sercured", authRoute.AuthHandlerFunc(SecurePlace))
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
	router.HandlerFunc("GET", "/secured", SecurePlace)

	app := negroni.Classic()
	// Use the middleware to protect this app
	app.Use(negroni.HandlerFunc(authRoute.AuthMiddleware))
	app.UseHandler(router)
	app.Run(":1212")

}
```
