package auth

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/gorilla/context"

	"github.com/dahernan/auth/jwt"
	"github.com/dahernan/auth/store"
)

const (
	TokenKey = "token"
	UserKey  = "user"
)

type AuthRoute struct {
	userStore store.UserRepository
	options   jwt.Options
}

func NewAuthRoute(store store.UserRepository, opt jwt.Options) *AuthRoute {
	return &AuthRoute{
		userStore: store,
		options:   opt,
	}
}

func (a *AuthRoute) Login(w http.ResponseWriter, req *http.Request) {
	var authForm map[string]string

	err := RequestToJsonObject(req, &authForm)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	email := authForm["email"]
	pass := authForm["password"]

	userId, err := a.userStore.Login(email, pass)
	if err != nil {
		http.Error(w, "Username or Password Invalid", http.StatusUnauthorized)
		return
	}

	log.Println("User ID to login", userId)
	token, err := jwt.GenerateJWTToken(userId, a.options)
	if err != nil {
		http.Error(w, "Error while Signing Token :S", http.StatusInternalServerError)
		return
	}

	jtoken, err := json.Marshal(map[string]string{"token": token})
	if err != nil {
		http.Error(w, "Error marshalling the token to json", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(jtoken)
}

func (a *AuthRoute) Signin(w http.ResponseWriter, req *http.Request) {
	var authForm map[string]string

	err := RequestToJsonObject(req, &authForm)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	email := authForm["email"]
	pass := authForm["password"]

	userId, err := a.userStore.Signin(email, pass)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	juser, err := json.Marshal(map[string]string{"id": userId})
	if err != nil {
		http.Error(w, "Error marshalling the user to json", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Header().Set("Content-Type", "application/json")
	w.Write(juser)
}

func (a *AuthRoute) authenticate(w http.ResponseWriter, r *http.Request) (string, string, error) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", "", errors.New("Error no token is provided")
	}
	userId, token, err := jwt.ValidateToken(r, a.options.PublicKey)
	if err != nil {
		return "", "", err
	}
	return userId, token, nil
}

// auth middleware for negroni
func (a *AuthRoute) AuthMiddleware(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	userId, token, err := a.authenticate(w, r)

	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	context.Set(r, TokenKey, token)
	context.Set(r, UserKey, userId)
	next(w, r)
	context.Clear(r)

}

func GetUserId(r *http.Request) string {
	return context.Get(r, UserKey).(string)
}
func GetToken(r *http.Request) string {
	return context.Get(r, TokenKey).(string)
}

func (a *AuthRoute) AuthHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userId, token, err := a.authenticate(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		context.Set(r, TokenKey, token)
		context.Set(r, UserKey, userId)
		h.ServeHTTP(w, r)
		context.Clear(r)
	})
}

func RequestToJsonObject(req *http.Request, jsonDoc interface{}) error {
	defer req.Body.Close()

	decoder := json.NewDecoder(req.Body)
	err := decoder.Decode(jsonDoc)
	if err != nil {
		return err
	}
	return nil
}
