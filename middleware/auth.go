package middleware

import (
	"crypto/rand"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/jwtauth"
)

type JWT struct {
	TokenClaim string
	TokenAuth  *jwtauth.JWTAuth
}

var Jwt JWT

func init() {
	Jwt.TokenClaim = "user_id"
	token := make([]byte, 32)
	rand.Read(token)
	log.Printf("Token: %x \n", token)
	Jwt.TokenAuth = jwtauth.New("HS256", token, nil)
}

func EncodeJWT(id string) string {
	expiration := (24 * time.Hour)
	claims := map[string]interface{}{Jwt.TokenClaim: id, "exp": expiration}
	_, tokenString, _ := Jwt.TokenAuth.Encode(claims)
	return tokenString
}

func DecodeJWT(r *http.Request) interface{} {
	_, claims, _ := jwtauth.FromContext(r.Context())
	userid := claims[Jwt.TokenClaim]
	return userid
}
