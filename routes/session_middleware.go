package routes

import (
	"context"
	"log"
	"net/http"

	"github.com/dgrijalva/jwt-go"
)

// TODO: this is redefined in oauth_google.go!!!! Ugly!!!
type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

func sessionMiddleware(jwtKey []byte, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := r.Cookie("vpnwa_session")
		if err != nil {
			log.Printf("Cannot find session cookie: %s", err.Error())
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}

		tokenString := session.Value
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil {
			if err == jwt.ErrSignatureInvalid {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if !token.Valid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		r = r.WithContext(context.WithValue(r.Context(), "identity", claims.Username))
		h(w, r)
	}
}
