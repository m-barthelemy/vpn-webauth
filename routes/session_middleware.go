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
	HasMFA   bool   `json:"has_mfa"`
	jwt.StandardClaims
}

func sessionMiddleware(jwtKey []byte, h http.HandlerFunc, allowNoSession bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := r.Cookie("vpnwa_session")
		if err != nil {
			if !allowNoSession {
				log.Printf("Cannot find session cookie: %s", err.Error())
				if r.Header.Get("Accept") == "application/json" {
					http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
					return
				}
				http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
				return
			}
			h(w, r)
			return
		}

		tokenString := session.Value
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil && !allowNoSession {
			if err == jwt.ErrSignatureInvalid {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if !token.Valid && !allowNoSession {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if token.Valid {
			ctx := context.WithValue(r.Context(), "identity", claims.Username)
			ctx = context.WithValue(ctx, "hasMfa", claims.HasMFA)
			r = r.WithContext(ctx)
		}
		h(w, r)
	}
}
