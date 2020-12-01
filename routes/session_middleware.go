package routes

import (
	"context"
	"log"
	"net/http"

	"github.com/dgrijalva/jwt-go"
	"github.com/m-barthelemy/vpn-webauth/models"
)

// TODO: this is redefined in oauth_google.go!!!! Ugly!!!
type Claims struct {
	Username string `json:"username"`
	HasMFA   bool   `json:"has_mfa"`
	jwt.StandardClaims
}

type SessionHandler struct {
	config *models.Config
}

func NewSessionHandler(config *models.Config) *SessionHandler {
	return &SessionHandler{config: config}
}

func (s *SessionHandler) SessionMiddleware(jwtKey []byte, h http.HandlerFunc, allowNoSession bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookieName := "vpnwa_session"
		if s.config.SSLMode != "off" {
			cookieName = "__Host-" + cookieName
		}
		session, err := r.Cookie(cookieName)
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
			ctx = context.WithValue(ctx, "sessionExpiresAt", claims.ExpiresAt)
			ctx = context.WithValue(ctx, "hasMfa", claims.HasMFA)
			r = r.WithContext(ctx)
		}
		h(w, r)
	}
}

func (s *SessionHandler) IdentificationMiddleware(jwtKey []byte, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookieName := "vpnwa_identified_user"
		if s.config.SSLMode != "off" {
			cookieName = "__Host-" + cookieName
		}
		session, err := r.Cookie(cookieName)
		if err != nil {
			log.Printf("Cannot find identification cookie: %s", err.Error())
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
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

		if token.Valid {
			ctx := context.WithValue(r.Context(), "identity", claims.Subject)
			r = r.WithContext(ctx)
		}
		h(w, r)
	}
}
