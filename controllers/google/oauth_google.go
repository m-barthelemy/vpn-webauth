package controllers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/m-barthelemy/vpn-webauth/models"
	userManager "github.com/m-barthelemy/vpn-webauth/services"
	"github.com/m-barthelemy/vpn-webauth/utils"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"gorm.io/gorm"
)

type GoogleController struct {
	db     *gorm.DB
	config *models.Config
}

type GoogleUser struct {
	Id            string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified string `json:"email_verified"`
}

// Used for the session cookie
type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

var googleOauthConfig *oauth2.Config

const oauthGoogleUrlAPI = "https://www.googleapis.com/oauth2/v2/userinfo?access_token="

func New(db *gorm.DB, config *models.Config) *GoogleController {
	// Scopes: OAuth 2.0 scopes provide a way to limit the amount of access that is granted to an access token.
	googleOauthConfig = &oauth2.Config{
		RedirectURL:  fmt.Sprintf("%s/auth/google/callback", config.RedirectDomain.String()),
		ClientID:     config.GoogleClientID,
		ClientSecret: config.GoogleClientSecret,
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
		Endpoint:     google.Endpoint,
	}

	return &GoogleController{db: db, config: config}
}

func (g *GoogleController) OauthGoogleLogin(w http.ResponseWriter, r *http.Request) {
	oauthState := generateStateCookie("oauthstate", w)

	// The state value in the URL when Google redirects back to us, and in the oauthstate cookie, must match.
	u := googleOauthConfig.AuthCodeURL(oauthState)
	http.Redirect(w, r, u, http.StatusTemporaryRedirect)
}

func (g *GoogleController) OauthGoogleCallback(w http.ResponseWriter, r *http.Request) {
	oauthState, _ := r.Cookie("oauthstate")

	if r.FormValue("state") != oauthState.Value {
		log.Println("invalid oauth google state")
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	googleUser, err := getUserDataFromGoogle(r.FormValue("code"))
	if err != nil {
		log.Printf("GoogleController: error fetching user info from Google: %s", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	log.Printf("User %s completed Google authentication step", googleUser.Email)
	userManager := userManager.New(g.db, g.config)
	user, err := userManager.CheckOrCreate(googleUser.Email)
	if err != nil {
		log.Print(err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
	if g.createSession(user.Email, g.config.OTP, w) != nil {
		log.Printf("GoogleController: error creating user session: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	if g.config.OTP {
		if user.TotpValidated {
			log.Printf("GoogleController: User %s already has MFA setup, asking TOTP code.", user.Email)
			http.Redirect(w, r, "/enter2fa.html", http.StatusTemporaryRedirect)
		} else {
			log.Printf("GoogleController: User %s hasn't setup authenticator app, redirecting to registration.", googleUser.Email)
			http.Redirect(w, r, "/register2fa.html", http.StatusTemporaryRedirect)
		}
	} else { // If no additional 2FA required, user has now been created and authenticated.
		sourceIP := utils.New(g.config).GetClientIP(r)
		err := userManager.CreateVpnSession(*user, sourceIP)
		if err != nil {
			log.Printf("GoogleController: Error creating VPN session for %s : %s", user.Email, err.Error())
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
		http.Redirect(w, r, "/success.html", http.StatusTemporaryRedirect)
	}
}

func generateStateCookie(name string, w http.ResponseWriter) string {
	// Session needs to be valid until user has completed )Auth2 login, which may take longer if
	// dome for the first time or on a new browser.
	var expiration = time.Now().Add(3 * time.Minute)
	b := make([]byte, 64) // random ID
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)
	cookie := http.Cookie{Name: name, Value: state, Expires: expiration, HttpOnly: true}
	http.SetCookie(w, &cookie)

	return state
}

func (g *GoogleController) createSession(email string, requiresMFA bool, w http.ResponseWriter) error {
	jwtKey := []byte(g.config.SigningKey)
	// Session needs to be valid until user has completed initial 2FA registration if needed
	// hence the 3 minutes here.
	expirationTime := time.Now().Add(3 * time.Minute)
	claims := &Claims{
		Username: email,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return err
	}
	cookie := http.Cookie{Name: "vpnwa_session", Value: tokenString, Expires: expirationTime, HttpOnly: true, Path: "/"}
	http.SetCookie(w, &cookie)
	return nil
}

func getUserDataFromGoogle(code string) (GoogleUser, error) {
	var user GoogleUser

	token, err := googleOauthConfig.Exchange(context.Background(), code)
	if err != nil {
		return user, fmt.Errorf("GoogleController: exchange code is wrong: %s", err.Error())
	}
	response, err := http.Get(oauthGoogleUrlAPI + token.AccessToken)
	if err != nil {
		return user, fmt.Errorf("GoogleController: failed to get user info: %s", err.Error())
	}
	defer response.Body.Close()
	contents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return user, fmt.Errorf("GoogleController: failed to read response: %s", err.Error())
	}

	json.Unmarshal(contents, &user)
	return user, nil
}
