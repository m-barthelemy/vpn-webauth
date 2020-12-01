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
	"strings"
	"time"

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

// OauthGoogleLogin redirects to Google for the actual login
func (g *GoogleController) OauthGoogleLogin(w http.ResponseWriter, r *http.Request) {
	contextValue := r.Context().Value("identity")

	// If we have a valid session, directly move to next step
	if contextValue != nil {
		var email = contextValue.(string)
		g.afterFirstAuthStep(email, w, r)
		return
	}

	oauthState := g.generateStateCookie("oauthstate", w)

	// `select_account` forces displaying the Google account selection step, in case the user has multiple
	//  accounts registered on their device.
	url := googleOauthConfig.AuthCodeURL(oauthState) + "&prompt=select_account"
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// OauthGoogleCallback is called once the Google authentication has been completed
func (g *GoogleController) OauthGoogleCallback(w http.ResponseWriter, r *http.Request) {
	oauthState, err := r.Cookie("oauthstate")
	if err != nil {
		log.Printf("GoogleController: Error fetching OAuth state cookie: %s", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	// The state value in the URL when Google redirects back to us, and in the `oauthState` cookie, must match.
	if r.FormValue("state") != oauthState.Value {
		log.Println("GoogleController: Invalid oauth google state")
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	googleUser, err := getUserDataFromGoogle(r.FormValue("code"))
	if err != nil {
		log.Printf("GoogleController: Error fetching user info from Google: %s", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	log.Printf("User %s completed Google authentication step", googleUser.Email)

	g.afterFirstAuthStep(googleUser.Email, w, r)

}

func (g *GoogleController) afterFirstAuthStep(email string, w http.ResponseWriter, r *http.Request) {
	userManager := userManager.New(g.db, g.config)
	user, err := userManager.CheckOrCreate(email)
	if err != nil {
		log.Print(err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if userManager.CreateSession(user, false, w) != nil {
		log.Printf("GoogleController: Error creating user oauth2-only session for %s: %s", user.Email, err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	sourceIP := utils.New(g.config).GetClientIP(r)
	if !g.config.EnforceMFA {
		// If no additional 2FA required, the user has now been created and authenticated.
		// ensure they have an oauth2 MFAUser
		var requestedMFA *models.UserMFA
		if user.MFAs != nil {
			for i := range user.MFAs {
				if user.MFAs[i].Type == "oauth2" {
					requestedMFA = &user.MFAs[i]
					break
				}
			}
		}
		if requestedMFA == nil {
			if requestedMFA, err = userManager.AddMFA(user, "oauth2", "", r.Header.Get("User-Agent")); err != nil {
				log.Printf("GoogleController: Error creating UserMFA for %s: %s", user.Email, err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
		}

		err := userManager.CreateVpnSession(user, sourceIP)
		if err != nil {
			log.Printf("GoogleController: Error creating VPN session for %s : %s", user.Email, err.Error())
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
		http.Redirect(w, r, "/success", http.StatusTemporaryRedirect)
		return
	}

	if user.HasMFA() {
		options := ""
		for _, mfa := range user.MFAs {
			if mfa.IsValid() {
				options += mfa.Type + ","
			}
		}
		if len(options) > 1 {
			log.Printf("GoogleController: User %s already has MFA setup, requesting additional authentication.", user.Email)
			http.Redirect(w, r, fmt.Sprintf("/enter2fa?options=%s", options), http.StatusTemporaryRedirect)
			return
		}
	}

	// If we get there, the User has no MFA configured or validated.
	options := utils.New(g.config).GetAllowedMFAs()
	log.Printf("GoogleController: User %s hasn't setup MFA, redirecting to MFA selection.", email)
	http.Redirect(w, r, fmt.Sprintf("/choose2fa?options=%s", strings.Join(options, ",")), http.StatusTemporaryRedirect)
}

// Availeble MFA options for registration
func (g *GoogleController) GetMFaChoosePage(w http.ResponseWriter, r *http.Request) {
	options := utils.New(g.config).GetAllowedMFAs()
	http.Redirect(w, r, fmt.Sprintf("/choose2fa?options=%s", strings.Join(options, ",")), http.StatusTemporaryRedirect)
}

func (g *GoogleController) generateStateCookie(name string, w http.ResponseWriter) string {
	// Session needs to be valid until user has completed OAuth2 login, which may take longer if
	// done for the first time or on a new browser.
	var expiration = time.Now().Add(3 * time.Minute)
	b := make([]byte, 64) // random ID
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)
	cookie := http.Cookie{
		Name:     name,
		Value:    state,
		Expires:  expiration,
		HttpOnly: true,
		Secure:   g.config.SSLMode != "off",
	}
	http.SetCookie(w, &cookie)

	return state
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

	err = json.Unmarshal(contents, &user)
	return user, err
}
