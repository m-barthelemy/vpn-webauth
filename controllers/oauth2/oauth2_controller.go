package controllers

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/m-barthelemy/vpn-webauth/models"
	services "github.com/m-barthelemy/vpn-webauth/services"

	//oAuthManager "github.com/m-barthelemy/vpn-webauth/services"
	"github.com/m-barthelemy/vpn-webauth/utils"
	"gorm.io/gorm"
)

type OAuth2Controller struct {
	db     *gorm.DB
	config *models.Config
}

var oAuthProvider services.OAuth2Provider

func New(db *gorm.DB, config *models.Config) *OAuth2Controller {
	// Scopes: OAuth 2.0 scopes provide a way to limit the amount of access that is granted to an access token.

	if config.OAuth2Provider == "google" {
		oAuthProvider = services.NewGoogleProvider(config.RedirectDomain.String(), "", config.OAuth2ClientID, config.OAuth2ClientSecret)

	} else if config.OAuth2Provider == "azure" {
		oAuthProvider = services.NewMicrosoftProvider(config.RedirectDomain.String(), "", config.OAuth2ClientID, config.OAuth2ClientSecret)
	}

	return &OAuth2Controller{db: db, config: config}
}

// OauthGoogleLogin redirects to Google for the actual login
func (g *OAuth2Controller) OAuth2BeginLogin(w http.ResponseWriter, r *http.Request) {
	contextValue := r.Context().Value("identity")

	// If we have a valid session, directly move to next step
	if contextValue != nil {
		var email = contextValue.(string)
		g.afterFirstAuthStep(email, w, r)
		return
	}

	oauthState := g.generateStateCookie("oauthstate", w)
	url := oAuthProvider.GetURL(oauthState)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// OauthGoogleCallback is called once the Google authentication has been completed
func (g *OAuth2Controller) OAuth2Callback(w http.ResponseWriter, r *http.Request) {
	oauthState, err := r.Cookie("oauthstate")
	if err != nil {
		log.Errorf("OAuth2Controller: error fetching OAuth state cookie: %s", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	// The state value in the URL when Google redirects back to us, and in the `oauthState` cookie, must match.
	if r.FormValue("state") != oauthState.Value {
		log.Error("OAuth2Controller: invalid OAuth state")
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	oauthUser, err := oAuthProvider.GetUserInfo(r.FormValue("code"))
	if err != nil {
		log.Errorf("OAuth2Controller: error fetching user info from %s: %s", err, g.config.OAuth2Provider)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	if oauthUser.Email == "" {
		log.Errorf("OAuth2Controller: %s user `email` field is null or empty", g.config.OAuth2Provider)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	userIdentity := oauthUser.Email
	log.Infof("User %s completed %s authentication step", userIdentity, g.config.OAuth2Provider)
	g.afterFirstAuthStep(userIdentity, w, r)
}

func (g *OAuth2Controller) afterFirstAuthStep(email string, w http.ResponseWriter, r *http.Request) {
	userManager := services.NewUserManager(g.db, g.config)
	user, err := userManager.CheckOrCreate(email)
	if err != nil {
		log.Error(err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if userManager.CreateSession(user, false, w) != nil {
		log.Errorf("OAuth2Controller: error creating user oauth2-only session for %s: %s", user.Email, err)
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
				log.Errorf("OAuth2Controller: error creating UserMFA for %s: %s", user.Email, err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
		}

		err := userManager.CreateVpnSession(user, sourceIP)
		if err != nil {
			log.Errorf("OAuth2Controller: error creating VPN session for %s : %s", user.Email, err.Error())
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
			log.Infof("OAuth2Controller: user %s already has MFA setup, requesting additional authentication.", user.Email)
			http.Redirect(w, r, fmt.Sprintf("/enter2fa?options=%s", options), http.StatusTemporaryRedirect)
			return
		}
	}

	// If we get there, the User has no MFA configured or validated.
	options := utils.New(g.config).GetAllowedMFAs()
	log.Infof("OAuth2Controller: user %s hasn't setup MFA, redirecting to MFA selection.", email)
	http.Redirect(w, r, fmt.Sprintf("/choose2fa?options=%s", strings.Join(options, ",")), http.StatusTemporaryRedirect)
}

// Availeble MFA options for registration
func (g *OAuth2Controller) GetMFaChoosePage(w http.ResponseWriter, r *http.Request) {
	options := utils.New(g.config).GetAllowedMFAs()
	http.Redirect(w, r, fmt.Sprintf("/choose2fa?options=%s", strings.Join(options, ",")), http.StatusTemporaryRedirect)
}

func (g *OAuth2Controller) generateStateCookie(name string, w http.ResponseWriter) string {
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
