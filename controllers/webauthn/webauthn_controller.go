package controllers

import (
	"log"
	"net/http"

	"github.com/duo-labs/webauthn/webauthn"
	"github.com/gorilla/mux"
	"github.com/m-barthelemy/vpn-webauth/models"
	userManager "github.com/m-barthelemy/vpn-webauth/services"
	"gorm.io/gorm"
)

type WebAuthNController struct {
	db     *gorm.DB
	config *models.Config
}

// New creates an instance of the controller and sets its DB handle
func New(db *gorm.DB, config *models.Config) *WebAuthNController {
	return &WebAuthNController{config: config}
}

func (m *WebAuthNController) BeginRegisterWebauthn(w http.ResponseWriter, r *http.Request) {
	var email = r.Context().Value("identity").(string)
	if email == "" {
		http.Redirect(w, r, "/choose2fa", http.StatusTemporaryRedirect)
		return
	}
	var user *models.User
	// Ensure User exists
	userManager := userManager.New(m.db, m.config)
	user, err := userManager.Get(email)
	if err != nil {
		log.Printf("WebAuthNController: Error fetching user: %s", err.Error)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	// Ensure similar Webauthn does not already exist
	webAuthnType := "webauthn"
	webAuthnTypeParam, ok := r.URL.Query()["type"]
	if !ok {
		log.Printf("Error getting Url Param 'type'")
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	if len(webAuthnTypeParam[0]) == 1 && webAuthnTypeParam[0] == "touchid" {
		webAuthnType = "touchid"
	}
	if user.MFAs != nil {
		for i, item := range user.MFAs {
			if item.Type == webAuthnType {
				log.Printf("User %s already has an authentication provider of type %s", user.Email, webAuthnType)
				http.Error(w, http.StatusText(http.StatusConflict), http.StatusConflict)
				return
			}
		}
	}

	webAuthn, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "Foobar Corp.",     // Display Name for your site
		RPID:          "localhost",        // Generally the domain name for your site
		RPOrigin:      "http://localhost", // The origin URL for WebAuthn requests
		// RPIcon: "https://duo.com/logo.png", // Optional icon URL for your site
	})

	if err != nil {
		log.Fatal("failed to create WebAuthn from config:", err)
	}
}

func (m *WebAuthNController) FinishRegisterWebauthn(email string) (*models.UserMFA, error) {

}

func BeginLogin(w http.ResponseWriter, r *http.Request) {
	var email = r.Context().Value("identity").(string)
	if email == "" {
		http.Redirect(w, r, "/choose2fa", http.StatusTemporaryRedirect)
		return
	}

	// get user
	user, err := userDB.GetUser(username)

	// user doesn't exist
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// generate PublicKeyCredentialRequestOptions, session data
	options, sessionData, err := webAuthn.BeginLogin(user)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// store session data as marshaled JSON
	err = sessionStore.SaveWebauthnSession("authentication", sessionData, r, w)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonResponse(w, options, http.StatusOK)
}

func FinishLogin(w http.ResponseWriter, r *http.Request) {

	// get username
	vars := mux.Vars(r)
	username := vars["username"]

	// get user
	user, err := userDB.GetUser(username)

	// user doesn't exist
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// load the session data
	sessionData, err := sessionStore.GetWebauthnSession("authentication", r)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// in an actual implementation, we should perform additional checks on
	// the returned 'credential', i.e. check 'credential.Authenticator.CloneWarning'
	// and then increment the credentials counter
	_, err = webAuthn.FinishLogin(user, sessionData, r)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// handle successful login
	jsonResponse(w, "Login Success", http.StatusOK)
}
