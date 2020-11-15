package controllers

import (
	"errors"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/m-barthelemy/vpn-webauth/models"
	"gorm.io/gorm"
)

type WebAuthNController struct {
	//db     *gorm.DB
	config *models.Config
}

// New creates an instance of the controller and sets its DB handle
func New(config *models.Config) *WebAuthNController {
	return &WebAuthNController{config: config}
}

func (m *WebAuthNController) BeginRegisterWebauthn(email string) (*models.WebAuthNUser, error) {
	var user models.User
	// Ensure User exists
	userResult := m.db.Where("email = ?", email).First(&user)
	if userResult.Error != nil {
		return nil, userResult.Error
	}
	// Ensure Webauthn does not already exist
	var authN models.UserMFA
	mfaResult := m.db.Where("email = ?", email).First(&authN)
	// we _need_ to get a gorm.ErrRecordNotFound error
	if mfaResult.Error == nil || !errors.Is(mfaResult.Error, gorm.ErrRecordNotFound) {
		return nil, errors.New("User already has MFA set")
	}

	return &authN, nil
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
