package controllers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/protocol/webauthncose"
	"github.com/duo-labs/webauthn/webauthn"
	"github.com/gofrs/uuid"
	"github.com/m-barthelemy/vpn-webauth/models"
	dataProtector "github.com/m-barthelemy/vpn-webauth/services"
	userManager "github.com/m-barthelemy/vpn-webauth/services"

	"gorm.io/gorm"
)

// Inspired by https://github.com/hbolimovsky/webauthn-example/blob/master/server.go

type WebAuthNController struct {
	db     *gorm.DB
	config *models.Config
}

// New creates an instance of the controller and sets its DB handle
func New(db *gorm.DB, config *models.Config) *WebAuthNController {
	return &WebAuthNController{db: db, config: config}
}

func (m *WebAuthNController) BeginRegisterWebauthn(w http.ResponseWriter, r *http.Request) {
	var email = r.Context().Value("identity").(string)
	if email == "" {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	var user *models.User
	// Ensure User exists
	userManager := userManager.New(m.db, m.config)
	user, err := userManager.Get(email)
	if err != nil {
		log.Printf("WebAuthNController: Error fetching user: %s", err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	webAuthnType := "webauthn"
	webAuthnTypeParam, ok := r.URL.Query()["type"]
	if !ok {
		log.Printf("WebAuthNController: Error getting Url Param 'type'")
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	if len(webAuthnTypeParam[0]) >= 1 && webAuthnTypeParam[0] == "touchid" {
		webAuthnType = "touchid"
	}
	// Ensure Webauthn does not already exist for the user
	if user.MFAs != nil {
		for _, item := range user.MFAs {
			if item.Type == webAuthnType {
				log.Printf("WebAuthNController: User %s already has an authentication provider of type %s", user.Email, webAuthnType)
				http.Error(w, http.StatusText(http.StatusConflict), http.StatusConflict)
				return
			}
		}
	}

	webAuthn, err := webauthn.New(&webauthn.Config{
		RPDisplayName: m.config.MFAIssuer, // Display Name or the site
		RPID:          m.config.RedirectDomain.Hostname(),
		RPOrigin:      fmt.Sprintf("%s://%s", m.config.RedirectDomain.Scheme, m.config.RedirectDomain.Hostname()), // The origin URL for WebAuthn requests
	})
	if err != nil {
		log.Printf("WebAuthNController: failed to create WebAuthn from config: %s", err)
	}

	newUserMFA, err := userManager.AddMFA(user, webAuthnType)
	newWebAuthNUser := models.NewWebAuthNUser(newUserMFA.ID, user.Email, user.Email)
	registerOptions := func(credCreationOpts *protocol.PublicKeyCredentialCreationOptions) {
		credCreationOpts.CredentialExcludeList = newWebAuthNUser.CredentialExcludeList()
	}

	// Generate PublicKeyCredentialCreationOptions, session data
	options, sessionData, err := webAuthn.BeginRegistration(
		newWebAuthNUser,
		registerOptions,
	)
	options.Response.Timeout = 120000
	if webAuthnType == "touchid" {
		options.Response.AuthenticatorSelection.AuthenticatorAttachment = protocol.Platform
		// Apple attestation format not supported
		//options.Response.Attestation = protocol.PreferDirectAttestation
	} else {
		options.Response.AuthenticatorSelection.AuthenticatorAttachment = protocol.CrossPlatform
	}
	// Only ES256 (alg: -7) is supported by Touchid
	options.Response.Parameters = nil
	pubKey := protocol.CredentialParameter{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgES256}
	options.Response.Parameters = append(options.Response.Parameters, pubKey)

	if err := m.createWebauthNCookie("webauthn_register", sessionData, w); err != nil {
		log.Printf("WebAuthNController: Failed to create registration cookie: %s", err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}

	jsonResponse(w, options, http.StatusOK)
}

func (m *WebAuthNController) FinishRegisterWebauthn(w http.ResponseWriter, r *http.Request) {
	var email = r.Context().Value("identity").(string)
	if email == "" {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	webAuthnType := "webauthn"
	webAuthnTypeParam, ok := r.URL.Query()["type"]
	if !ok {
		log.Printf("WebAuthNController: Error getting Url Param 'type'")
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	if len(webAuthnTypeParam[0]) >= 1 && webAuthnTypeParam[0] == "touchid" {
		webAuthnType = "touchid"
	}

	// Ensure User exists
	userManager := userManager.New(m.db, m.config)
	user, err := userManager.Get(email)
	if err != nil {
		log.Printf("WebAuthNController: Error fetching user: %s", err.Error)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	sessionData, err := m.getWebauthNCookie("webauthn_register", w, r)
	if err != nil {
		log.Printf("WebAuthNController: Error fetching registration session for %s: ", user.Email, err.Error)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	webAuthn, err := webauthn.New(&webauthn.Config{
		RPDisplayName: m.config.MFAIssuer,
		RPID:          m.config.RedirectDomain.Hostname(),
		RPOrigin:      fmt.Sprintf("%s://%s", m.config.RedirectDomain.Scheme, m.config.RedirectDomain.Hostname()), // The origin URL for WebAuthn requests
	})
	if err != nil {
		log.Printf("WebAuthNController: failed to create WebAuthn from config: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	sessionUserID, err := uuid.FromBytes(sessionData.UserID)
	if err != nil {
		log.Printf("WebAuthNController: failed to get WebAuthn ID from session: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	webAuthNUser := models.NewWebAuthNUser(sessionUserID, user.Email, user.Email)
	credential, err := webAuthn.FinishRegistration(webAuthNUser, *sessionData, r)
	if err != nil {
		log.Printf("WebAuthNController: Error validating WebAuthn registration for %s: %s", user.Email, err)
		if specificError, ok := err.(*protocol.Error); ok {
			log.Printf("WebAuthNController: Registration validation error detail: %s", specificError.DevInfo)
		}
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	serializedCredential, _ := json.Marshal(credential)
	println("Credential: %s", string(serializedCredential[:]))

	if err := userManager.ValidateMFA(user, webAuthnType, string(serializedCredential[:])); err != nil {
		log.Printf("WebAuthNController: failed to save %s registration validation for %s: %s", webAuthnType, user.Email, err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	m.deleteWebauthNCookie("webauthn_register", w)
}

/*func BeginLogin(w http.ResponseWriter, r *http.Request) {
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
*/
func jsonResponse(w http.ResponseWriter, d interface{}, c int) {
	dj, err := json.Marshal(d)
	if err != nil {
		log.Printf("WebAuthNController: Error serializing response to JSON: %s", err.Error)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(c)
	fmt.Fprintf(w, "%s", dj)
}

// Create an encrypted cookie with webauthn stateful session data
func (m *WebAuthNController) createWebauthNCookie(name string, value interface{}, w http.ResponseWriter) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	dp := dataProtector.NewDataProtector(m.config)
	encryptedData, err := dp.Encrypt(string(data[:]))
	if err != nil {
		return err
	}

	var expiration = time.Now().Add(2 * time.Minute)
	cookie := http.Cookie{
		Name:     name,
		Value:    encryptedData,
		Expires:  expiration,
		HttpOnly: true,
		Secure:   m.config.SSLMode != "off",
	}
	http.SetCookie(w, &cookie)

	return nil
}

func (m *WebAuthNController) getWebauthNCookie(name string, w http.ResponseWriter, r *http.Request) (*webauthn.SessionData, error) {
	session, err := r.Cookie(name)
	if err != nil {
		log.Printf("Cannot find WebAuthN cookie: %s", err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return nil, err
	}

	dp := dataProtector.NewDataProtector(m.config)
	decryptedData, err := dp.Decrypt(session.Value)
	if err != nil {
		return nil, err
	}
	sessionData := webauthn.SessionData{}
	err = json.Unmarshal([]byte(decryptedData), &sessionData)
	if err != nil {
		return nil, err
	}

	return &sessionData, nil
}

func (m *WebAuthNController) deleteWebauthNCookie(name string, w http.ResponseWriter) error {
	c := &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		Secure:   m.config.SSLMode != "off",
		HttpOnly: true,
	}

	http.SetCookie(w, c)
	return nil
}
