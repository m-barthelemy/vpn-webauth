package controllers

import (
	"bytes"
	"encoding/json"
	"errors"
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
	"github.com/m-barthelemy/vpn-webauth/utils"

	"gorm.io/gorm"
)

// Inspired by https://github.com/hbolimovsky/webauthn-example/blob/master/server.go

// WebAuthNController manages Webauthn Registrations and Logins.
// Note: currently Apple TouchID, Windows Hello and any platform TPM are all
// treated and configured like an Apple TouchID device
type WebAuthNController struct {
	db     *gorm.DB
	config *models.Config
}

// New creates an instance of the controller and sets its DB handle
func New(db *gorm.DB, config *models.Config) *WebAuthNController {
	return &WebAuthNController{db: db, config: config}
}

// BeginRegister starts the registration of a new Webauthn device or browser
func (m *WebAuthNController) BeginRegister(w http.ResponseWriter, r *http.Request) {
	var email = r.Context().Value("identity").(string)
	var sessionHasMFA = r.Context().Value("hasMfa").(bool)

	var user *models.User
	userManager := userManager.New(m.db, m.config)
	user, err := userManager.Get(email)
	if err != nil {
		log.Printf("WebAuthNController: Error fetching user %s: %s", email, err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Deny if the user has enabled MFA but hasn't logged in fully
	if user.HasMFA() && !sessionHasMFA {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	webAuthnType, err := getWebauthType(r)
	if err != nil {
		log.Printf("WebAuthNController: Error getting WebAuthn type: %s", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	webAuthn, err := webauthn.New(&webauthn.Config{
		RPDisplayName: m.config.MFAIssuer, // Display Name or the site
		RPID:          m.config.RedirectDomain.Hostname(),
		RPOrigin:      fmt.Sprintf("%s://%s", m.config.RedirectDomain.Scheme, m.config.RedirectDomain.Hostname()), // The origin URL for WebAuthn requests
	})
	if err != nil {
		log.Printf("WebAuthNController: failed to create WebAuthn from config: %s", err)
	}

	_, err = userManager.AddMFA(user, webAuthnType, "", r.Header.Get("User-Agent"))
	newWebAuthNUser := models.NewWebAuthNUser(user.ID, user.Email, user.Email)

	registerOptions := func(credCreationOpts *protocol.PublicKeyCredentialCreationOptions) {
		credCreationOpts.CredentialExcludeList = newWebAuthNUser.CredentialExcludeList()
		// TODO: Add all existing user webauthn creds
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
		// Only ES256 (alg: -7) is supported by Touchid
		pubKey := protocol.CredentialParameter{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgES256}
		options.Response.Parameters = nil
		options.Response.Parameters = append(options.Response.Parameters, pubKey)
	} else {
		options.Response.AuthenticatorSelection.AuthenticatorAttachment = protocol.CrossPlatform
	}

	if err := m.createWebauthNCookie("webauthn_register", sessionData, w); err != nil {
		log.Printf("WebAuthNController: Failed to create registration cookie: %s", err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}

	utils.JSONResponse(w, options, http.StatusOK)
}

func (m *WebAuthNController) FinishRegister(w http.ResponseWriter, r *http.Request) {
	var email = r.Context().Value("identity").(string)

	webAuthnType, err := getWebauthType(r)
	if err != nil {
		log.Printf("WebAuthNController: Error getting WebAuthn type: %s", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	userManager := userManager.New(m.db, m.config)
	user, err := userManager.Get(email)
	if err != nil {
		log.Printf("WebAuthNController: Error fetching user %s: %s", email, err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	sessionData, err := m.getWebauthNCookie("webauthn_register", w, r)
	if err != nil {
		log.Printf("WebAuthNController: Error fetching registration session for %s: %s", user.Email, err.Error())
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

	webAuthNUser := models.NewWebAuthNUser(user.ID, user.Email, user.Email)
	credential, err := webAuthn.FinishRegistration(webAuthNUser, *sessionData, r)
	if err != nil {
		log.Printf("WebAuthNController: Error validating WebAuthn registration for %s: %s", user.Email, err)
		if specificError, ok := err.(*protocol.Error); ok {
			log.Printf("WebAuthNController: Registration validation error detail: %s", specificError.DevInfo)
		}
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Determine which UserMFA to use
	var usedMFA *models.UserMFA
	for i, mfa := range user.MFAs {
		if mfa.Type == webAuthnType && !mfa.Validated && mfa.ExpiresAt.After(time.Now()) {
			usedMFA = &user.MFAs[i]
			break
		}
	}
	if usedMFA == nil {
		log.Printf("WebAuthNController: Couldn't find %s MFA pending validation for %s", webAuthnType, user.Email)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	serializedCredential, _ := json.Marshal(credential)
	validatedMFA, err := userManager.ValidateMFA(usedMFA, string(serializedCredential[:]))
	if err != nil {
		log.Printf("WebAuthNController: failed to save %s registration validation for %s: %s", webAuthnType, user.Email, err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	_ = m.deleteWebauthNCookie("webauthn_register", w)

	sourceIP := utils.New(m.config).GetClientIP(r)
	if err := userManager.CreateVpnSession(validatedMFA.ID, user, sourceIP); err != nil {
		log.Printf("WebAuthNController: Error creating VPN session for %s : %s", user.Email, err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	log.Printf("WebAuthNController: User %s created VPN session from %s", user.Email, sourceIP)

	if userManager.CreateSession(user.Email, true, w) != nil {
		log.Printf("WebAuthNController: Error creating user MFA session for %s: %s", user.Email, err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}

func (m *WebAuthNController) BeginLogin(w http.ResponseWriter, r *http.Request) {
	var email = r.Context().Value("identity").(string)

	webAuthnType, err := getWebauthType(r)
	if err != nil {
		log.Printf("WebAuthNController: Error getting WebAuthn type: %s", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	// Ensure User exists
	userManager := userManager.New(m.db, m.config)
	user, err := userManager.Get(email)
	if err != nil {
		log.Printf("WebAuthNController: Error fetching user %s: %s", email, err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	webAuthNUser := models.NewWebAuthNUser(user.ID, user.Email, user.Email)
	availableCredentials, err := m.getAvailableCredentials(*user, webAuthnType, true)
	if err != nil {
		log.Printf("WebAuthNController: Error fetching available webauthn credentials for %s: %s", user.Email, err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	for _, credential := range availableCredentials {
		webAuthNUser.AddCredential(credential)
	}

	webAuthn, err := webauthn.New(&webauthn.Config{
		RPDisplayName: m.config.MFAIssuer,
		RPID:          m.config.RedirectDomain.Hostname(),
		RPOrigin:      fmt.Sprintf("%s://%s", m.config.RedirectDomain.Scheme, m.config.RedirectDomain.Hostname()),
	})

	// Generate PublicKeyCredentialRequestOptions and session data
	options, sessionData, err := webAuthn.BeginLogin(webAuthNUser)
	if err != nil {
		log.Printf("WebAuthNController: Error starting Webauthn login for %s: %s", user.Email, err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if webAuthnType == "touchid" { // Only offer Touchid and skip choice of security key
		options.Response.AllowedCredentials[0].Transport = append(options.Response.AllowedCredentials[0].Transport, protocol.Internal)
	}

	if err := m.createWebauthNCookie("webauthn_login", sessionData, w); err != nil {
		log.Printf("WebAuthNController: Failed to create registration cookie: %s", err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}

	utils.JSONResponse(w, options, http.StatusOK)
}

func (m *WebAuthNController) FinishLogin(w http.ResponseWriter, r *http.Request) {
	var email = r.Context().Value("identity").(string)

	webAuthnType, err := getWebauthType(r)
	if err != nil {
		log.Printf("WebAuthNController: Error getting WebAuthn type: %s", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	// Ensure User exists
	userManager := userManager.New(m.db, m.config)
	user, err := userManager.Get(email)
	if err != nil {
		log.Printf("WebAuthNController: Error fetching user %s: %s", email, err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	sessionData, err := m.getWebauthNCookie("webauthn_login", w, r)
	if err != nil {
		log.Printf("WebAuthNController: Error fetching WebAuthn session cookie for %s: %s", user.Email, err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	webAuthNUser := models.NewWebAuthNUser(user.ID, user.Email, user.Email)
	availableCredentials, err := m.getAvailableCredentials(*user, webAuthnType, true)
	if err != nil {
		log.Printf("WebAuthNController: Error fetching available webauthn credentials for %s: %s", user.Email, err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	for _, credential := range availableCredentials {
		webAuthNUser.AddCredential(credential)
	}

	webAuthn, err := webauthn.New(&webauthn.Config{
		RPDisplayName: m.config.MFAIssuer,
		RPID:          m.config.RedirectDomain.Hostname(),
		RPOrigin:      fmt.Sprintf("%s://%s", m.config.RedirectDomain.Scheme, m.config.RedirectDomain.Hostname()),
	})

	// TODO: Check 'credential.Authenticator.CloneWarning' when not using touchid
	successLoginCredential, err := webAuthn.FinishLogin(webAuthNUser, *sessionData, r)
	if err != nil {
		log.Printf("WebAuthNController: Error finishing WebAuthn login for %s: %s", user.Email, err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Determine which UserMFA was used
	var usedMFAID *uuid.UUID
	for mfaID, cred := range availableCredentials {
		if bytes.Compare(cred.ID, successLoginCredential.ID) == 0 {
			usedMFAID = &mfaID
		}
	}
	if usedMFAID == nil {
		log.Printf("WebAuthNController: Error getting webauthn credential ID for %s: %s", user.Email, err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	sourceIP := utils.New(m.config).GetClientIP(r)
	if err := userManager.CreateVpnSession(*usedMFAID, user, sourceIP); err != nil {
		log.Printf("WebAuthNController: Error creating VPN session for %s : %s", user.Email, err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	log.Printf("WebAuthNController: User %s created VPN session from %s", user.Email, sourceIP)

	if userManager.CreateSession(user.Email, true, w) != nil {
		log.Printf("GoogleController: Error creating user MFA session for %s: %s", user.Email, err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	utils.JSONResponse(w, "Login Success", http.StatusOK)
}

func (m *WebAuthNController) getAvailableCredentials(user models.User, webAuthnType string, onlyValidated bool) (map[uuid.UUID]webauthn.Credential, error) {
	dp := dataProtector.NewDataProtector(m.config)
	availableCredentials := make(map[uuid.UUID]webauthn.Credential)
	if user.MFAs == nil {
		return nil, errors.New("User doesn't have Webauthn credentials")
	}
	for _, item := range user.MFAs {
		if item.Type == webAuthnType && item.Validated == onlyValidated {
			if item.Data == "" { // it's not a credential
				continue
			}
			decryptedData, err := dp.Decrypt(item.Data)
			if err != nil {
				return nil, fmt.Errorf("%s Data could not be decrypted: %s", webAuthnType, err.Error())
			}
			var credential webauthn.Credential
			if err := json.Unmarshal([]byte(decryptedData), &credential); err != nil {
				return nil, fmt.Errorf("%s Data could not be deserialized to credential: %s", webAuthnType, err.Error())
			}
			availableCredentials[item.ID] = credential
		}
	}

	return availableCredentials, nil
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

func getWebauthType(r *http.Request) (string, error) {
	webAuthnType := "webauthn"
	webAuthnTypeParam, ok := r.URL.Query()["type"]
	if !ok {
		return "", errors.New("'webauthn' URL parameter missing")
	}
	if len(webAuthnTypeParam[0]) >= 1 && webAuthnTypeParam[0] == "touchid" {
		webAuthnType = "touchid"
	}
	return webAuthnType, nil
}
