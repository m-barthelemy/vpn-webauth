package controllers

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"time"

	"github.com/m-barthelemy/vpn-webauth/models"
	services "github.com/m-barthelemy/vpn-webauth/services"
	"github.com/m-barthelemy/vpn-webauth/utils"
	"gorm.io/gorm"
)

type OneTimeCodeController struct {
	db     *gorm.DB
	config *models.Config
}

// New creates an instance of the singleCodeController controller and sets its DB handle
func New(db *gorm.DB, config *models.Config) *OneTimeCodeController {
	return &OneTimeCodeController{db: db, config: config}
}

type OneTimeCode struct {
	Code           string
	RemainingTries int
	ExpiresAt      time.Time
}

// GenerateSingleUseCode Create a single-usage 6 digits temporary code
// Useful when a user only has Webauthn MFA, which is specific to a device and browser.
// Without alternative MFA such as OTP, they would use this temporary code feature
//  to be allowed to register webauthn on another device or browser.
func (c *OneTimeCodeController) GenerateSingleUseCode(w http.ResponseWriter, r *http.Request) {
	var email = r.Context().Value("identity").(string)
	var sessionHasMFA = r.Context().Value("hasMfa").(bool)

	// Deny if the user has enabled MFA but hasn't logged in fully
	// TODO: in the future we may want to force a re-auth before emitting a single use token
	// given that it grants full session "powers" if validated
	if c.config.EnforceMFA && !sessionHasMFA {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	var user *models.User
	userManager := services.NewUserManager(c.db, c.config)
	user, err := userManager.Get(email)
	if err != nil {
		log.Printf("SingleUseCodeController: Error fetching user %s: %s", email, err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Deny if there's already a valid single-use code
	for _, mfa := range user.MFAs {
		if mfa.Type == "code" && mfa.ExpiresAt.After(time.Now()) {
			log.Printf("SingleUseCodeController: Cannot generate single use code for user %s: found other pending unique code", user.Email)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}

	randomCode, err := rand.Int(rand.Reader, big.NewInt(999999))
	if err != nil {
		log.Printf("SingleUseCodeController: Error generating random numeric code for user %s: %s", user.Email, err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	code := OneTimeCode{
		Code:           fmt.Sprintf("%06d", randomCode.Uint64()),
		RemainingTries: 3,
	}

	otcMFA, err := userManager.AddMFA(user, "code", "", r.Header.Get("User-Agent"))
	if err != nil {
		log.Printf("SingleUseCodeController: Error saving OTC for user %s: %s", user.Email, err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	serialized, _ := json.Marshal(code)
	otcMFA.Data = string(serialized[:])
	otcMFA.Validated = true
	if _, err := userManager.UpdateMFA(*otcMFA); err != nil {
		log.Printf("SingleUseCodeController: Error updating OTC for user %s: %s", user.Email, err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	code.ExpiresAt = otcMFA.ExpiresAt
	utils.JSONResponse(w, code, http.StatusOK)
}

func (c *OneTimeCodeController) ValidateSingleUseCode(w http.ResponseWriter, r *http.Request) {
	var email = r.Context().Value("identity").(string)
	var sessionHasMFA = r.Context().Value("hasMfa").(bool)

	var user *models.User
	userManager := services.NewUserManager(c.db, c.config)
	user, err := userManager.Get(email)
	if err != nil {
		log.Printf("SingleUseCodeController: Error fetching user %s: %s", email, err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Deny if the user has MFA and logged in fully: it means that
	// they don't need the single-usage code and are probably validating from the
	// same device that generated it
	if user.HasMFA() && sessionHasMFA {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	// Get active single-use code `UserMFA`
	var codeMFA *models.UserMFA
	for i, mfa := range user.MFAs {
		if mfa.Type == "code" && mfa.IsValid() {
			codeMFA = &user.MFAs[i]
			break
		}
	}
	if codeMFA == nil {
		log.Printf("SingleUseCodeController: User %s single-use code doesn't exist", email)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	dp := services.NewDataProtector(c.config)
	decryptedData, err := dp.Decrypt(codeMFA.Data)
	if err != nil {
		log.Printf("SingleUseCodeController: Unable to decrypt %s single-use code: %s", user.Email, err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	var singleUseCode OneTimeCode
	if err := json.Unmarshal([]byte(decryptedData), &singleUseCode); err != nil {
		log.Printf("SingleUseCodeController: Data could not be deserialized to SingleUseCode for %s single-use code: %s", user.Email, err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	var codeToValidate OneTimeCode
	err = json.NewDecoder(r.Body).Decode(&codeToValidate)
	if err != nil {
		log.Printf("SingleUseCodeController: Unable to unmarshal %s single-use code: %s", user.Email, err.Error())
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	if singleUseCode.RemainingTries == 0 {
		log.Printf("SingleUseCodeController: Maximum number of attempts reached for %s single-use code", user.Email)
		http.Error(w, "Too many failed attempts", http.StatusInternalServerError)
		return
	}

	if codeToValidate.Code != singleUseCode.Code {
		singleUseCode.RemainingTries = singleUseCode.RemainingTries - 1
		newData, _ := json.Marshal(singleUseCode)
		codeMFA.Data = string(newData[:])
		if _, err = userManager.UpdateMFA(*codeMFA); err != nil {
			log.Printf("SingleUseCodeController: Unable to update %s single-use code MFA: %s", user.Email, err.Error())
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		http.Error(w, "Invalid code", http.StatusBadRequest)
		return
	}

	// Success, disable the UserMFA and log in
	codeMFA.Data = "disabled"
	codeMFA.Validated = false
	codeMFA.ExpiresAt = time.Time{}
	if _, err := userManager.UpdateMFA(*codeMFA); err != nil {
		log.Printf("SingleUseCodeController: Unable to deactivate %s single-use code MFA: %s", user.Email, err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Create fully MFA-authenticated session
	if userManager.CreateSession(user, true, w) != nil {
		log.Printf("GoogleController: Error creating user MFA session for %s: %s", user.Email, err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	utils.JSONResponse(w, "Login Success", http.StatusOK)
}
