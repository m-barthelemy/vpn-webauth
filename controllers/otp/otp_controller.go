package controllers

import (
	"bytes"
	"image/png"
	"log"
	"net/http"
	"strconv"

	"github.com/pquerna/otp/totp"

	"github.com/m-barthelemy/vpn-webauth/models"
	dataProtector "github.com/m-barthelemy/vpn-webauth/services"
	userManager "github.com/m-barthelemy/vpn-webauth/services"

	"github.com/m-barthelemy/vpn-webauth/utils"

	"gorm.io/gorm"
)

type OTPController struct {
	db     *gorm.DB
	config *models.Config
}

// New creates an instance of the controller and sets its DB handle
func New(db *gorm.DB, config *models.Config) *OTPController {
	return &OTPController{db: db, config: config}
}

// GenerateQrCode creates an OTP MFA provider for the user and the OTP secret.
// If successful, returns the QRCode image
func (u *OTPController) GenerateQrCode(w http.ResponseWriter, r *http.Request) {
	var email = r.Context().Value("identity").(string)
	var sessionHasMFA = r.Context().Value("hasMfa").(bool)

	userManager := userManager.New(u.db, u.config)
	user, err := userManager.Get(email)
	if err != nil {
		log.Printf("OTPController: Error fetching user %s: %s", email, err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Deny if the user has enabled MFA but hasn't logged in fully
	if user.HasMFA() && !sessionHasMFA {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	var otpMFA *models.UserMFA
	for i := range user.MFAs {
		if user.MFAs[i].Type == "otp" {
			otpMFA = &user.MFAs[i]
			break
		}
	}

	// Exposing the TOTP secret, once the user has successfully validated their OTP setup,
	// would be a security vulnerability.
	if otpMFA != nil && otpMFA.Validated {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	if otpMFA == nil {
		otp, err := totp.Generate(totp.GenerateOpts{
			Issuer:      u.config.MFAIssuer,
			AccountName: email,
		})
		if err != nil {
			log.Printf("OTPController: Error generating user TOTP secret for %s: %s", user.Email, err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}

		otpMFA, err = userManager.AddMFA(user, "otp", otp.Secret(), r.Header.Get("User-Agent"))
		if err != nil {
			log.Printf("OTPController: Error creating user TOTP MFA provider for %s: %s", user.Email, err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
	}

	dp := dataProtector.NewDataProtector(u.config)
	otpSecret, err := dp.Decrypt(otpMFA.Data)
	if err != nil {
		log.Printf("OTPController: Error decrypting user TOTP secret for %s: %s", user.Email, err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}

	otpSecretBytes := []byte(otpSecret)
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      u.config.MFAIssuer,
		AccountName: email,
		Secret:      otpSecretBytes,
	})
	if err != nil {
		log.Printf("OTPController: Error initializing TOTP secret: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	var qrBuf bytes.Buffer
	img, err := key.Image(512, 512)
	if err != nil {
		log.Printf("OTPController: Error generating QR code image: %s", err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	pngErr := png.Encode(&qrBuf, img)
	if pngErr != nil {
		log.Printf("OTPController: Error generating QR code image PNG: %s", err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Content-Length", strconv.Itoa(len(qrBuf.Bytes())))
	// For security reasons it's best to disable any storage aching of the QR code
	w.Header().Set("Cache-Control", "no-store")
	if _, err := w.Write(qrBuf.Bytes()); err != nil {
		log.Printf("OTPController: Unable to generate QRcode: %s", err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

func (u *OTPController) ValidateOTP(w http.ResponseWriter, r *http.Request) {
	var email = r.Context().Value("identity").(string)
	userManager := userManager.New(u.db, u.config)
	user, err := userManager.Get(email)
	if err != nil {
		log.Printf("OTPController: Error fetching user: %s", err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	var otpMFA *models.UserMFA
	for i := range user.MFAs {
		if user.MFAs[i].Type == "otp" {
			otpMFA = &user.MFAs[i]
			break
		}
	}
	if otpMFA == nil {
		log.Printf("OTPController: User %s has no TOTP MFA provider", user.Email)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	dp := dataProtector.NewDataProtector(u.config)
	otpSecret, err := dp.Decrypt(otpMFA.Data)
	if err != nil {
		log.Printf("OTPController: Error fetching user TOTP secret: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	otpSecretBytes := []byte(otpSecret)
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      u.config.MFAIssuer,
		AccountName: email,
		Secret:      otpSecretBytes,
	})
	if err != nil {
		log.Printf("OTPController: Error initializing TOTP secret: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if err != nil {
		log.Printf("OTPController: Error loading user OTP for %s : %s", email, err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	if !totp.Validate(r.FormValue("otp"), key.Secret()) {
		log.Printf("OTPController: Error validating OTP code validation for %s", email)
		http.Redirect(w, r, "/enter2fa?error", http.StatusTemporaryRedirect)
		return
	}

	if !otpMFA.Validated {
		if _, err := userManager.ValidateMFA(otpMFA, ""); err != nil {
			log.Printf("OTPController: Error updating OTP provider for %s : %s", user.Email, err.Error())
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		log.Printf("OTPController: Successfully validated OTP provider for %s", user.Email)
	}

	sourceIP := utils.New(u.config).GetClientIP(r)
	if err := userManager.CreateVpnSession(otpMFA.ID, user, sourceIP); err != nil {
		log.Printf("OTPController: Error creating VPN session for %s : %s", email, err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	log.Printf("OTPController: User %s created VPN session from %s", email, sourceIP)

	if userManager.CreateSession(user.Email, true, w) != nil {
		log.Printf("WebAuthNController: Error creating user MFA session for %s: %s", user.Email, err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/success", http.StatusTemporaryRedirect)
}
