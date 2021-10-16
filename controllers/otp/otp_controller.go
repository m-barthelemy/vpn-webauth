package controllers

import (
	"bytes"
	"encoding/json"
	"image/png"
	"net/http"
	"strconv"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/m-barthelemy/vpn-webauth/models"
	services "github.com/m-barthelemy/vpn-webauth/services"

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

type OneTimePassword struct {
	Code string
}

// GenerateQrCode creates an OTP MFA provider for the user and the OTP secret.
// If successful, returns the QRCode image
func (u *OTPController) GenerateQrCode(w http.ResponseWriter, r *http.Request) {
	var email = r.Context().Value("identity").(string)
	sourceIP := utils.New(u.config).GetClientIP(r)
	log := utils.ConfigureLogger(email, sourceIP)
	var sessionHasMFA = r.Context().Value("hasMfa").(bool)

	userManager := services.NewUserManager(u.db, u.config)
	user, err := userManager.Get(email)
	if err != nil {
		log.Errorf("OTPController: Error fetching user: %s", err.Error())
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
		if user.MFAs[i].Type == "otp" && user.MFAs[i].ExpiresAt.After(time.Now()) {
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
			Issuer:      u.config.Issuer,
			AccountName: email,
		})
		if err != nil {
			log.Errorf("OTPController: Error generating user TOTP secret: %s", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}

		otpMFA, err = userManager.AddMFA(user, "otp", otp.Secret(), r.Header.Get("User-Agent"))
		if err != nil {
			log.Errorf("OTPController: Error creating user TOTP MFA provider: %s", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
	}

	dp := services.NewDataProtector(u.config)
	otpSecret, err := dp.Decrypt(otpMFA.Data)
	if err != nil {
		log.Errorf("OTPController: Error decrypting user TOTP secret: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}

	otpSecretBytes := []byte(otpSecret)
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      u.config.Issuer,
		AccountName: email,
		Secret:      otpSecretBytes,
	})
	if err != nil {
		log.Errorf("OTPController: Error initializing TOTP secret: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	var qrBuf bytes.Buffer
	img, err := key.Image(512, 512)
	if err != nil {
		log.Errorf("OTPController: Error generating QR code image: %s", err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	pngErr := png.Encode(&qrBuf, img)
	if pngErr != nil {
		log.Errorf("OTPController: Error generating QR code image PNG: %s", err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Content-Length", strconv.Itoa(len(qrBuf.Bytes())))
	// For security reasons it's best to disable any storage aching of the QR code
	w.Header().Set("Cache-Control", "no-store")
	if _, err := w.Write(qrBuf.Bytes()); err != nil {
		log.Errorf("OTPController: Unable to generate QRcode: %s", err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

func (u *OTPController) ValidateOTP(w http.ResponseWriter, r *http.Request) {
	var email = r.Context().Value("identity").(string)
	sourceIP := utils.New(u.config).GetClientIP(r)
	log := utils.ConfigureLogger(email, sourceIP)

	userManager := services.NewUserManager(u.db, u.config)
	user, err := userManager.Get(email)
	if err != nil {
		log.Errorf("OTPController: Error fetching user: %s", err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	var otpMFA *models.UserMFA
	for i := range user.MFAs {
		// OTP provider must be fully validated if singing in, or expiry date must be valid if mfa is pending validation
		if user.MFAs[i].Type == "otp" && (user.MFAs[i].IsValid() || user.MFAs[i].ExpiresAt.After(time.Now())) {
			otpMFA = &user.MFAs[i]
			break
		}
	}
	if otpMFA == nil {
		log.Error("OTPController: User has no TOTP MFA provider")
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	dp := services.NewDataProtector(u.config)
	otpSecret, err := dp.Decrypt(otpMFA.Data)
	if err != nil {
		log.Errorf("OTPController: Error fetching user TOTP secret: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	otpSecretBytes := []byte(otpSecret)
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      u.config.Issuer,
		AccountName: email,
		Secret:      otpSecretBytes,
	})
	if err != nil {
		log.Errorf("OTPController: error initializing TOTP secret: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	var codeToValidate OneTimePassword
	err = json.NewDecoder(r.Body).Decode(&codeToValidate)
	if err != nil {
		log.Errorf("OTPController: unable to unmarshal OTP code: %s", err.Error())
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	if !totp.Validate(codeToValidate.Code, key.Secret()) {
		log.Error("OTPController: invalid OTP code")
		http.Error(w, "Invalid code", http.StatusBadRequest)
		return
	}

	if !otpMFA.Validated {
		if _, err := userManager.ValidateMFA(otpMFA, ""); err != nil {
			log.Errorf("OTPController: error updating OTP provider: %s", err.Error())
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		log.Info("OTPController: Successfully validated OTP provider")
	}

	if err := userManager.CreateVpnSession(user, sourceIP); err != nil {
		log.Errorf("OTPController: error creating VPN session: %s", err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	log.Info("OTPController: user created VPN session")

	if userManager.CreateSession(user, true, w) != nil {
		log.Errorf("WebAuthNController: error creating user MFA session: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}
