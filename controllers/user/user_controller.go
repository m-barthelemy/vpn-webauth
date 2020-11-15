package controllers

import (
	"bytes"
	"image/png"
	"log"
	"net/http"
	"strconv"

	"github.com/pquerna/otp/totp"

	"github.com/m-barthelemy/vpn-webauth/models"
	"github.com/m-barthelemy/vpn-webauth/services"
	userManager "github.com/m-barthelemy/vpn-webauth/services"
	"github.com/m-barthelemy/vpn-webauth/utils"

	"gorm.io/gorm"
)

type UserController struct {
	db     *gorm.DB
	config *models.Config
}

// New creates an instance of the controller and sets its DB handle
func New(db *gorm.DB, config *models.Config) *UserController {
	return &UserController{db: db, config: config}
}

func (u *UserController) GenerateQrCode(w http.ResponseWriter, r *http.Request) {
	var email = r.Context().Value("identity").(string)
	if email == "" {
		http.Redirect(w, r, "/choose2fa", http.StatusTemporaryRedirect)
		return
	}
	userManager := userManager.New(u.db, u.config)
	user, err := userManager.Get(email)
	if err != nil {
		log.Printf("UserController: Error fetching user: %s", err.Error)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	// Exposing the TOTP secret, once the user has successfully validated their OTP setup,
	// would be a security vulnerability.
	if user.TotpValidated {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	dp := services.NewDataProtector(u.config)
	otpSecret, err := dp.Decrypt(user.TotpSecret)
	if err != nil {
		log.Printf("UserController: Error fetching user TOTP secret: %s", err)
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
		log.Printf("UserController: Error initializing TOTP secret: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	var qrBuf bytes.Buffer
	img, err := key.Image(512, 512)
	if err != nil {
		log.Printf("UserController: Error generating QR code image: %s", err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	err = png.Encode(&qrBuf, img)
	if err != nil {
		log.Printf("UserController: Error generating QR code image PNG: %s", err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Content-Length", strconv.Itoa(len(qrBuf.Bytes())))
	// For security reasons it's best to disable any storage/caching of the QR code
	w.Header().Set("Cache-Control", "no-store")
	if _, err := w.Write(qrBuf.Bytes()); err != nil {
		log.Printf("UserController: Unable to generate QRcode: %s", err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

func (u *UserController) ValidateOTP(w http.ResponseWriter, r *http.Request) {
	var email = r.Context().Value("identity").(string)
	userManager := userManager.New(u.db, u.config)
	user, err := userManager.Get(email)
	if err != nil {
		log.Printf("UserController: Error fetching user: %s", err.Error)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	dp := services.NewDataProtector(u.config)
	otpSecret, err := dp.Decrypt(user.TotpSecret)
	if err != nil {
		log.Printf("UserController: Error fetching user TOTP secret: %s", err)
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
		log.Printf("UserController: Error initializing TOTP secret: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if err != nil {
		log.Printf("UserController: Error loading user OTP for %s : %s", email, err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if !totp.Validate(r.FormValue("otp"), key.Secret()) {
		log.Printf("UserController: OTP code validation failed for %s", email)
		http.Redirect(w, r, "/enter2fa?error", http.StatusTemporaryRedirect)
		return
	} else {
		if !user.TotpValidated {
			user.TotpValidated = true
			u.db.Save(&user)
		}

		sourceIP := utils.New(u.config).GetClientIP(r)
		if err := userManager.CreateVpnSession(user, sourceIP); err != nil {
			log.Printf("UserController: Error creating VPN session for %s : %s", email, err.Error())
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		log.Printf("UserController: User %s created VPN session from %s", email, sourceIP)
		http.Redirect(w, r, "/success", http.StatusTemporaryRedirect)
	}
}
