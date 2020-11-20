package routes

import (
	"log"
	"net/http"
	"os"

	"github.com/gorilla/handlers"
	googlecontroller "github.com/m-barthelemy/vpn-webauth/controllers/google"
	usercontroller "github.com/m-barthelemy/vpn-webauth/controllers/user"
	vpnController "github.com/m-barthelemy/vpn-webauth/controllers/vpn"
	webauthNController "github.com/m-barthelemy/vpn-webauth/controllers/webauthn"
	"github.com/m-barthelemy/vpn-webauth/models"
	"github.com/markbates/pkger"
	"gorm.io/gorm"
)

func New(config *models.Config, db *gorm.DB) http.Handler {
	tokenSigningKey := []byte(config.SigningKey)

	// Prepare embedded templates
	dir := pkger.Include("/templates")
	tplHandler := NewTemplateHandler(config)
	err := tplHandler.CompileTemplates(dir)
	if err != nil {
		log.Fatalf("Error compiling templates: ", err.Error())
	}
	mux := http.NewServeMux()

	mux.HandleFunc("/assets/", tplHandler.HandleStaticAsset)
	mux.HandleFunc("/fonts/", tplHandler.HandleStaticAsset)
	mux.HandleFunc("/font/", tplHandler.HandleStaticAsset)

	mux.HandleFunc("/", tplHandler.HandleEmbeddedTemplate)

	googleC := googlecontroller.New(db, config)
	mux.HandleFunc("/auth/google/login", googleC.OauthGoogleLogin)
	mux.Handle("/auth/google/callback",
		handlers.LoggingHandler(
			os.Stdout,
			http.HandlerFunc(googleC.OauthGoogleCallback),
		),
	)

	usersC := usercontroller.New(db, config)
	// This creates the OTP provider (and secret) for the User
	mux.Handle("/auth/otp/qrcode",
		handlers.LoggingHandler(
			os.Stdout,
			http.HandlerFunc(sessionMiddleware(tokenSigningKey, usersC.GenerateQrCode)),
		),
	)
	mux.Handle("/auth/otp/validateotp",
		handlers.LoggingHandler(
			os.Stdout,
			http.HandlerFunc(sessionMiddleware(tokenSigningKey, usersC.ValidateOTP)),
		),
	)

	webauthnC := webauthNController.New(db, config)
	mux.Handle("/auth/webauthn/beginregister",
		handlers.LoggingHandler(
			os.Stdout,
			http.HandlerFunc(sessionMiddleware(tokenSigningKey, webauthnC.BeginRegister)),
		),
	)
	mux.Handle("/auth/webauthn/finishregister",
		handlers.LoggingHandler(
			os.Stdout,
			http.HandlerFunc(sessionMiddleware(tokenSigningKey, webauthnC.FinishRegister)),
		),
	)
	mux.Handle("/auth/webauthn/beginlogin",
		handlers.LoggingHandler(
			os.Stdout,
			http.HandlerFunc(sessionMiddleware(tokenSigningKey, webauthnC.BeginLogin)),
		),
	)
	mux.Handle("/auth/webauthn/finishlogin",
		handlers.LoggingHandler(
			os.Stdout,
			http.HandlerFunc(sessionMiddleware(tokenSigningKey, webauthnC.FinishLogin)),
		),
	)

	vpnC := vpnController.New(db, config)
	mux.Handle("/vpn/check",
		handlers.LoggingHandler(
			os.Stdout,
			http.HandlerFunc(vpnC.CheckSession),
		),
	)

	return mux
}
