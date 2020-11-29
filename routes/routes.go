package routes

import (
	"log"
	"net/http"
	"os"

	"github.com/asaskevich/EventBus"
	"github.com/gorilla/handlers"
	googlecontroller "github.com/m-barthelemy/vpn-webauth/controllers/google"
	otcController "github.com/m-barthelemy/vpn-webauth/controllers/otc"
	otpController "github.com/m-barthelemy/vpn-webauth/controllers/otp"
	userController "github.com/m-barthelemy/vpn-webauth/controllers/user"
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
	sessHandler := NewSessionHandler(config)
	err := tplHandler.CompileTemplates(dir)
	if err != nil {
		log.Fatalf("Error compiling templates: %s", err.Error())
	}
	mux := http.NewServeMux()

	mux.HandleFunc("/assets/", tplHandler.HandleStaticAsset)
	mux.HandleFunc("/fonts/", tplHandler.HandleStaticAsset)
	mux.HandleFunc("/font/", tplHandler.HandleStaticAsset)
	mux.HandleFunc("/favicon.ico", tplHandler.HandleStaticAsset) // Avoid it being treated like a template throwing errors in logs
	mux.HandleFunc("/service.js", tplHandler.HandleStaticAsset)  // Needs to be served from the root due to Service Worker scope

	mux.HandleFunc("/", tplHandler.HandleEmbeddedTemplate)

	googleC := googlecontroller.New(db, config)
	mux.Handle("/auth/google/login",
		handlers.LoggingHandler(
			os.Stdout,
			http.HandlerFunc(sessHandler.SessionMiddleware(tokenSigningKey, googleC.OauthGoogleLogin, true)),
		),
	)
	mux.Handle("/auth/google/callback",
		handlers.LoggingHandler(
			os.Stdout,
			http.HandlerFunc(googleC.OauthGoogleCallback),
		),
	)

	mux.Handle("/auth/getmfachoice",
		handlers.LoggingHandler(
			os.Stdout,
			http.HandlerFunc(sessHandler.SessionMiddleware(tokenSigningKey, googleC.GetMFaChoosePage, true)),
		),
	)

	otpC := otpController.New(db, config)
	// This creates the OTP provider (and secret) for the User
	mux.Handle("/auth/otp/qrcode",
		handlers.LoggingHandler(
			os.Stdout,
			http.HandlerFunc(sessHandler.SessionMiddleware(tokenSigningKey, otpC.GenerateQrCode, false)),
		),
	)
	mux.Handle("/auth/otp/validate",
		handlers.LoggingHandler(
			os.Stdout,
			http.HandlerFunc(sessHandler.SessionMiddleware(tokenSigningKey, otpC.ValidateOTP, false)),
		),
	)

	webauthnC := webauthNController.New(db, config)
	mux.Handle("/auth/webauthn/beginregister",
		handlers.LoggingHandler(
			os.Stdout,
			http.HandlerFunc(sessHandler.SessionMiddleware(tokenSigningKey, webauthnC.BeginRegister, false)),
		),
	)
	mux.Handle("/auth/webauthn/finishregister",
		handlers.LoggingHandler(
			os.Stdout,
			http.HandlerFunc(sessHandler.SessionMiddleware(tokenSigningKey, webauthnC.FinishRegister, false)),
		),
	)
	mux.Handle("/auth/webauthn/beginlogin",
		handlers.LoggingHandler(
			os.Stdout,
			http.HandlerFunc(sessHandler.SessionMiddleware(tokenSigningKey, webauthnC.BeginLogin, false)),
		),
	)
	mux.Handle("/auth/webauthn/finishlogin",
		handlers.LoggingHandler(
			os.Stdout,
			http.HandlerFunc(sessHandler.SessionMiddleware(tokenSigningKey, webauthnC.FinishLogin, false)),
		),
	)

	otcC := otcController.New(db, config)
	mux.Handle("/auth/code/generate",
		handlers.LoggingHandler(
			os.Stdout,
			http.HandlerFunc(sessHandler.SessionMiddleware(tokenSigningKey, otcC.GenerateSingleUseCode, false)),
		),
	)
	mux.Handle("/auth/code/validate",
		handlers.LoggingHandler(
			os.Stdout,
			http.HandlerFunc(sessHandler.SessionMiddleware(tokenSigningKey, otcC.ValidateSingleUseCode, false)),
		),
	)

	// Shared event bus between the VPN and the User controllers.
	// This allows RefreshAuth to signal to CheckSession that a User
	// still has a valid web session and check if its source IP matches
	// that of the VPN connection attempt.
	// This allows to shorten VPN sessions validity, since we have a
	// way, using browser push notifications, to check that the user
	// is still "online" and still has a strong web authentication
	// without requiring the user to open the web app and sign in again.
	bus := EventBus.New()

	vpnC := vpnController.New(db, config, &bus)
	mux.Handle("/vpn/check",
		handlers.LoggingHandler(
			os.Stdout,
			http.HandlerFunc(vpnC.CheckSession),
		),
	)

	userC := userController.New(db, config, &bus)
	// Creates a browser push subscription for the user
	mux.Handle("/user/push_subscriptions/begin",
		handlers.LoggingHandler(
			os.Stdout,
			http.HandlerFunc(sessHandler.SessionMiddleware(tokenSigningKey, userC.GetPushSubscriptionKey, false)),
		),
	)
	mux.Handle("/user/push_subscriptions/finish",
		handlers.LoggingHandler(
			os.Stdout,
			http.HandlerFunc(sessHandler.SessionMiddleware(tokenSigningKey, userC.RegisterPushSubscription, false)),
		),
	)

	mux.Handle("/user/auth/refresh",
		handlers.LoggingHandler(
			os.Stdout,
			http.HandlerFunc(sessHandler.SessionMiddleware(tokenSigningKey, userC.RefreshAuth, true)),
		),
	)

	return mux
}
