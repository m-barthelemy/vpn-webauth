package routes

import (
	"log"
	"net/http"
	"os"

	"github.com/asaskevich/EventBus"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	oauthcontroller "github.com/m-barthelemy/vpn-webauth/controllers/oauth2"
	otcController "github.com/m-barthelemy/vpn-webauth/controllers/otc"
	otpController "github.com/m-barthelemy/vpn-webauth/controllers/otp"
	sseController "github.com/m-barthelemy/vpn-webauth/controllers/sse"
	userController "github.com/m-barthelemy/vpn-webauth/controllers/user"
	vpnController "github.com/m-barthelemy/vpn-webauth/controllers/vpn"
	webauthNController "github.com/m-barthelemy/vpn-webauth/controllers/webauthn"
	"github.com/m-barthelemy/vpn-webauth/models"
	"github.com/m-barthelemy/vpn-webauth/services"
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
	//mux := http.NewServeMux()
	mux := mux.NewRouter()
	mux.PathPrefix("/assets/").HandlerFunc(tplHandler.HandleStaticAsset)
	mux.PathPrefix("/fonts/").HandlerFunc(tplHandler.HandleStaticAsset)
	mux.PathPrefix("/font/").HandlerFunc(tplHandler.HandleStaticAsset)
	mux.HandleFunc("/favicon.ico", tplHandler.HandleStaticAsset) // Avoid it being treated like a template throwing errors in logs
	mux.HandleFunc("/service.js", tplHandler.HandleStaticAsset)  // Needs to be served from the root due to Service Worker scope

	oauth2C := oauthcontroller.New(db, config)
	mux.Handle("/auth/{provider}/login",
		handlers.LoggingHandler(
			os.Stdout,
			http.HandlerFunc(sessHandler.SessionMiddleware(tokenSigningKey, oauth2C.OAuth2BeginLogin, true)),
		),
	)
	mux.Handle("/auth/{provider}/callback",
		handlers.LoggingHandler(
			os.Stdout,
			http.HandlerFunc(oauth2C.OAuth2Callback),
		),
	)

	mux.Handle("/auth/getmfachoice",
		handlers.LoggingHandler(
			os.Stdout,
			http.HandlerFunc(sessHandler.SessionMiddleware(tokenSigningKey, oauth2C.GetMFaChoosePage, true)),
		),
	).Methods("GET")

	otpC := otpController.New(db, config)
	// This creates the OTP provider (and secret) for the User
	mux.Handle("/auth/otp/qrcode",
		handlers.LoggingHandler(
			os.Stdout,
			http.HandlerFunc(sessHandler.SessionMiddleware(tokenSigningKey, otpC.GenerateQrCode, false)),
		),
	).Methods("GET")
	mux.Handle("/auth/otp/validate",
		handlers.LoggingHandler(
			os.Stdout,
			http.HandlerFunc(sessHandler.SessionMiddleware(tokenSigningKey, otpC.ValidateOTP, false)),
		),
	).Methods("POST")

	webauthnC := webauthNController.New(db, config)
	mux.Handle("/auth/webauthn/beginregister",
		handlers.LoggingHandler(
			os.Stdout,
			http.HandlerFunc(sessHandler.SessionMiddleware(tokenSigningKey, webauthnC.BeginRegister, false)),
		),
	).Methods("POST")
	mux.Handle("/auth/webauthn/finishregister",
		handlers.LoggingHandler(
			os.Stdout,
			http.HandlerFunc(sessHandler.SessionMiddleware(tokenSigningKey, webauthnC.FinishRegister, false)),
		),
	).Methods("POST")
	mux.Handle("/auth/webauthn/beginlogin",
		handlers.LoggingHandler(
			os.Stdout,
			http.HandlerFunc(sessHandler.SessionMiddleware(tokenSigningKey, webauthnC.BeginLogin, false)),
		),
	).Methods("POST")
	mux.Handle("/auth/webauthn/finishlogin",
		handlers.LoggingHandler(
			os.Stdout,
			http.HandlerFunc(sessHandler.SessionMiddleware(tokenSigningKey, webauthnC.FinishLogin, false)),
		),
	).Methods("POST")

	otcC := otcController.New(db, config)
	mux.Handle("/auth/otc/generate",
		handlers.LoggingHandler(
			os.Stdout,
			http.HandlerFunc(sessHandler.SessionMiddleware(tokenSigningKey, otcC.GenerateSingleUseCode, false)),
		),
	).Methods("POST")
	mux.Handle("/auth/otc/validate",
		handlers.LoggingHandler(
			os.Stdout,
			http.HandlerFunc(sessHandler.SessionMiddleware(tokenSigningKey, otcC.ValidateSingleUseCode, false)),
		),
	).Methods("POST")

	// Shared event bus between the VPN and the User controllers.
	// This allows RefreshAuth to signal to CheckSession that a User
	// still has a valid web session and check if its source IP matches
	// that of the VPN connection attempt.
	// This allows to shorten VPN sessions validity, since we have a
	// way, using browser push notifications, to check that the user
	// is still "online" and still has a strong web authentication
	// without requiring the user to open the web app and sign in again.
	bus := EventBus.New()
	notificationsManager := services.NewNotificationsManager(db, config, &bus)

	vpnC := vpnController.New(db, config, notificationsManager)
	mux.Handle("/vpn/check",
		handlers.LoggingHandler(
			os.Stdout,
			http.HandlerFunc(vpnC.CheckSession),
		),
	).Methods("POST")

	userC := userController.New(db, config, notificationsManager)
	// Creates a browser push subscription for the user
	mux.Handle("/user/push_subscriptions/begin",
		handlers.LoggingHandler(
			os.Stdout,
			http.HandlerFunc(sessHandler.SessionMiddleware(tokenSigningKey, userC.GetPushSubscriptionKey, false)),
		),
	).Methods("POST")
	mux.Handle("/user/push_subscriptions/finish",
		handlers.LoggingHandler(
			os.Stdout,
			http.HandlerFunc(sessHandler.SessionMiddleware(tokenSigningKey, userC.RegisterPushSubscription, false)),
		),
	).Methods("POST")

	mux.Handle("/user/auth/refresh",
		handlers.LoggingHandler(
			os.Stdout,
			http.HandlerFunc(sessHandler.SessionMiddleware(tokenSigningKey, userC.RefreshAuth, true)),
		),
	).Methods("POST")

	mux.Handle("/user/info",
		handlers.LoggingHandler(
			os.Stdout,
			http.HandlerFunc(sessHandler.SessionMiddleware(tokenSigningKey, userC.GetSessionInfo, true)),
		),
	).Methods("GET")

	mux.Handle("/user/logout",
		handlers.LoggingHandler(
			os.Stdout,
			http.HandlerFunc(sessHandler.SessionMiddleware(tokenSigningKey, userC.Logout, false)),
		),
	)

	// Server-Side Events fallback if browser doesn't support push notifications
	sseC := sseController.New(db, config, &bus)
	sseC.Start()
	mux.Handle("/events",
		handlers.LoggingHandler(
			os.Stdout,
			http.HandlerFunc(sessHandler.IdentificationMiddleware(tokenSigningKey, sseC.HandleEvents)),
		),
	)

	mux.PathPrefix("/").HandlerFunc(tplHandler.HandleEmbeddedTemplate)

	return mux
}
