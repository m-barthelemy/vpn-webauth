//go:generate pkger

package routes

import (
	"log"
	"net/http"
	"os"

	"github.com/gorilla/handlers"
	googlecontroller "github.com/m-barthelemy/vpn-webauth/controllers/google"
	usercontroller "github.com/m-barthelemy/vpn-webauth/controllers/user"
	vpnController "github.com/m-barthelemy/vpn-webauth/controllers/vpn"
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
		log.Printf("Error compiling templates: ", err.Error())
	}
	mux := http.NewServeMux()

	/*mux.Handle("/assets/", http.FileServer(http.Dir("templates/")))
	mux.Handle("/fonts/", http.FileServer(http.Dir("templates/")))
	mux.Handle("/font/", http.FileServer(http.Dir("templates/")))*/

	// Anything not matching a route below will be considered as a HTML template
	//mux.HandleFunc("/", tplHandler.HandleTemplate)

	mux.HandleFunc("/assets/", tplHandler.HandleStaticAsset)
	mux.HandleFunc("/", tplHandler.HandleEmbeddedTemplate)

	googleC := googlecontroller.New(db, config)
	mux.HandleFunc("/auth/google/login", googleC.OauthGoogleLogin)
	mux.Handle("/auth/google/callback", handlers.LoggingHandler(os.Stdout, http.HandlerFunc(googleC.OauthGoogleCallback)))

	usersC := usercontroller.New(db, config)
	mux.Handle("/auth/qrcode", handlers.LoggingHandler(os.Stdout, http.HandlerFunc(sessionMiddleware(tokenSigningKey, usersC.GenerateQrCode))))
	mux.Handle("/auth/validateotp", handlers.LoggingHandler(os.Stdout, http.HandlerFunc(sessionMiddleware(tokenSigningKey, usersC.ValidateOTP))))

	vpnC := vpnController.New(db, config)
	mux.Handle("/vpn/check", handlers.LoggingHandler(os.Stdout, http.HandlerFunc(vpnC.CheckSession)))

	return mux
}
