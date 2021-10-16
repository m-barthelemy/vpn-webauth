package utils

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/m-barthelemy/vpn-webauth/models"
)

type Utils struct {
	config *models.Config
}

func New(config *models.Config) *Utils {
	return &Utils{config: config}
}

func (u *Utils) GetClientIP(r *http.Request) string {
	if u.config.OriginalIPHeader != "" {
		if proxyHeader := r.Header.Get(u.config.OriginalIPHeader); len(proxyHeader) > 0 {
			forwardedIps := strings.Split(proxyHeader, ",")
			// Last value, if multiple found, is supposed to be the "trusted" one because added by a reverse proxy we control.
			return strings.TrimSpace(forwardedIps[len(forwardedIps)-1])

		} else {
			log.Printf("Utils: Configured to get client IP from `%s` but header is absent or empty", u.config.OriginalIPHeader)
		}
	}

	sourceIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	return sourceIP
}

func (u *Utils) GetAllowedMFAs() []string {
	var options []string
	if u.config.MFATouchID {
		options = append(options, "touchid")
	}
	if u.config.MFAOTP {
		options = append(options, "otp")
	}
	if u.config.MFAWebauthn {
		options = append(options, "webauthn")
	}
	return options
}

// JsonResponse outputs tobject as a 200 HTTP JSON encoded response
func JSONResponse(w http.ResponseWriter, d interface{}, statusCode int) {
	json, err := json.Marshal(d)
	if err != nil {
		log.Printf("WebAuthNController: Error serializing response to JSON: %s", err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	fmt.Fprintf(w, "%s", json)
}

func Contains(arr []string, str string) bool {
	for _, a := range arr {
		if a == str {
			return true
		}
	}
	return false
}
