package utils

import (
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
			return ""
		}
	} else {
		sourceIP, _, _ := net.SplitHostPort(r.RemoteAddr)
		return sourceIP
	}
}
