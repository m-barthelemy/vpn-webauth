package models

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/url"
)

// Config holds all the application config values.
// Not really a classical model since not saved into DB.
type Config struct {
	Debug               bool     // VPNWA_DEBUG
	Port                int      // VPNWA_PORT
	Host                string   // VPNWA_HOST
	DbType              string   // VPNWA_DBTYPE
	DbDSN               string   // VPNWA_DBDSN
	RedirectDomain      *url.URL // VPNWA_REDIRECTDOMAIN
	GoogleClientID      string   // VPNWA_GOOGLECLIENTID
	GoogleClientSecret  string   // VPNWA_GOOGLECLIENTSECRET
	SessionValidity     int      // VPNWA_SESSIONVALIDITY
	OTP                 bool     // VPNWA_OTP
	OTPIssuer           string   // VPNWA_OTPISSUER
	LogoURL             *url.URL // VPNWA_LOGOURL
	SigningKey          string   // VPNWA_SIGNINGKEY
	EncryptionKey       string   // VPNWA_ENCRYPTIONKEY
	OriginalIPHeader    string   // VPNWA_ORIGINALIPHEADER
	VpnOriginalIPHeader string   // VPNWA_VPNORIGINALIPHEADER
}

func (config *Config) New() Config {
	var defaultConfig = Config{
		DbType:          "sqlite",
		DbDSN:           "/tmp/vpnwa.db",
		Debug:           false,
		Port:            8080,
		Host:            "127.0.0.1",
		SessionValidity: 3600,
		OTP:             true,
		OTPIssuer:       "VPN",
	}
	redirDomain, _ := url.Parse(fmt.Sprintf("http://%s:%v", defaultConfig.Host, defaultConfig.Port))
	defaultConfig.RedirectDomain = redirDomain
	// We create a default random key for signing session tokens
	b := make([]byte, 32) // random ID
	rand.Read(b)
	key := base64.URLEncoding.EncodeToString(b)
	defaultConfig.SigningKey = key

	return defaultConfig
}

func (config *Config) Verify() {
	log.Printf("Session validity set to %v seconds", config.SessionValidity)
	log.Printf("Google callback redirect set to %s", config.RedirectDomain)
	if config.GoogleClientID == "" {
		log.Panic("VPNWA_GOOGLECLIENTID is not set")
	}
	if config.GoogleClientSecret == "" {
		log.Panic("VPNWA_GOOGLECLIENTSECRET is not set")
	}
	if config.OTP {
		if config.EncryptionKey == "" {
			log.Panic("VPNWA_ENCRYPTIONKEY is required when VPNWA_OTP is set to true. You can use `openssl rand -hex 16` to generate it")
		} else if len(config.EncryptionKey) != 32 {
			log.Panic("VPNWA_ENCRYPTIONKEY must be 32 characters")
		}
	}
}
