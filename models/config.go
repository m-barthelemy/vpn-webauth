package models

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/url"
	"strings"
)

// Config holds all the application config values.
// Not really a classical model since not saved into DB.
type Config struct {
	Debug               bool     // VPNWA_DEBUG
	Port                int      // VPNWA_PORT
	Host                string   // VPNWA_HOST
	DbType              string   // VPNWA_DBTYPE
	DbDSN               string   // VPNWA_DBDSN
	ExcludedIdentities  []string // VPNWA_EXCLUDEDIDENTITIES
	RedirectDomain      *url.URL // VPNWA_REDIRECTDOMAIN
	GoogleClientID      string   // VPNWA_GOOGLECLIENTID
	GoogleClientSecret  string   // VPNWA_GOOGLECLIENTSECRET
	EnforceMFA          bool     // VPNWA_ENFORCEMFA
	MFAOTP              bool     // VPNWA_MFAOTP
	MFAIssuer           string   // VPNWA_OTPISSUER
	MFAValidity         int      // VPNWA_MFAVALIDITY
	MFATouchID          bool     // VPNWA_MFATOUCHID
	MFAWebauthn         bool     // MFAWEBAUTHN
	LogoURL             *url.URL // VPNWA_LOGOURL
	SigningKey          string   // VPNWA_SIGNINGKEY
	EncryptionKey       string   // VPNWA_ENCRYPTIONKEY
	OriginalIPHeader    string   // VPNWA_ORIGINALIPHEADER
	OriginalProtoHeader string   // VPNWA_ORIGINALPROTOHEADER
	SSLMode             string   // VPNWA_SSLMODE
	SSLAutoCertsDir     string   // VPNWA_SSLAUTOCERTSDIR
	SSLCustomCertPath   string   // VPNWA_SSLCUSTOMCERTPATH
	SSLCustomKeyPath    string   // VPNWA_SSLCUSTOMKEYPATH
	VPNSessionValidity  int      // VPNWA_VPNSESSIONVALIDITY
}

func (config *Config) New() Config {
	var defaultConfig = Config{
		DbType:              "sqlite",
		DbDSN:               "/tmp/vpnwa.db",
		Debug:               false,
		ExcludedIdentities:  []string{},
		Port:                8080,
		Host:                "127.0.0.1",
		VPNSessionValidity:  3600,
		EnforceMFA:          true,
		MFAIssuer:           "VPN",
		MFAOTP:              true,
		MFATouchID:          true,
		MFAWebauthn:         true,
		SSLMode:             "off",
		SSLAutoCertsDir:     "/tmp",
		SSLCustomCertPath:   "/ssl/cert.pem",
		SSLCustomKeyPath:    "/ssl/kep.pem",
		OriginalProtoHeader: "X-Forwarded-Proto",
	}
	redirDomain, _ := url.Parse(fmt.Sprintf("http://%s:%v", defaultConfig.Host, defaultConfig.Port))
	defaultConfig.RedirectDomain = redirDomain
	defaultConfig.MFAValidity = defaultConfig.VPNSessionValidity
	// We create a default random key for signing session tokens
	b := make([]byte, 32) // random ID
	rand.Read(b)
	key := base64.URLEncoding.EncodeToString(b)
	defaultConfig.SigningKey = key

	return defaultConfig
}

func (config *Config) Verify() {
	log.Printf("Session validity set to %v seconds", config.VPNSessionValidity)
	log.Printf("Google callback redirect set to %s", config.RedirectDomain)
	if config.GoogleClientID == "" {
		log.Fatal("VPNWA_GOOGLECLIENTID is not set")
	}
	if config.GoogleClientSecret == "" {
		log.Fatal("VPNWA_GOOGLECLIENTSECRET is not set")
	}
	if config.EnforceMFA {
		if config.EncryptionKey == "" {
			log.Fatal("VPNWA_ENCRYPTIONKEY is required when VPNWA_OTP is set to true. You can use `openssl rand -hex 16` to generate it")
		} else if len(config.EncryptionKey) != 32 {
			log.Fatal("VPNWA_ENCRYPTIONKEY must be 32 characters")
		}
	}
	config.SSLMode = strings.ToLower(config.SSLMode)
	if config.SSLMode != "off" && config.SSLMode != "auto" && config.SSLMode != "custom" && config.SSLMode != "proxy" {
		log.Fatal("VPNWA_SSLMODE must be one of off, auto, custom, proxy")
	}

}
