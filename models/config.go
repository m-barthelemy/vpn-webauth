package models

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/url"
	"strings"

	"github.com/SherClockHolmes/webpush-go"
)

// Config holds all the application config values.
// Not really a classical model since not saved into DB.
type Config struct {
	AdminEmail           string
	ConnectionsRetention int      // CONNECTIONSRETENTION
	Debug                bool     // DEBUG
	Port                 int      // PORT
	Host                 string   // HOST
	DbType               string   // DBTYPE
	DbDSN                string   // DBDSN
	ExcludedIdentities   []string // EXCLUDEDIDENTITIES
	RedirectDomain       *url.URL // REDIRECTDOMAIN
	GoogleClientID       string   // GOOGLECLIENTID
	GoogleClientSecret   string   // GOOGLECLIENTSECRET
	EnforceMFA           bool     // ENFORCEMFA
	MFAOTP               bool     // MFAOTP
	MFAIssuer            string   // OTPISSUER
	MFAValidity          int      // MFAVALIDITY
	MFATouchID           bool     // MFATOUCHID
	MFAWebauthn          bool     // MFAWEBAUTHN
	LogoURL              *url.URL // LOGOURL
	SigningKey           string   // SIGNINGKEY
	EncryptionKey        string   // ENCRYPTIONKEY
	OriginalIPHeader     string   // ORIGINALIPHEADER
	OriginalProtoHeader  string   // ORIGINALPROTOHEADER
	SSLMode              string   // SSLMODE
	SSLAutoCertsDir      string   // SSLAUTOCERTSDIR
	SSLCustomCertPath    string   // SSLCUSTOMCERTPATH
	SSLCustomKeyPath     string   // SSLCUSTOMKEYPATH
	VapidPublicKey       string
	VapidPrivateKey      string
	VPNCheckPassword     string // VPNCHECKPASSWORD
	VPNSessionValidity   int    // VPNSESSIONVALIDITY
}

func (config *Config) New() Config {
	var defaultConfig = Config{
		ConnectionsRetention: 30,
		DbType:               "sqlite",
		DbDSN:                "/tmp/vpnwa.db",
		Debug:                false,
		ExcludedIdentities:   []string{},
		Port:                 8080,
		Host:                 "127.0.0.1",
		VPNSessionValidity:   3600,
		EnforceMFA:           true,
		MFAIssuer:            "VPN",
		MFAOTP:               true,
		MFATouchID:           true,
		MFAWebauthn:          true,
		SSLMode:              "off",
		SSLAutoCertsDir:      "/tmp",
		SSLCustomCertPath:    "/ssl/cert.pem",
		SSLCustomKeyPath:     "/ssl/kep.pem",
		OriginalProtoHeader:  "X-Forwarded-Proto",
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
		log.Fatal("GOOGLECLIENTID is not set")
	}
	if config.GoogleClientSecret == "" {
		log.Fatal("GOOGLECLIENTSECRET is not set")
	}
	if config.EnforceMFA {
		if config.EncryptionKey == "" {
			log.Fatal("ENCRYPTIONKEY is required when OTP is set to true. You can use `openssl rand -hex 16` to generate it")
		} else if len(config.EncryptionKey) != 32 {
			log.Fatal("ENCRYPTIONKEY must be 32 characters")
		}
	}
	if config.VapidPrivateKey == "" || config.VapidPublicKey == "" {
		log.Printf("FATAL: VAPIDPRIVATEKEY and VAPIDPUBLICKEY must be defined and valid")
		log.Printf("If you have never defined them, here are some fresh values generated just for you.")
		if privateKey, publicKey, err := webpush.GenerateVAPIDKeys(); err == nil {
			log.Printf("VAPIDPUBLICKEY=\"%s\"", publicKey)
			log.Printf("VAPIDPRIVATEKEY=\"%s\"", privateKey)
		}
		log.Fatal("Add them to the environment variables. VAPIDPRIVATEKEY is sensitive, keep it secret.")
	}
	config.SSLMode = strings.ToLower(config.SSLMode)
	if config.SSLMode != "off" && config.SSLMode != "auto" && config.SSLMode != "custom" && config.SSLMode != "proxy" {
		log.Fatal("SSLMODE must be one of off, auto, custom, proxy")
	}

}
