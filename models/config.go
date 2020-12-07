package models

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/SherClockHolmes/webpush-go"
)

// Config holds all the application config values.
// Not really a classical model since not saved into DB.
type Config struct {
	AdminEmail             string        // ADMINEMAIL
	ConnectionsRetention   int           // CONNECTIONSRETENTION
	Debug                  bool          // DEBUG
	Port                   int           // PORT
	Host                   string        // HOST
	DbType                 string        // DBTYPE
	DbDSN                  string        // DBDSN
	ExcludedIdentities     []string      // EXCLUDEDIDENTITIES
	RedirectDomain         *url.URL      // REDIRECTDOMAIN
	OAuth2ClientID         string        // OAUTH2LIENTID
	OAuth2ClientSecret     string        // OAUTH2CLIENTSECRET
	OAuth2Provider         string        // OAUTH2PROVIDER
	OAuth2Tenant           string        // OAUTH2TENANT
	EnableNotifications    bool          // ENABLENOTIFICATIONS
	EnableSSH              bool          // ENABLESSH
	EnableVPN              bool          // ENABLEVPN
	EnforceMFA             bool          // ENFORCEMFA
	MaxBodySize            int64         // not documented
	MFAOTP                 bool          // MFAOTP
	Issuer                 string        // ISSUER
	MFATouchID             bool          // MFATOUCHID
	MFAWebauthn            bool          // MFAWEBAUTHN
	LogoURL                *url.URL      // LOGOURL
	SigningKey             string        // SIGNINGKEY
	EncryptionKey          string        // ENCRYPTIONKEY
	OriginalIPHeader       string        // ORIGINALIPHEADER
	OriginalProtoHeader    string        // ORIGINALPROTOHEADER
	SSHRequireKey          bool          // SSHREQUIREKEY
	SSLMode                string        // SSLMODE
	SSLAutoCertsDir        string        // SSLAUTOCERTSDIR
	SSLCustomCertPath      string        // SSLCUSTOMCERTPATH
	SSLCustomKeyPath       string        // SSLCUSTOMKEYPATH
	VapidPublicKey         string        // VAPIDPUBLICKEY
	VapidPrivateKey        string        // VAPIDPRIVATEKEY
	VPNCheckPassword       string        // VPNCHECKPASSWORD
	VPNCheckAllowedIPs     []string      // VPNCHECKALLOWEDIPS
	VPNSessionValidity     time.Duration // VPNSESSIONVALIDITY
	WebSessionValidity     time.Duration // WEBSESSIONVALIDITY
	WebSessionProofTimeout time.Duration // WEBSESSIONPROOFTIMEOUT
}

func (config *Config) New() Config {
	var defaultConfig = Config{
		ConnectionsRetention:   90,
		DbType:                 "sqlite",
		DbDSN:                  "/tmp/vpnwa.db",
		Debug:                  false,
		ExcludedIdentities:     []string{},
		Port:                   8080,
		Host:                   "127.0.0.1",
		VPNSessionValidity:     30 * time.Minute,
		WebSessionValidity:     12 * time.Hour,
		WebSessionProofTimeout: 600 * time.Millisecond,
		EnableNotifications:    true,
		EnforceMFA:             true,
		MaxBodySize:            4096, // 4KB
		Issuer:                 "VPN",
		MFAOTP:                 true,
		MFATouchID:             true,
		MFAWebauthn:            true,
		SSLMode:                "off",
		SSLAutoCertsDir:        "/tmp",
		SSLCustomCertPath:      "/ssl/cert.pem",
		SSLCustomKeyPath:       "/ssl/kep.pem",
		OriginalProtoHeader:    "X-Forwarded-Proto",
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
	log.Printf("VPN Session validity set to %v", config.VPNSessionValidity)
	log.Printf("Web Session validity set to %v", config.WebSessionValidity)
	log.Printf("Google callback redirect set to %s", config.RedirectDomain)
	if config.OAuth2Provider == "" {
		log.Fatal("OAUTH2PROVIDER is not set, must be either google or azure")
	} else {
		config.OAuth2Provider = strings.ToLower(config.OAuth2Provider)
		if config.OAuth2Provider != "google" && config.OAuth2Provider != "azure" {
			log.Fatal("OAUTH2PROVIDER is invalid, must be either google or azure")
		}
	}
	if config.OAuth2Provider == "azure" && config.OAuth2Tenant == "" {
		log.Fatal("Microsoft/Azure OAuth2 provider requires OAUTH2TENANT to be set")
	}
	if config.OAuth2ClientID == "" {
		log.Fatal("OAUTH2CLIENTID is not set")
	}
	if config.OAuth2ClientSecret == "" {
		log.Fatal("OAUTH2CLIENTSECRET is not set")
	}
	if config.EnforceMFA {
		if config.EncryptionKey == "" {
			log.Fatal("ENCRYPTIONKEY is required when OTP is set to true. You can use `openssl rand -hex 16` to generate it")
		} else if len(config.EncryptionKey) != 32 {
			log.Fatal("ENCRYPTIONKEY must be 32 characters")
		}
	}
	if config.EnableNotifications {
		if config.AdminEmail == "" {
			log.Fatal("FATAL: ENABLENOTIFICATIONS is true, so ADMINEMAIL must be set to a valid email address.")
		}
		if config.VapidPrivateKey == "" || config.VapidPublicKey == "" {
			log.Printf("FATAL: ENABLENOTIFICATIONS is true, so VAPIDPRIVATEKEY and VAPIDPUBLICKEY must be defined and valid")
			log.Printf("If you have never defined them, here are some fresh values generated just for you.")
			if privateKey, publicKey, err := webpush.GenerateVAPIDKeys(); err == nil {
				log.Printf("VAPIDPUBLICKEY=\"%s\"", publicKey)
				log.Printf("VAPIDPRIVATEKEY=\"%s\"", privateKey)
			}
			log.Fatal("Add them to the environment variables. VAPIDPRIVATEKEY is sensitive, keep it secret.")
		}
	}
	config.SSLMode = strings.ToLower(config.SSLMode)
	if config.SSLMode != "off" && config.SSLMode != "auto" && config.SSLMode != "custom" && config.SSLMode != "proxy" {
		log.Fatal("SSLMODE must be one of off, auto, custom, proxy")
	}

}
