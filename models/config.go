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
	AdminEmail              string        `envconfig:"ADMIN_EMAIL"`
	ConnectionsRetention    int           `envconfig:"CONNECTIONS_RETENTION"`
	Debug                   bool          // DEBUG
	Port                    int           // PORT
	Host                    string        // HOST
	DbType                  string        `envconfig:"DB_TYPE"`
	DbDSN                   string        `envconfig:"DB_DSN"`
	ExcludedIdentities      []string      `envconfig:"EXCLUDED_IDENTITIES"`
	BaseURL                 *url.URL      `envconfig:"BASE_URL"`
	OAuth2ClientID          string        `envconfig:"OAUTH2_CLIENT_ID"`
	OAuth2ClientSecret      string        `envconfig:"OAUTH2_CLIENT_SECRET"`
	OAuth2Provider          string        `envconfig:"OAUTH2_PROVIDER"`
	OAuth2TenantID          string        `envconfig:"OAUTH2_TENANT_ID"`
	EnableNotifications     bool          `envconfig:"ENABLE_NOTIFICATIONS"`
	EnableSSH               bool          `envconfig:"ENABLE_SSH"`
	EnableVPN               bool          `envconfig:"ENABLE_VPN"`
	EnforceMFA              bool          `envconfig:"ENFORCE_MFA"`
	LogoURL                 *url.URL      `envconfig:"LOGO_URL"`
	MaxBodySize             int64         // not documented
	MFAOTP                  bool          `envconfig:"MFA_OTP"`
	MFATouchID              bool          `envconfig:"MFA_TOUCHID"`
	MFAWebauthn             bool          `envconfig:"MFA_WEBAUTHN"`
	OrgName                 string        `envconfig:"ORG_NAME"`
	SigningKey              string        `envconfig:"SIGNING_KEY"`
	EncryptionKey           string        `envconfig:"ENCRYPTION_KEY"`
	OriginalIPHeader        string        `envconfig:"ORIGINAL_IP_HEADER"`
	OriginalProtoHeader     string        `envconfig:"ORIGINAL_PROTO_HEADER"`
	RemoteAuthCheckPassword string        `envconfig:"REMOTE_AUTH_CHECK_PASSWORD"`
	RemoteSessionValidity   time.Duration `envconfig:"REMOTE_SESSION_VALIDITY"`
	SSHAllowedSourceIPs     []string      `envconfig:"SSH_ALLOWED_SOURCE_IPS"`
	SSLMode                 string        `envconfig:"SSL_MODE"`
	SSLAutoCertsDir         string        `envconfig:"SSL_AUTO_CERTS_DIR"`
	SSLCustomCertPath       string        `envconfig:"SSL_CUSTOM_CERT_PATH"`
	SSLCustomKeyPath        string        `envconfig:"SSL_CUSTOM_KEY_PATH"`
	VapidPublicKey          string        `envconfig:"VAPID_PUBLIC_KEY"`
	VapidPrivateKey         string        `envconfig:"VAPID_PRIVATE_KEY"`
	VPNCheckAllowedIPs      []string      `envconfig:"VPN_CHECK_ALLOWED_IPS"`
	WebSessionValidity      time.Duration `envconfig:"WEB_SESSION_VALIDITY"`
	WebSessionProofTimeout  time.Duration // WEBSESSIONPROOFTIMEOUT
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
		RemoteSessionValidity:  30 * time.Minute,
		WebSessionValidity:     12 * time.Hour,
		WebSessionProofTimeout: 600 * time.Millisecond, // Not yet documented
		EnableNotifications:    true,
		EnforceMFA:             true,
		MaxBodySize:            4096, // 4KB
		OrgName:                "VPN",
		MFAOTP:                 true,
		MFATouchID:             true,
		MFAWebauthn:            true,
		SSHAllowedSourceIPs:    []string{},
		SSLMode:                "off",
		SSLAutoCertsDir:        "/tmp",
		SSLCustomCertPath:      "/ssl/cert.pem",
		SSLCustomKeyPath:       "/ssl/kep.pem",
		OriginalProtoHeader:    "X-Forwarded-Proto",
	}
	redirDomain, _ := url.Parse(fmt.Sprintf("http://%s:%v", defaultConfig.Host, defaultConfig.Port))
	defaultConfig.BaseURL = redirDomain
	// We create a default random key for signing session tokens
	b := make([]byte, 32) // random ID
	rand.Read(b)
	key := base64.URLEncoding.EncodeToString(b)
	defaultConfig.SigningKey = key

	return defaultConfig
}

func (config *Config) Verify() {
	log.Printf("Remote sessions validity set to %v", config.RemoteSessionValidity)
	log.Printf("Web sessions validity set to %v", config.WebSessionValidity)
	log.Printf("User-facing base URL set to %s", config.BaseURL)
	if config.OAuth2Provider == "" {
		log.Fatal("OAUTH2_PROVIDER is not set, must be either google or azure")
	} else {
		config.OAuth2Provider = strings.ToLower(config.OAuth2Provider)
		if config.OAuth2Provider != "google" && config.OAuth2Provider != "azure" {
			log.Fatal("OAUTH2_PROVIDER is invalid, must be either google or azure")
		}
	}
	if config.OAuth2Provider == "azure" && config.OAuth2TenantID == "" {
		log.Fatal("Microsoft/Azure OAuth2 provider requires OAUTH2_TENANT_ID to be set")
	}
	if config.OAuth2ClientID == "" {
		log.Fatal("OAUTH2_CLIENT_ID is not set")
	}
	if config.OAuth2ClientSecret == "" {
		log.Fatal("OAUTH2_CLIENT_SECRET is not set")
	}
	if config.EnforceMFA {
		if config.EncryptionKey == "" {
			log.Fatal("ENCRYPTION_KEY is required when OTP is set to true. You can use `openssl rand -hex 16` to generate it")
		} else if len(config.EncryptionKey) != 32 {
			log.Fatal("ENCRYPTION_KEY must be 32 characters")
		}
	}
	if config.EnableNotifications {
		if config.AdminEmail == "" {
			log.Fatal("FATAL: ENABLE_NOTIFICATIONS is true, so ADMIN_EMAIL must be set to a valid email address.")
		}
		if config.VapidPrivateKey == "" || config.VapidPublicKey == "" {
			log.Printf("FATAL: ENABLE_NOTIFICATIONS is true, so VAPID_PRIVATE_KEY and VAPID_PUBLIC_KEY must be defined and valid")
			log.Printf("If you have never defined them, here are some fresh values generated just for you.")
			if privateKey, publicKey, err := webpush.GenerateVAPIDKeys(); err == nil {
				log.Printf("VAPID_PUBLIC_KEY=\"%s\"", publicKey)
				log.Printf("VAPID_PRIVATE_KEY=\"%s\"", privateKey)
			}
			log.Fatal("Add them to the environment variables. VAPID_PRIVATE_KEY is sensitive, keep it secret.")
		}
	}
	config.SSLMode = strings.ToLower(config.SSLMode)
	if config.SSLMode != "off" && config.SSLMode != "auto" && config.SSLMode != "custom" && config.SSLMode != "proxy" {
		log.Fatal("SSLMODE must be one of off, auto, custom, proxy")
	}
	if !config.EnableSSH && !config.EnableVPN {
		log.Fatal("Both ENABLE_SSH and ENABLE_VPN are disabled, which doesn't make sense.")
	}

}
