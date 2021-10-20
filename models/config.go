package models

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/SherClockHolmes/webpush-go"
)

// Config holds all the application config values.
// Not really a classical model since not saved into DB.
type Config struct {
	AdminEmail             string        // ADMINEMAIL
	AllowedVPNGwIPs        []IPDecoder   // ALLOWEDVPNGWIPS. CIDRs of VPN servers allowed to connect
	ConnectionsRetention   int           // CONNECTIONSRETENTION
	Debug                  bool          // DEBUG
	EAPMode                string        // EAPMODE
	EAPMSCHAPv2Password    string        // EAPMSCHAPV2PASSWORD
	EAPTLSCertificatePath  string        // EAPTLSCERTIFICATEPATH
	EAPTLSKeyPath          string        // EAPTLSKEYPATH
	EAPTLSClientCAPath     string        // EAPTLSCLIENTCAPATH
	Port                   int           // PORT
	Host                   string        // HOST
	DbType                 string        // DBTYPE
	DbDSN                  string        // DBDSN
	EnableNotifications    bool          // ENABLENOTIFICATIONS
	EnableRadiusEAP        bool          // ENABLERADIUSEAP
	EnforceMFA             bool          // ENFORCEMFA
	ExcludedIdentities     []string      // EXCLUDEDIDENTITIES
	RedirectDomain         *url.URL      // REDIRECTDOMAIN
	OAuth2ClientID         string        // OAUTH2LIENTID
	OAuth2ClientSecret     string        // OAUTH2CLIENTSECRET
	OAuth2Provider         string        // OAUTH2PROVIDER
	OAuth2Tenant           string        // OAUTH2TENANT
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
	RadiusPort             int           // RADIUSPORT
	RadiusSecret           string        // RADIUSSECRET
	SSLMode                string        // SSLMODE
	SSLAutoCertsDir        string        // SSLAUTOCERTSDIR
	SSLCustomCertPath      string        // SSLCUSTOMCERTPATH
	SSLCustomKeyPath       string        // SSLCUSTOMKEYPATH
	VapidPublicKey         string        // VAPIDPUBLICKEY
	VapidPrivateKey        string        // VAPIDPRIVATEKEY
	VPNCheckPassword       string        // VPNCHECKPASSWORD
	VPNSessionValidity     time.Duration // VPNSESSIONVALIDITY
	WebSessionValidity     time.Duration // WEBSESSIONVALIDITY
	WebSessionProofTimeout time.Duration // WEBSESSIONPROOFTIMEOUT
}

func (config *Config) New() Config {
	var defaultConfig = Config{
		AllowedVPNGwIPs: []IPDecoder{
			IPDecoder(net.IPNet{IP: net.IPv4(0x00, 0x00, 0x00, 0x00), Mask: net.CIDRMask(0, 32)}), // 0.0.0.0/0
		},
		ConnectionsRetention:   90,
		DbType:                 "sqlite",
		DbDSN:                  "/tmp/vpnwa.db",
		Debug:                  false,
		EnableRadiusEAP:        false,
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
		RadiusPort:             1812,
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
	log.Infof("VPN Session validity set to %v", config.VPNSessionValidity)
	log.Infof("Web Session validity set to %v", config.WebSessionValidity)
	log.Infof("Google callback redirect set to %s", config.RedirectDomain)
	if config.OAuth2Provider == "" {
		log.Fatal("OAUTH2PROVIDER is not set, must be either google or azure")
	} else {
		config.OAuth2Provider = strings.ToLower(config.OAuth2Provider)
		if config.OAuth2Provider != "google" && config.OAuth2Provider != "azure" {
			log.Fatal("OAUTH2PROVIDER is invalid, must be either 'google' or 'azure'")
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
			log.Fatal("ENABLENOTIFICATIONS is true, so ADMINEMAIL must be set to a valid email address.")
		}
		if config.VapidPrivateKey == "" || config.VapidPublicKey == "" {
			log.Error("ENABLENOTIFICATIONS is true, so VAPIDPRIVATEKEY and VAPIDPUBLICKEY must be defined and valid")
			log.Error("If you have never defined them, here are some fresh values generated just for you.")
			if privateKey, publicKey, err := webpush.GenerateVAPIDKeys(); err == nil {
				log.Infof("VAPIDPUBLICKEY=\"%s\"", publicKey)
				log.Infof("VAPIDPRIVATEKEY=\"%s\"", privateKey)
			}
			log.Fatal("Add them to the environment variables. VAPIDPRIVATEKEY is sensitive, keep it secret.")
		}
	}
	if config.EnableRadiusEAP {
		if config.RadiusSecret == "" {
			log.Fatal("ENABLERADIUSEAP is true, so RADIUSSECRET must be set")
		}
		if config.EAPMode != "mschapv2" && config.EAPMode != "tls" {
			log.Fatal("ENABLERADIUSEAP is true, so EAPMODE must be set to either 'mschapv2' or 'tls'")
		}
		if config.EAPMode == "mschapv2" && config.EAPMSCHAPv2Password == "" {
			log.Fatal("EAPMODE is set to 'mschapv2', so EAPMSCHAPV2PASSWORD must be set")
		}
		if config.EAPMode == "tls" && (config.EAPTLSCertificatePath == "" || config.EAPTLSKeyPath == "" || config.EAPTLSClientCAPath == "") {
			log.Fatal("EAPMODE is set to 'tls', so EAPTLSCERTIFICATEPATH, EAPTLSKEYPATH and EAPTLSCLIENTCAPATH must be set")
		}
	}
	config.SSLMode = strings.ToLower(config.SSLMode)
	if config.SSLMode != "off" && config.SSLMode != "auto" && config.SSLMode != "custom" && config.SSLMode != "proxy" {
		log.Fatal("SSLMODE must be one of: off, auto, custom, proxy")
	}
}

type IPDecoder net.IPNet

func (ipd *IPDecoder) Decode(value string) error {
	if strings.Index(value, "/") < 0 {
		value += "/32"
	}
	_, subnet, err := net.ParseCIDR(value)
	if err != nil {
		return err
	}
	*ipd = IPDecoder(*subnet)
	return nil
}
