package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"
	"strings"

	"github.com/m-barthelemy/vpn-webauth/models"
	"golang.org/x/crypto/acme/autocert"
)

func startServer(config *models.Config, handler http.Handler) {
	domain, _, _ := net.SplitHostPort(config.RedirectDomain.Host)
	if domain == "" {
		domain = config.RedirectDomain.Host
	}
	certManager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(domain),
	}

	if config.SSLMode == "auto" {
		if err := cacheDir(config.SSLAutoCertsDir); err != nil {
			log.Fatalf("Could not create Letsencrypt certs directory %s : %s", config.SSLAutoCertsDir, err.Error())
		}
		certManager.Cache = autocert.DirCache(config.SSLAutoCertsDir)
	}

	var tlsConfig tls.Config
	var customCert tls.Certificate
	if config.SSLMode == "custom" {
		var err error
		customCert, err = tls.LoadX509KeyPair(config.SSLCustomCertPath, config.SSLCustomKeyPath)
		if err != nil {
			log.Fatalf(" ould not load custom key or certificate: %s", err.Error())
		}
	}
	if config.SSLMode == "auto" || config.SSLMode == "custom" {
		// These settings provide high security and get an A+ grade with SSLLabs.
		tlsConfig = tls.Config{
			PreferServerCipherSuites: true,
			SessionTicketsDisabled:   true,
			ClientSessionCache:       tls.NewLRUClientSessionCache(32),
			MinVersion:               tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
			GetCertificate: func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				if config.SSLMode == "auto" {
					return certManager.GetCertificate(clientHello)
				}
				return &customCert, nil
			},
		}
	}

	// Create the HTTP server.
	server := &http.Server{
		Addr:      fmt.Sprintf("%s:%v", config.Host, config.Port),
		TLSConfig: &tlsConfig,
		// Needed to avoid some resources exhaustion, especially if the service is publicly exposed.
		ReadTimeout:       5 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      1 * time.Hour,                                 // Needs to be long for SSE
		IdleTimeout:       30 * time.Second,                              // slightly highler than the SSE periodic "ping" interval
		MaxHeaderBytes:    8 * 1024,                                      // 8KB
		Handler:           &topHandler{config: config, handler: handler}, // Ensure requests time out except for SSE endpoint
	}

	log.Printf("Serving http/https for domains: %+v", domain)
	if config.SSLMode == "auto" {
		go func() {
			// Serve HTTP, which will redirect automatically to HTTPS
			h := certManager.HTTPHandler(nil)
			log.Fatal(http.ListenAndServe(":http", h))
		}()
	}
	if config.SSLMode == "auto" || config.SSLMode == "custom" {
		// Serve HTTPS
		log.Fatal(server.ListenAndServeTLS("", ""))
	} else {
		log.Fatal(server.ListenAndServe())
	}
}

func cacheDir(dir string) error {
	if err := os.MkdirAll(dir, 0700); err == nil {
		return err
	}
	return nil
}

type topHandler struct {
	config  *models.Config
	handler http.Handler
}

func (h *topHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	header := w.Header()
	csp := []string{
		"default-src 'self'",
		"object-src 'none'",
		"media-src 'none'",
		"connect-src 'self'",
		"font-src https://fonts.gstatic.com 'self'",
		"child-src 'self'",
		"style-src 'self' 'sha384-Tn+eHgvLDlHfZ/Bd0HmrFRKnaocbJJECUsEAjjg2gey5liDBv1trMEyh2l7XC2C+' 'sha384-1ji7hb9jc+M2e4aPgCIK93lON9Hxx38Vo/3oNk9vrJsU8JbrdFdLs+VmVE1YNiuM' 'sha384-wvfXpqpZZVQGK6TAh5PVlGOfQNHSoD2xbE+QkPxCAFlNEevoEH3Sl0sibVcOQVnN' 'sha384-YzFrpTZultPbM+R+lmHjVtHhJR5p6ke81qSWnPtxFRQCyeOeHAEfJ3ahK1W716+L'",
		"img-src 'self' " + h.config.LogoURL.String(),
		"script-src 'self' 'sha384-ZvpUoO/+PpLXR1lu4jmpXWu80pZlYUAfxl5NsBMWOEPSjUn/6Z/hRTt8+pR6L4N2' 'sha384-jnt1QI5LA9Z8CEqFV7YvpkT/kvVzzSDZbit0VjFaNiz/XtzoN8OA7z/RI/cbzs95' 'sha384-6Lv63lIkYGuslSt2g+9eZjV3aRZ6a2gV4JF/AX2MB7JJo/jwTr/x7u3rbn/vMQGY'",
		"form-action 'self'",
	}
	header.Set("Content-Security-Policy", strings.Join(csp, "; "))
	
	// Refuse request with big body
	r.Body = http.MaxBytesReader(w, r.Body, h.config.MaxBodySize)

	// SSE are long duration connections
	if r.URL.Path == "/events" {
		h.handler.ServeHTTP(w, r)
	} else {
		o := http.TimeoutHandler(h.handler, 5*time.Second, "Request took too long")
		o.ServeHTTP(w, r)
	}
}
