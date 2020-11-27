package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

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
		// We need longer response timeouts for the Events persistent connection with the clients
		WriteTimeout: 3600 * time.Second,
		IdleTimeout:  60 * time.Second, // slightly highler than the SSE periodic "ping" interval
		Handler:      handler,
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
