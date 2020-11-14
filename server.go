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
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				// No PFS but provides compatibility with older OS
				// It it also required for enabling HTTP/2
				tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			},
			GetCertificate: func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				if config.SSLMode == "auto" {
					return certManager.GetCertificate(clientHello)
				} else {
					return &customCert, nil
				}
			},
		}
	}

	// Create the HTTP server.
	server := &http.Server{
		Addr:      fmt.Sprintf("%s:%v", config.Host, config.Port),
		TLSConfig: &tlsConfig,
		// Needed to avoid some resources exhaustion, especially if the service is publicly exposed.
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 8 * time.Second,
		IdleTimeout:  60 * time.Second,
		Handler:      handler,
	}

	log.Printf("Serving http/https for domains: %+v", domain)
	if config.SSLMode == "auto" {
		go func() {
			// serve HTTP, which will redirect automatically to HTTPS
			h := certManager.HTTPHandler(nil)
			log.Fatal(http.ListenAndServe(":http", h))
		}()
	}
	if config.SSLMode == "auto" || config.SSLMode == "custom" {
		// serve HTTPS!
		log.Fatal(server.ListenAndServeTLS("", ""))
	} else {
		server.ListenAndServe()
	}
}

func cacheDir(dir string) error {
	if err := os.MkdirAll(dir, 0700); err == nil {
		return err
	}
	return nil
}
