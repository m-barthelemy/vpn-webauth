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

func startHTTPerver(config *models.Config, handler http.Handler) {

}

func startTLSServer(config *models.Config, handler http.Handler) {
	domain, _, _ := net.SplitHostPort(config.RedirectDomain.Host)
	certManager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(domain),
	}

	// optionally use a cache dir
	if err := cacheDir(config.SSLAutoCertsDir); err != nil {
		log.Fatalf("Could not create Letsencrypt certs directory %s : %s", config.SSLAutoCertsDir, err.Error())
	}
	certManager.Cache = autocert.DirCache(config.SSLAutoCertsDir)

	// Ensure the browser will always use HTTPS
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=15768000 ; includeSubDomains")
		fmt.Fprintf(w, "Hello, HTTPS world!")
	})

	// create the HTTPS server.
	// The settings here provide good/high security and get A+ with SSLLabs.
	server := &http.Server{
		Addr: fmt.Sprintf("%s:%v", config.Host, config.Port),
		TLSConfig: &tls.Config{
			GetCertificate:           certManager.GetCertificate,
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
				tls.TLS_RSA_WITH_AES_128_GCM_SHA256, // No PFS but provides compatibility with older OS
			},
		},
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
		Handler:      handler,
	}

	log.Printf("Serving http/https for domains: %+v", domain)
	go func() {
		// serve HTTP, which will redirect automatically to HTTPS
		h := certManager.HTTPHandler(nil)
		log.Fatal(http.ListenAndServe(":http", h))
	}()

	// serve HTTPS!
	log.Fatal(server.ListenAndServeTLS("", ""))
}

func cacheDir(dir string) error {
	if err := os.MkdirAll(dir, 0700); err == nil {
		return err
	}
	return nil
}
