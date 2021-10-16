package controllers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/m-barthelemy/vpn-webauth/models"
	services "github.com/m-barthelemy/vpn-webauth/services"
	"github.com/m-barthelemy/vpn-webauth/utils"
	"gorm.io/gorm"
)

type VpnController struct {
	db                   *gorm.DB
	config               *models.Config
	notificationsManager *services.NotificationsManager
	webSessManager       *services.WebSessionManager
	utils                *utils.Utils
}

// New creates an instance of the controller and sets its DB handle
func New(db *gorm.DB, config *models.Config, notificationsManager *services.NotificationsManager, webSessManager *services.WebSessionManager) *VpnController {
	return &VpnController{
		db:                   db,
		config:               config,
		utils:                utils.New(config),
		webSessManager:       webSessManager,
		notificationsManager: notificationsManager,
	}
}

// VpnConnectionRequest is what is received from the Stringswan `ext-auth` script request
type VpnConnectionRequest struct {
	Identity string
	SourceIP string
}

func (v *VpnController) CheckSession(w http.ResponseWriter, r *http.Request) {
	start := time.Now() // report time taken to verify user for debugging purposes
	_, password, _ := r.BasicAuth()
	if password != v.config.VPNCheckPassword {
		log.Error("VpnController: password does not match VPNCHECKPASSWORD")
		http.Error(w, "Invalid VPNCHECKPASSWORD", http.StatusForbidden)
		return
	}

	var connRequest VpnConnectionRequest
	err := json.NewDecoder(r.Body).Decode(&connRequest)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	log := log.WithFields(log.Fields{
		"user_id": connRequest.Identity,
		"user_ip": connRequest.SourceIP,
	})
	log.Debugf("VpnController: verifying user web session")
	err = v.webSessManager.CheckSession(connRequest.Identity, connRequest.SourceIP)
	if err != nil {
		log.Errorf("VpnController: unable to authenticate client via web: %s", err)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	log.Info("VpnController: VPN session extended from valid Web session.")
	http.Error(w, fmt.Sprintf("Ok %s", time.Since(start)), http.StatusOK)
}
