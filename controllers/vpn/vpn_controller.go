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
	utils                *utils.Utils
}

// New creates an instance of the controller and sets its DB handle
func New(db *gorm.DB, config *models.Config, notificationsManager *services.NotificationsManager, webSessManager *services.WebSessionManager) *VpnController {
	return &VpnController{
		db:                   db,
		config:               config,
		utils:                utils.New(config),
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

	// Early exit if identity is excluded from any additional auth.
	if contains(v.config.ExcludedIdentities, connRequest.Identity) {
		http.Error(w, "Excluded", http.StatusOK)
		return
	}

	userManager := services.NewUserManager(v.db, v.config)
	user, session, allowed, err := userManager.CheckVpnSession(connRequest.Identity, connRequest.SourceIP)
	if err != nil {
		log.Errorf("VpnController: Error checking user session: %s", err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if user == nil {
		log.Errorf("VpnController: Received request for unknown identity '%s' from %s", connRequest.Identity, connRequest.SourceIP)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	vpnConnection := models.VPNConnection{
		Allowed:     allowed,
		Identity:    connRequest.Identity,
		SourceIP:    connRequest.SourceIP,
		VPNSourceIP: v.utils.GetClientIP(r),
	}

	vpnConnection.UserID = &user.ID
	if allowed {
		vpnConnection.VPNSessionID = &session.ID
	}

	if allowed {
		if tx := v.db.Save(&vpnConnection); tx.Error != nil {
			log.Errorf("VpnController: error saving Vpnconnection audit entry for %s: %s", user.Email, tx.Error.Error())
		}
		http.Error(w, fmt.Sprintf("Ok %s", time.Since(start)), http.StatusOK)
		return
	}

	_, notifUniqueID, err := v.notificationsManager.NotifyUser(user, connRequest.SourceIP)
	hasValidBrowserSession := v.notificationsManager.WaitForBrowserProof(user, connRequest.SourceIP, *notifUniqueID)
	vpnConnection.Allowed = hasValidBrowserSession
	if tx := v.db.Save(&vpnConnection); tx.Error != nil {
		log.Errorf("VpnController: error saving Vpnconnection audit entry for %s: %s", user.Email, tx.Error.Error())
	}

	if !hasValidBrowserSession {
		log.Errorf("VpnController: No valid session found for user %s", connRequest.Identity)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	// Create a new VPNSession
	if err := userManager.CreateVpnSession(user, connRequest.SourceIP); err != nil {
		log.Errorf("VpnController: error creating VPN session: %s", err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	log.Infof("VpnController: user %s VPN session extended from valid Web session.", user.Email)
	http.Error(w, fmt.Sprintf("Ok %s", time.Since(start)), http.StatusOK)
}

func contains(arr []string, str string) bool {
	for _, a := range arr {
		if a == str {
			return true
		}
	}
	return false
}
