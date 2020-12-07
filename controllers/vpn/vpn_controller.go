package controllers

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"github.com/m-barthelemy/vpn-webauth/models"
	"github.com/m-barthelemy/vpn-webauth/services"
	userManager "github.com/m-barthelemy/vpn-webauth/services"
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
func New(db *gorm.DB, config *models.Config, notificationsManager *services.NotificationsManager) *VpnController {
	return &VpnController{
		db:                   db,
		config:               config,
		utils:                utils.New(config),
		notificationsManager: notificationsManager,
	}
}

// ServerConnectionRequest is what is received from the Strongswan `ext-auth` script
// or pam_exec module.
type ServerConnectionRequest struct {
	Identity    string // The user identity as seen by remote SSH/VPN server
	SourceIP    string // The user source IP
	SSHAuthInfo string // Value of SSH_AUTH_INFO_0, line returns replaced with commas
	CallerName  string // The name or hostname of the caller (Hostname for SSH)
}

func (v *VpnController) CheckSession(w http.ResponseWriter, r *http.Request) {
	start := time.Now() // report time taken to verify user for debugging purposes
	_, password, _ := r.BasicAuth()
	if password != v.config.VPNCheckPassword {
		log.Print("VpnController: password does not match VPNCHECKPASSWORD")
		http.Error(w, "Invalid VPNCHECKPASSWORD", http.StatusForbidden)
		return
	}
	callerIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	// TODO: how does that apply to SSH connections?
	if len(v.config.VPNCheckAllowedIPs) > 0 {
		if !contains(v.config.VPNCheckAllowedIPs, callerIP) {
			log.Printf("VpnController: source IP %s is not in VPNCHECKALLOWEDIPS allowed list", callerIP)
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
	}
	var connRequest ServerConnectionRequest
	err := json.NewDecoder(r.Body).Decode(&connRequest)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if connRequest.Identity == "" {
		http.Error(w, "Empty Identity field", http.StatusBadRequest)
		return
	}
	// Early exit if identity is excluded from any additional auth.
	if contains(v.config.ExcludedIdentities, connRequest.Identity) {
		http.Error(w, "Excluded", http.StatusOK)
		return
	}

	params := mux.Vars(r)
	checkType := params["type"] // "vpn" or "ssh"
	if checkType != "vpn" && checkType != "ssh" {
		log.Printf("VpnController: path %s must end with ssh or vpn", r.URL.Path)
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}
	if checkType == "vpn" && !v.config.EnableVPN {
		log.Print("VpnController: Received VPN request but ENABLEVPN is disabled")
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	} else if checkType == "ssh" && !v.config.EnableSSH {
		log.Print("VpnController: Received SSH request but ENABLESSH is disabled")
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	sshKey := getSSHKey(connRequest.SSHAuthInfo)
	if checkType == "ssh" && v.config.SSHRequireKey && sshKey == "" {
		log.Printf("VpnController: '%s' SSH request from %s (%s) didn't include any public key", connRequest.Identity, callerIP, connRequest.CallerName)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	userManager := userManager.New(v.db, v.config)
	user, session, allowed, err := userManager.CheckVpnSession(connRequest.Identity, connRequest.SourceIP)
	if err != nil {
		log.Printf("VpnController: Error checking user session: %s", err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if user == nil {
		log.Printf("VpnController: Received request for unknown identity '%s' from %s", connRequest.Identity, connRequest.SourceIP)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	auditEntry := models.ConnectionAuditEntry{
		Allowed:        allowed,
		Identity:       connRequest.Identity,
		ClientSourceIP: connRequest.SourceIP,
		CallerSourceIP: v.utils.GetClientIP(r),
		Type:           checkType,
	}

	auditEntry.UserID = &user.ID
	if allowed {
		auditEntry.SessionID = &session.ID
	}

	if allowed {
		if tx := v.db.Save(&auditEntry); tx.Error != nil {
			log.Printf("VpnController: error saving connection audit entry for %s: %s", user.Email, tx.Error.Error())
		}
		http.Error(w, fmt.Sprintf("Ok %s", time.Since(start)), http.StatusOK)
		return
	}

	_, notifUniqueID, err := v.notificationsManager.NotifyUser(user, connRequest.SourceIP)
	hasValidBrowserSession := v.notificationsManager.WaitForBrowserProof(user, connRequest.SourceIP, *notifUniqueID)
	auditEntry.Allowed = hasValidBrowserSession
	if tx := v.db.Save(&auditEntry); tx.Error != nil {
		log.Printf("VpnController: error saving connection audit entry for %s: %s", user.Email, tx.Error.Error())
	}

	if !hasValidBrowserSession {
		log.Printf("VpnController: No valid session found for user %s from %s", connRequest.Identity, connRequest.SourceIP)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	// Create a new VPNSession
	if err := userManager.CreateVpnSession(user, connRequest.SourceIP); err != nil {
		log.Printf("VpnController: error creating VPN session: %s", err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	log.Printf("VpnController: user %s VPN session extended from valid Web session.", user.Email)
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

func getSSHKey(sshAuthInfo string) string {
	authInfoList := strings.Split(sshAuthInfo, ",")
	for idx, val := range authInfoList {
		if val == "publickey" {
			// Format is "publickey key_type key_value "
			return authInfoList[idx+2]
		}
	}
	return ""
}
