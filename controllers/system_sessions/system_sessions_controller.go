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

type SystemSessionController struct {
	db                   *gorm.DB
	config               *models.Config
	notificationsManager *services.NotificationsManager
	utils                *utils.Utils
}

var vpnAllowedRanges []*net.IPNet
var sshAllowedRanges []*net.IPNet

// New creates an instance of the controller and sets its DB handle
func New(db *gorm.DB, config *models.Config, notificationsManager *services.NotificationsManager) (*SystemSessionController, error) {
	if len(config.SSHAllowedSourceIPs) > 0 {
		for _, allowedRange := range config.SSHAllowedSourceIPs {
			_, allowedsubnet, err := net.ParseCIDR(allowedRange)
			if err != nil {
				return nil, err
			}
			sshAllowedRanges = append(sshAllowedRanges, allowedsubnet)
		}
	}
	if len(config.VPNCheckAllowedIPs) > 0 {
		for _, allowedRange := range config.VPNCheckAllowedIPs {
			_, allowedsubnet, err := net.ParseCIDR(allowedRange)
			if err != nil {
				return nil, err
			}
			vpnAllowedRanges = append(vpnAllowedRanges, allowedsubnet)
		}
	}
	return &SystemSessionController{
		db:                   db,
		config:               config,
		utils:                utils.New(config),
		notificationsManager: notificationsManager,
	}, nil
}

// ServerConnectionRequest is what is received from the Strongswan `ext-auth` script
// or pam_exec module.
type ServerConnectionRequest struct {
	Identity    string // The user identity as seen by remote SSH/VPN server
	SourceIP    string // The user source IP
	SSHAuthInfo string // Value of SSH_AUTH_INFO_0, line returns replaced with commas
	CallerName  string // The name or hostname of the caller (Hostname for SSH)
}

func (v *SystemSessionController) CheckSession(w http.ResponseWriter, r *http.Request) {
	start := time.Now() // report time taken to verify user for debugging purposes
	_, password, _ := r.BasicAuth()
	if password != v.config.RemoteAuthCheckPassword {
		log.Print("SystemSessionController: password does not match REMOTE_AUTH_CHECK_PASSWORD")
		http.Error(w, "Invalid REMOTE_AUTH_CHECK_PASSWORD", http.StatusForbidden)
		return
	}

	var connRequest ServerConnectionRequest
	err := json.NewDecoder(r.Body).Decode(&connRequest)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if connRequest.Identity == "" {
		http.Error(w, "Empty `Identity` field", http.StatusBadRequest)
		return
	}
	// Early exit if identity is excluded from any additional auth.
	if contains(v.config.ExcludedIdentities, connRequest.Identity) {
		http.Error(w, "Excluded", http.StatusOK)
		return
	}

	callerIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	params := mux.Vars(r)
	checkType := params["type"] // "vpn" or "ssh"
	if checkType != "vpn" && checkType != "ssh" {
		log.Printf("SystemSessionController: path %s must end with ssh or vpn", r.URL.Path)
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}
	if checkType == "vpn" && !v.config.EnableVPN {
		log.Print("SystemSessionController: Received VPN request but ENABLE_VPN is disabled")
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	} else if checkType == "ssh" {
		if !v.config.EnableSSH {
			log.Print("SystemSessionController: Received SSH request but ENABLE_SSH is disabled")
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		if connRequest.SSHAuthInfo == "" {
			log.Printf("SystemSessionController: Received SSH request for '%s' from %s but SSH key is empty", connRequest.Identity, callerIP)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
	}

	if checkType == "vpn" && len(vpnAllowedRanges) > 0 {
		// This checks if the VPN source IP is allowed to call the endpoint
		allowed := false
		ip := net.ParseIP(callerIP)
		for _, allowedRange := range vpnAllowedRanges {
			if allowedRange.Contains(ip) {
				allowed = true
				break
			}
		}
		if !allowed {
			log.Printf("SystemSessionController: source IP %s is not in VPN_CHECK_ALLOWED_IPS allowed list", callerIP)
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}

	} else if checkType == "ssh" && len(sshAllowedRanges) > 0 {
		// This checks if the SSH client source IP is allowed
		allowed := false
		ip := net.ParseIP(connRequest.SourceIP)
		for _, allowedRange := range sshAllowedRanges {
			if allowedRange.Contains(ip) {
				allowed = true
				break
			}
		}
		if !allowed {
			log.Printf("SystemSessionController: source IP %s is not in SSH_ALLOWED_SOURCE_IPS list", callerIP)
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
	}

	userManager := userManager.New(v.db, v.config)
	var sessionIdentity string
	if checkType == "ssh" { // the connecting user identity becomes the ssh key
		sessionIdentity = getSSHKey(connRequest.SSHAuthInfo)
	} else {
		sessionIdentity = connRequest.Identity
	}

	session, allowed, err := userManager.CheckSystemSession(checkType, sessionIdentity, connRequest.SourceIP)
	if err != nil {
		log.Printf("SystemSessionController: Error checking %s user session: %s", checkType, err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	var user *models.User
	if session != nil {
		user, err = userManager.GetById(*session.UserID)
	} else if checkType == "vpn" {
		user, err = userManager.Get(connRequest.Identity)
	} else if checkType == "ssh" {
		user = v.checkSSHSession(connRequest, w, r)
		if user == nil {
			return
		}
	}
	if user == nil {
		log.Printf("SystemSessionController: Received %s request for unknown identity '%s' from %s", checkType, connRequest.Identity, connRequest.SourceIP)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	auditEntry := models.ConnectionAuditEntry{
		Allowed:        allowed,
		Identity:       sessionIdentity,
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
			log.Printf("SystemSessionController: error saving %s connection audit entry for %s: %s", checkType, connRequest.Identity, tx.Error.Error())
		}
		http.Error(w, fmt.Sprintf("Ok %s", time.Since(start)), http.StatusOK)
		return
	}

	var connectionName string
	if checkType == "vpn" {
		if connRequest.CallerName == "" {
			connectionName = v.config.OrgName
		} else {
			connectionName = connRequest.CallerName
		}
		connectionName = "🔗 " + connectionName
	} else {
		connectionName = fmt.Sprintf("🖥️ %s (%s)", connRequest.CallerName, callerIP)
	}

	_, notifUniqueID, notifErr := v.notificationsManager.NotifyUser(checkType, connectionName, user)
	hasValidBrowserSession := v.notificationsManager.WaitForBrowserProof(checkType, user, *notifUniqueID, []*net.IPNet{})
	if notifErr != nil {
		log.Printf("SystemSessionController: error notifying browser for %s: %s", user.Email, notifErr.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	auditEntry.Allowed = hasValidBrowserSession

	if !hasValidBrowserSession {
		log.Printf("SystemSessionController: No valid session found for user %s from %s", connRequest.Identity, connRequest.SourceIP)
		http.Error(w, v.config.BaseURL.String(), http.StatusUnauthorized)
		if tx := v.db.Save(&auditEntry); tx.Error != nil {
			log.Printf("SystemSessionController: error saving %s connection audit entry for %s: %s", checkType, connRequest.Identity, tx.Error.Error())
		}
		return
	}

	// Create a new RemoteSession
	newSession, sessionCreateError := userManager.CreateSystemSession(checkType, user, sessionIdentity, connRequest.SourceIP)
	if sessionCreateError != nil {
		log.Printf("SystemSessionController: error creating %s session: %s", checkType, err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	auditEntry.SessionID = &newSession.ID
	if tx := v.db.Create(&auditEntry); tx.Error != nil {
		log.Printf("SystemSessionController: error saving %s connection audit entry for %s: %s", checkType, connRequest.Identity, tx.Error.Error())
	}

	log.Printf("SystemSessionController: %s session for %s extended from valid Web session.", checkType, user.Email)
	http.Error(w, fmt.Sprintf("Ok %s", time.Since(start)), http.StatusOK)
}

func (v *SystemSessionController) checkSSHSession(connRequest ServerConnectionRequest, w http.ResponseWriter, r *http.Request) *models.User {
	callerIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	sshKey := getSSHKey(connRequest.SSHAuthInfo)
	if sshKey == "" {
		log.Printf("SystemSessionController: '%s' SSH request from %s (%s) didn't include any public key", connRequest.Identity, callerIP, connRequest.CallerName)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return nil
	}

	userManager := userManager.New(v.db, v.config)
	sshIdentity, err := userManager.GetSSHIdentity(connRequest.Identity, sshKey)
	if err != nil {
		log.Printf("SystemSessionController: Error checking SSH identity for Unix user '%s' : %s", connRequest.Identity, err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return nil
	}

	// If it's the first time we see the key and/or username, reply with a one-time code
	//  to tie the username+key to a known and authenticated User.
	if sshIdentity == nil {
		otc, err := userManager.CreateIdentity(connRequest.Identity, sshKey)
		if err != nil {
			log.Printf("SystemSessionController: Error creating SSH identity for Unix user %s : %s", connRequest.Identity, err.Error())
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return nil
		}

		log.Printf("SystemSessionController: SSH identity for Unix user '%s' is unknown, sending one-time validation challenge", connRequest.Identity)
		http.Error(w, fmt.Sprintf("%s/addSSHKey %s", v.config.BaseURL, *otc), http.StatusNotAcceptable)
		return nil
	}
	user := sshIdentity.User
	if user == nil {
		log.Printf("SystemSessionController: Valid SSH identity for Unix user %s doesn't match any User", connRequest.Identity)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return nil
	}
	return user
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
	for _, val := range authInfoList {
		authInfo := strings.Split(val, " ")
		if len(authInfo) == 3 && authInfo[0] == "publickey" {
			// Format is "publickey key_type key_value"
			return authInfo[2]
		}
	}
	return ""
}
