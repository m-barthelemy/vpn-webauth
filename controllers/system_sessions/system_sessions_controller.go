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

// New creates an instance of the controller and sets its DB handle
func New(db *gorm.DB, config *models.Config, notificationsManager *services.NotificationsManager) *SystemSessionController {
	return &SystemSessionController{
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

func (v *SystemSessionController) CheckSession(w http.ResponseWriter, r *http.Request) {
	start := time.Now() // report time taken to verify user for debugging purposes
	_, password, _ := r.BasicAuth()
	if password != v.config.RemoteAuthCheckPassword {
		log.Print("SystemSessionController: password does not match REMOTEAUTHCHECKPASSWORD")
		http.Error(w, "Invalid REMOTEAUTHCHECKPASSWORD", http.StatusForbidden)
		return
	}
	callerIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	// TODO: how does that apply to SSH connections?
	if len(v.config.VPNCheckAllowedIPs) > 0 {
		if !contains(v.config.VPNCheckAllowedIPs, callerIP) {
			log.Printf("SystemSessionController: source IP %s is not in VPNCHECKALLOWEDIPS allowed list", callerIP)
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
		http.Error(w, "Empty `Identity` field", http.StatusBadRequest)
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
		log.Printf("SystemSessionController: path %s must end with ssh or vpn", r.URL.Path)
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}
	if checkType == "vpn" && !v.config.EnableVPN {
		log.Print("SystemSessionController: Received VPN request but ENABLEVPN is disabled")
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	} else if checkType == "ssh" {
		if !v.config.EnableSSH {
			log.Print("SystemSessionController: Received SSH request but ENABLESSH is disabled")
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		if connRequest.SSHAuthInfo == "" {
			log.Printf("SystemSessionController: Received SSH request for '%s' from %s but SSH key is empty", connRequest.Identity, callerIP)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
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

	user, session, allowed, err := userManager.CheckSystemSession(checkType, sessionIdentity, connRequest.SourceIP)
	if err != nil {
		log.Printf("SystemSessionController: Error checking %s user session: %s", checkType, err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if user == nil {
		if checkType == "vpn" {
			log.Printf("SystemSessionController: Received request for unknown %s identity '%s' from %s", checkType, connRequest.Identity, connRequest.SourceIP)
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		} else if checkType == "ssh" {
			user = v.checkSSHSession(connRequest, w, r)
			if user == nil {
				return
			}
		}
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
	_, notifUniqueID, err := v.notificationsManager.NotifyUser(checkType, connectionName, user, connRequest.SourceIP)
	hasValidBrowserSession := v.notificationsManager.WaitForBrowserProof(checkType, user, connRequest.SourceIP, *notifUniqueID)
	auditEntry.Allowed = hasValidBrowserSession

	if !hasValidBrowserSession {
		log.Printf("SystemSessionController: No valid session found for user %s from %s", connRequest.Identity, connRequest.SourceIP)
		http.Error(w, v.config.RedirectDomain.String(), http.StatusUnauthorized)
		if tx := v.db.Save(&auditEntry); tx.Error != nil {
			log.Printf("SystemSessionController: error saving %s connection audit entry for %s: %s", checkType, connRequest.Identity, tx.Error.Error())
		}
		return
	}

	// Create a new VPNSession
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
		http.Error(w, fmt.Sprintf("%s/addSSHKey %s", v.config.RedirectDomain, *otc), http.StatusNotAcceptable)
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
