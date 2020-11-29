package controllers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/asaskevich/EventBus"
	"github.com/m-barthelemy/vpn-webauth/models"
	userManager "github.com/m-barthelemy/vpn-webauth/services"
	"github.com/m-barthelemy/vpn-webauth/utils"
	"gorm.io/gorm"
)

type VpnController struct {
	db     *gorm.DB
	config *models.Config
	bus    *EventBus.Bus
	utils  *utils.Utils
}

// New creates an instance of the controller and sets its DB handle
func New(db *gorm.DB, config *models.Config, bus *EventBus.Bus) *VpnController {
	return &VpnController{
		db:     db,
		config: config,
		bus:    bus,
		utils:  utils.New(config),
	}
}

// VpnConnectionRequest is what is received from the Stringswan `ext-auth` script request
type VpnConnectionRequest struct {
	Identity string
	SourceIP string
}

func (v *VpnController) CheckSession(w http.ResponseWriter, r *http.Request) {
	_, password, _ := r.BasicAuth()
	if password != v.config.VPNCheckPassword {
		log.Print("VpnController: password does not match VPNCHECKPASSWORD")
		http.Error(w, "Invalid VPNCHECKPASSWORD", http.StatusUnauthorized)
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

	userManager := userManager.New(v.db, v.config)
	user, session, allowed, err := userManager.CheckVpnSession(connRequest.Identity, connRequest.SourceIP, false)
	if err != nil {
		log.Printf("VpnController: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if session == nil {
		log.Printf("VpnController: no VPN session found for user %s, required reauth", connRequest.Identity)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	vpnConnection := models.VPNConnection{
		Identity:    connRequest.Identity,
		SourceIP:    connRequest.SourceIP,
		VPNSourceIP: v.utils.GetClientIP(r),
	}
	if user != nil {
		vpnConnection.UserID = &user.ID
	}
	if !allowed {
		vpnConnection.Allowed = false

	} else {
		vpnConnection.Allowed = true
		vpnConnection.VPNSessionID = &session.ID
	}

	v.db.Save(&vpnConnection)

	if allowed {
		http.Error(w, "Ok", http.StatusOK)
		return
	}

	// Ask any active user browser to send a request to confirm web session and source IP
	if err := userManager.NotifyUser(user, false); err != nil {
		log.Printf("VpnController: error notifying %s: %s", user.Email, err.Error())
	}

	channel := make(chan bool, 1)
	eventBus := *v.bus

	checkWebSessions := func(validSession bool) {
		if validSession {
			channel <- true
		} else {
			channel <- false
		}
	}

	hasValidBrowserSession := false

	// Background work so that we can kill it after some time
	go func() {
		eventBus.Subscribe(fmt.Sprintf("%s:%s", connRequest.Identity, connRequest.SourceIP), checkWebSessions)
		eventBus.WaitAsync()
	}()
	select {
	case res := <-channel:
		hasValidBrowserSession = res
		if hasValidBrowserSession {
			break
		} // otherwise there can still be a browser having a valid session that has not yet replied.
	// Wait for a short interval to not clog the VPN server that waiting for a reply in blocking mode
	case <-time.After(500 * time.Millisecond):
		log.Printf("VpnController: No active web session replied on time for user %s", connRequest.Identity)
	}
	close(channel)
	eventBus.Unsubscribe(fmt.Sprintf("%s:%s", connRequest.Identity, connRequest.SourceIP), checkWebSessions)

	if !hasValidBrowserSession {
		log.Printf("VpnController: No valid session found for user %s", connRequest.Identity)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	// Create a new VPNSession reusing the previous expired session MFA.
	userManager.CreateVpnSession(session.MFAID, user, connRequest.SourceIP)
	log.Printf("VpnController: user %s session extended from valid browser session.", user.Email)
}

func contains(arr []string, str string) bool {
	for _, a := range arr {
		if a == str {
			return true
		}
	}
	return false
}
