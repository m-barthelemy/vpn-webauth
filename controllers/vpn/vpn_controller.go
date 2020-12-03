package controllers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/asaskevich/EventBus"
	"github.com/m-barthelemy/vpn-webauth/models"
	"github.com/m-barthelemy/vpn-webauth/services"
	userManager "github.com/m-barthelemy/vpn-webauth/services"
	"github.com/m-barthelemy/vpn-webauth/utils"
	"gorm.io/gorm"
)

type VpnController struct {
	db                   *gorm.DB
	config               *models.Config
	bus                  *EventBus.Bus
	notificationsManager *services.NotificationsManager
	utils                *utils.Utils
}

// New creates an instance of the controller and sets its DB handle
func New(db *gorm.DB, config *models.Config, notificationsManager *services.NotificationsManager, bus *EventBus.Bus) *VpnController {
	return &VpnController{
		db:                   db,
		config:               config,
		bus:                  bus,
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
		log.Print("VpnController: password does not match VPNCHECKPASSWORD")
		http.Error(w, "Invalid VPNCHECKPASSWORD", http.StatusForbidden)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, v.config.MaxBodySize) // Refuse request with big body

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
	user, session, allowed, err := userManager.CheckVpnSession(connRequest.Identity, connRequest.SourceIP)
	if err != nil {
		log.Printf("VpnController: Error checking user session: %s", err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	vpnConnection := models.VPNConnection{
		Allowed:     allowed,
		Identity:    connRequest.Identity,
		SourceIP:    connRequest.SourceIP,
		VPNSourceIP: v.utils.GetClientIP(r),
	}
	if user != nil {
		vpnConnection.UserID = &user.ID
	}
	if allowed {
		vpnConnection.VPNSessionID = &session.ID
	}

	if allowed {
		if tx := v.db.Save(&vpnConnection); tx.Error != nil {
			log.Printf("VpnController: error saving Vpnconnection audit entry for %s: %s", user.Email, tx.Error.Error())
		}
		http.Error(w, fmt.Sprintf("Ok %s", time.Since(start)), http.StatusOK)
		return
	}

	hasValidBrowserSession := false
	// Ask any active user browser to send a request to confirm web session and source IP
	/*notifUniqueID, _ := uuid.NewV4() // unique id that must be present in browser request, for additional security
	notified := false
	if v.config.EnableNotifications {
		notified, err = userManager.NotifyUser(user, notifUniqueID, connRequest.SourceIP)
		if err != nil {
			log.Printf("VpnController: error notifying %s: %s", user.Email, err.Error())
		}
		// Also send to SSe fallback
		msg := sse.SSEAuthRequestMessage{
			SourceIP: connRequest.SourceIP,
			UserId:   user.ID,
			Message: sse.SSEMessage{
				Action: "Auth",
				Nonce:  notifUniqueID.String(),
				Issuer: v.config.Issuer,
			},
		}
		bus := *v.bus
		bus.Publish("sse", msg)
		notified = true // For now assume SSE always successfully notified a client
		// TODO: report real SSE notify status
	}
	*/
	notified, notifUniqueID, err := v.notificationsManager.NotifyUser(user, connRequest.SourceIP)
	if notified {
		/*channel := make(chan bool, 1)
		eventBus := *v.bus

		checkWebSessions := func(nonce uuid.UUID) {
			if nonce == *notifUniqueID {
				channel <- true
			} else {
				log.Printf("VpnController: invalid browser response for %s: nonce doesn't match expected value", user.Email)
				channel <- false
			}
		}

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

		vpnConnection.Allowed = hasValidBrowserSession*/

	}

	hasValidBrowserSession = v.notificationsManager.WaitForBrowserProof(user, connRequest.SourceIP, *notifUniqueID)
	vpnConnection.Allowed = hasValidBrowserSession
	if tx := v.db.Save(&vpnConnection); tx.Error != nil {
		log.Printf("VpnController: error saving Vpnconnection audit entry for %s: %s", user.Email, tx.Error.Error())
	}

	if !hasValidBrowserSession {
		log.Printf("VpnController: No valid session found for user %s", connRequest.Identity)
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
