package controllers

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/SherClockHolmes/webpush-go"
	"github.com/asaskevich/EventBus"
	"github.com/m-barthelemy/vpn-webauth/models"
	userManager "github.com/m-barthelemy/vpn-webauth/services"
	"github.com/m-barthelemy/vpn-webauth/utils"
	"gorm.io/gorm"
)

type UserController struct {
	db        *gorm.DB
	config    *models.Config
	bus       *EventBus.Bus
	vapidKeys VapidKeys
}

type VapidKeys struct {
	PublicKey  string `json:"public_key"`
	privateKey string
	subscriber string
}

// New creates an instance of the controller and sets its DB handle
func New(db *gorm.DB, config *models.Config, bus *EventBus.Bus) *UserController {
	vapidKeys := VapidKeys{subscriber: config.AdminEmail, PublicKey: config.VapidPublicKey, privateKey: config.VapidPrivateKey}
	return &UserController{db: db, config: config, bus: bus, vapidKeys: vapidKeys}
}

func (u *UserController) GetPushSubscriptionKey(w http.ResponseWriter, r *http.Request) {
	var email = r.Context().Value("identity").(string)
	var sessionHasMFA = r.Context().Value("hasMfa").(bool)

	userManager := userManager.New(u.db, u.config)
	user, err := userManager.Get(email)
	if err != nil {
		log.Printf("UserController: Error fetching user %s: %s", email, err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Deny if the user has enabled MFA but hasn't logged in fully
	if user.HasMFA() && !sessionHasMFA {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	keyInfo := VapidKeys{PublicKey: u.vapidKeys.PublicKey}
	utils.JSONResponse(w, keyInfo, http.StatusOK)
}

func (u *UserController) RegisterPushSubscription(w http.ResponseWriter, r *http.Request) {
	var email = r.Context().Value("identity").(string)
	var sessionHasMFA = r.Context().Value("hasMfa").(bool)

	r.Body = http.MaxBytesReader(w, r.Body, u.config.MaxBodySize) // Refuse request with big body

	userManager := userManager.New(u.db, u.config)
	user, err := userManager.Get(email)
	if err != nil {
		log.Printf("UserController: Error fetching user %s: %s", email, err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Deny if the user has enabled MFA but hasn't logged in fully
	if user.HasMFA() && !sessionHasMFA {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	// read raw body for hashing the subscription
	var bodyBytes []byte
	if r.Body != nil {
		bodyBytes, _ = ioutil.ReadAll(r.Body)
	}
	// Restore the io.ReadCloser to its original state
	r.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))

	// Validate that what we receive is a valid web push subscription
	subscription := &webpush.Subscription{}
	if err := json.NewDecoder(r.Body).Decode(&subscription); err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	hash := sha256.Sum256(bodyBytes)
	userSubscription := models.UserSubscription{
		UserID: user.ID,
		Hash:   fmt.Sprintf("%x\n", hash),
		Data:   string(bodyBytes[:]),
	}
	if _, err := userManager.AddUserSubscription(user, &userSubscription); err != nil {
		log.Printf("UserController: Error saving user subscription for %s: %s", email, err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	log.Printf("UserController: User %s subscribed to push notifications", user.Email)
}

// RefreshAuth is called by the browser worker when it receives a push notification asking it to do so.
// The push notification is triggered by a VPN connection attempt when there is valid VPN "session".
// If we still have a valid web session, we can notify the VPN controller to create a new VPN session
// transparently and accept the connection attempt.
func (u *UserController) RefreshAuth(w http.ResponseWriter, r *http.Request) {
	sourceIP := utils.New(u.config).GetClientIP(r)
	eventBus := *u.bus

	var email, userOk = r.Context().Value("identity").(string)
	if !userOk {
		eventBus.Publish(fmt.Sprintf("%s:%s", email, sourceIP), false)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	var sessionHasMFA, mfaOk = r.Context().Value("hasMfa").(bool)
	if u.config.EnforceMFA && (!mfaOk || !sessionHasMFA) {
		eventBus.Publish(fmt.Sprintf("%s:%s", email, sourceIP), false)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	log.Printf("UserController: User %s requesting new VPN session still has a valid web session, notifying VPNController", email)
	eventBus.Publish(fmt.Sprintf("%s:%s", email, sourceIP), true)
}
