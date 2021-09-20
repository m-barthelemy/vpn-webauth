package services

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/SherClockHolmes/webpush-go"
	"github.com/asaskevich/EventBus"
	"github.com/gofrs/uuid"
	"github.com/m-barthelemy/vpn-webauth/controllers/sse"
	"github.com/m-barthelemy/vpn-webauth/models"

	"gorm.io/gorm"
)

type NotificationsManager struct {
	db     *gorm.DB
	config *models.Config
	bus    *EventBus.Bus
}

type SessionInfo struct {
	Identity            string // user identity (email)
	Issuer              string // Name of the connection
	EnableNotifications bool
	FullyAuthenticated  bool   // Whether authentication fully complies with requirement (ie MFA)
	SessionExpiry       int64  // Unix timestamp
	IconURL             string // LOGOURL
}

// New creates an instance of the controller and sets its DB handle
func NewNotificationsManager(db *gorm.DB, config *models.Config, bus *EventBus.Bus) *NotificationsManager {
	return &NotificationsManager{db: db, config: config, bus: bus}
}

func (n *NotificationsManager) NotifyUser(user *models.User, sourceIP string) (bool, *uuid.UUID, error) {
	var subscriptions []models.UserSubscription
	minUsedAt := time.Now().AddDate(0, -3, 0)
	if result := n.db.Where("user_id = ? AND last_used_at > ?", user.ID.String(), minUsedAt).Find(&subscriptions); result.Error != nil {
		return false, nil, result.Error
	}

	// Nonce ensuring that "proof of session" received from browsers match a legitimate proof request
	// originating from this app.
	notifId, _ := uuid.NewV4()

	dp := NewDataProtector(n.config)
	deletedCount := 0
	var nonce struct {
		Nonce  uuid.UUID
		Issuer string
	}
	nonce.Nonce = notifId
	nonce.Issuer = n.config.Issuer
	jsonNonce, err := json.Marshal(nonce)
	if err != nil {
		return false, &notifId, err
	}

	notified := false
	userManager := NewUserManager(n.db, n.config)
	for i, subscription := range subscriptions {
		pushSubscriptionRaw, err := dp.Decrypt(subscription.Data)
		if err != nil {
			return false, &notifId, err
		}
		pushSubscription := &webpush.Subscription{}
		if err := json.Unmarshal([]byte(pushSubscriptionRaw), &pushSubscription); err != nil {
			return false, &notifId, err
		}

		resp, err := webpush.SendNotification(jsonNonce, pushSubscription, &webpush.Options{
			Subscriber:      n.config.AdminEmail,
			VAPIDPublicKey:  n.config.VapidPublicKey,
			VAPIDPrivateKey: n.config.VapidPrivateKey,
			TTL:             60,
		})
		defer resp.Body.Close()

		// The push provider signals that the subscription is no longer active, so delete it.
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			if err := userManager.DeleteUserSubscription(&subscriptions[i]); err != nil {
				return false, &notifId, err
			}
			deletedCount++
		} else if err != nil {
			return false, &notifId, err
		}
		notified = true
	}
	if deletedCount > 0 {
		log.Printf("NotificationsManager: Deleted %d inactive push subscriptions for %s", deletedCount, user.Email)
	}

	// Also send to clients using SSE fallback
	msg := sse.SSEAuthRequestMessage{
		SourceIP: sourceIP,
		UserId:   user.ID,
		Message: sse.SSEMessage{
			Action: "Auth",
			Nonce:  notifId.String(),
			Issuer: n.config.Issuer,
		},
	}
	bus := *n.bus
	bus.Publish("sse", msg)

	return notified, &notifId, nil
}

// WaitForBrowserProof waits for browser to reply with a request having a valid session token, and a body
// containing the same nonce value that was sent with the Push or SSE notification.
func (n *NotificationsManager) WaitForBrowserProof(user *models.User, sourceIP string, nonce uuid.UUID) bool {
	channel := make(chan bool, 1)
	eventBus := *n.bus

	checkWebSessions := func(id uuid.UUID) {
		if id == nonce {
			channel <- true
		} else {
			log.Printf("NotificationsManager: invalid browser response for %s: nonce doesn't match expected value", user.Email)
			channel <- false
		}
	}

	hasValidBrowserSession := false
	// Background task that we can kill it after some time to avoid Strongswan hanging for too long
	go func() {
		eventBus.Subscribe(fmt.Sprintf("%s:%s", user.Email, sourceIP), checkWebSessions)
		eventBus.WaitAsync()
	}()
	select {
	case res := <-channel:
		hasValidBrowserSession = res
		if hasValidBrowserSession {
			break
		} // otherwise there can still be a browser having a valid session that has not yet replied.
	// Wait for a short interval to not clog the VPN server that waiting for a reply in blocking mode
	case <-time.After(n.config.WebSessionProofTimeout):
		log.Printf("NotificationsManager: No active web session replied on time for user %s", user.Email)
	}
	close(channel)
	eventBus.Unsubscribe(fmt.Sprintf("%s:%s", user.Email, sourceIP), checkWebSessions)

	return hasValidBrowserSession
}

func (n *NotificationsManager) PublishBrowserProof(identity string, sourceIP string, nonce uuid.UUID) {
	eventBus := *n.bus
	eventBus.Publish(fmt.Sprintf("%s:%s", identity, sourceIP), nonce)
}
