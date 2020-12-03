package services

import (
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/asaskevich/EventBus"
	"github.com/dgrijalva/jwt-go"
	"github.com/m-barthelemy/vpn-webauth/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type UserManager struct {
	db     *gorm.DB
	config *models.Config
}

var bus EventBus.Bus

// New creates an instance of UserManager and sets its DB handle
func New(db *gorm.DB, config *models.Config) *UserManager {
	bus = EventBus.New()
	return &UserManager{db: db, config: config}
}

func (m *UserManager) Get(email string) (*models.User, error) {
	var user models.User

	result := m.db.Preload("MFAs").Where("email = ?", email).First(&user)
	if result.Error != nil {
		return nil, result.Error
	}
	return &user, nil
}

// Check that the user exists and has a valid OTP setup.
// User is created if it doesn't exist.
// Returns false if the user doesn't have a verified TOTP secret
func (m *UserManager) CheckOrCreate(email string) (*models.User, error) {
	var user models.User

	result := m.db.Preload("MFAs").Where("email = ?", email).First(&user)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {

			user = models.User{Email: email}
			result := m.db.Create(&user)
			if result.Error != nil {
				return nil, result.Error
			}
			log.Printf("UserManager: Created new user %s", user.Email)
		} else {
			return nil, result.Error
		}
	}

	return &user, nil
}

func (m *UserManager) CheckVpnSession(identity string, ip string) (*models.User, *models.VpnSession, bool, error) {
	var session models.VpnSession
	var user models.User

	duration := m.config.VPNSessionValidity
	minDate := time.Now().Add(-duration)
	userResult := m.db.Where("email = ?", identity).First(&user)
	if userResult.Error != nil {
		if errors.Is(userResult.Error, gorm.ErrRecordNotFound) {
			return nil, nil, false, nil
		} else {
			return nil, nil, false, userResult.Error
		}
	}

	sessionResult := m.db.Order("created_at desc").Where("email = ? AND source_ip = ?", identity, ip).First(&session)
	if sessionResult.Error != nil {
		if errors.Is(sessionResult.Error, gorm.ErrRecordNotFound) {
			return &user, nil, false, nil
		} else {
			return &user, &session, false, sessionResult.Error
		}
	}
	isValid := (session.CreatedAt.After(minDate))
	return &user, &session, isValid, nil
}

// CreateVpnSession Creates a new VPN "Session" for the `User` from the specified IP address.
func (m *UserManager) CreateVpnSession(user *models.User, ip string) error {
	// First delete any existing session for the same user
	oldSession := models.VpnSession{Email: user.Email}
	deleteResult := m.db.Delete(&oldSession)
	if deleteResult.Error != nil {
		return deleteResult.Error
	}
	// Then create the new "session"
	var vpnSession = models.VpnSession{Email: user.Email, SourceIP: ip}
	result := m.db.Create(&vpnSession)
	if result.Error != nil {
		return result.Error
	}
	log.Printf("UserController: User %s created VPN session from %s", user.Email, ip)
	return nil
}

// AddMFA Creates a new `UserMFA`, and encrypts the `data` field
func (m *UserManager) AddMFA(user *models.User, mfaType string, data string, userAgent string) (*models.UserMFA, error) {
	// Cleanup any expired, non validated UserMFA
	_ = m.db.Delete(&models.UserMFA{}, "id = ? AND validated = ? AND expires_at < ?", user.ID, false, time.Now())

	userMFA := models.UserMFA{
		UserID:    user.ID,
		Validated: false,
		ExpiresAt: time.Now().Add(time.Minute * 5),
		Type:      mfaType,
		UserAgent: userAgent,
	}

	if data != "" {
		dp := NewDataProtector(m.config)
		encryptedData, err := dp.Encrypt(data)
		if err != nil {
			return nil, err
		}
		userMFA.Data = encryptedData
	}

	result := m.db.Create(&userMFA)
	if result.Error != nil {
		return nil, result.Error
	}
	log.Printf("UserManager: Created %s UserMFA for %s", mfaType, user.Email)

	return &userMFA, nil
}

// UpdateMFA updates a `UserMFA`.
// It assumes that the `data` field need to be encrypted again.
func (m *UserManager) UpdateMFA(userMFA models.UserMFA) (*models.UserMFA, error) {
	if userMFA.Data != "" {
		dp := NewDataProtector(m.config)
		encryptedData, err := dp.Encrypt(userMFA.Data)
		if err != nil {
			return nil, err
		}
		userMFA.Data = encryptedData
	}

	result := m.db.Save(&userMFA)
	if result.Error != nil {
		return nil, result.Error
	}

	return &userMFA, nil
}

// ValidateMFA sets the UserMFA as validated and saves any data if present.
func (m *UserManager) ValidateMFA(mfa *models.UserMFA, data string) (*models.UserMFA, error) {
	var userMFA models.UserMFA
	result := m.db.Where("id = ? AND validated = ? AND expires_at > ?", mfa.ID, false, time.Now()).First(&userMFA)
	if result.Error != nil {
		return nil, result.Error
	}

	userMFA.Validated = true
	userMFA.ExpiresAt = time.Now().AddDate(10, 0, 0)

	if data != "" {
		dp := NewDataProtector(m.config)
		encryptedData, err := dp.Encrypt(data)
		if err != nil {
			return nil, err
		}
		userMFA.Data = encryptedData
	}

	if result := m.db.Save(&userMFA); result.Error != nil {
		return nil, result.Error
	}

	log.Printf("UserManager: Validated %s UserMFA for User %s", userMFA.Type, userMFA.ID.String())
	return &userMFA, nil
}

func (m *UserManager) AddUserSubscription(user *models.User, subscription *models.UserSubscription) (*models.UserSubscription, error) {
	subscription.LastUsedAt = time.Now()
	if subscription.Data != "" {
		dp := NewDataProtector(m.config)
		encryptedData, err := dp.Encrypt(subscription.Data)
		if err != nil {
			return nil, err
		}
		subscription.Data = encryptedData
	}

	// Every time a Service worker is activated, we will try to register a subscription
	// so duplicates are expected
	// In that case we want to update the CreatedAt field to be able to detect
	// old => inactive subscriptions
	result := m.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "hash"}},
		DoUpdates: clause.AssignmentColumns([]string{"last_used_at"}),
	}).Create(&subscription)
	if result.Error != nil {
		return nil, result.Error
	}
	log.Printf("UserManager: Created Web push subscription for %s", user.Email)

	return subscription, nil
}

func (m *UserManager) DeleteUserSubscription(subscription *models.UserSubscription) error {
	result := m.db.Delete(&models.UserSubscription{}, "hash = ?", subscription.Hash)
	return result.Error
}

// TODO: Move to a NotificationsManager service.
/*func (m *UserManager) NotifyUser(user *models.User, notifId uuid.UUID, sourceIP string) (bool, error) {
	var subscriptions []models.UserSubscription
	minUsedAt := time.Now().AddDate(0, -3, 0)
	if result := m.db.Where("user_id = ? AND last_used_at > ?", user.ID.String(), minUsedAt).Find(&subscriptions); result.Error != nil {
		return false, result.Error
	}

	dp := NewDataProtector(m.config)
	deletedCount := 0
	var nonce struct {
		Nonce  uuid.UUID
		Issuer string
	}
	nonce.Nonce = notifId
	nonce.Issuer = m.config.Issuer
	jsonNonce, err := json.Marshal(nonce)
	if err != nil {
		return false, err
	}

	notified := false
	for i, subscription := range subscriptions {
		pushSubscriptionRaw, err := dp.Decrypt(subscription.Data)
		if err != nil {
			return false, err
		}
		pushSubscription := &webpush.Subscription{}
		if err := json.Unmarshal([]byte(pushSubscriptionRaw), &pushSubscription); err != nil {
			return false, err
		}

		resp, err := webpush.SendNotification(jsonNonce, pushSubscription, &webpush.Options{
			Subscriber:      m.config.AdminEmail,
			VAPIDPublicKey:  m.config.VapidPublicKey,
			VAPIDPrivateKey: m.config.VapidPrivateKey,
			TTL:             120,
		})
		defer resp.Body.Close()

		// The push provider signals that the subscription is no longer active, so delete it.
		if resp.StatusCode >= 400 && resp.StatusCode <= 500 {
			if err := m.DeleteUserSubscription(&subscriptions[i]); err != nil {
				return false, err
			}
			deletedCount++
		} else if err != nil {
			return false, err
		}
		notified = true
	}

	if deletedCount > 0 {
		log.Printf("UserManager: Deleted %d inactive push subscriptions for %s", deletedCount, user.Email)
	}
	return notified, nil
} */

// Claims is used Used for the session cookie
type Claims struct {
	Username string `json:"username"`
	HasMFA   bool   `json:"has_mfa"`
	jwt.StandardClaims
}

func (m *UserManager) CreateSession(user *models.User, hasMFA bool, w http.ResponseWriter) error {
	jwtKey := []byte(m.config.SigningKey)
	cookieName := "vpnwa_session"
	if m.config.SSLMode != "off" {
		cookieName = "__Host-" + cookieName
	}
	expirationTime := time.Now().Add(m.config.WebSessionValidity)
	claims := &Claims{
		Username: user.Email,
		HasMFA:   hasMFA,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return err
	}
	cookie := http.Cookie{
		Name:     cookieName,
		Value:    tokenString,
		Expires:  expirationTime,
		HttpOnly: true,
		Path:     "/",
		Secure:   m.config.SSLMode != "off",
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, &cookie)
	return m.createIdentifierCookie(user, w)
}

// CreateIdentifierCookie creates a long-term, non-authorizing cookie identifying the user
//  for desktop notifications.
func (m *UserManager) createIdentifierCookie(user *models.User, w http.ResponseWriter) error {
	jwtKey := []byte(m.config.SigningKey)
	cookieName := "vpnwa_identified_user"
	if m.config.SSLMode != "off" {
		cookieName = "__Host-" + cookieName
	}
	expirationTime := time.Now().AddDate(0, 3, 0) // In 3 months
	claims := &Claims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
			Subject:   user.ID.String(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return err
	}
	cookie := http.Cookie{
		Name:     cookieName,
		Value:    tokenString,
		Expires:  expirationTime,
		HttpOnly: true,
		Path:     "/",
		Secure:   m.config.SSLMode != "off",
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, &cookie)
	return nil
}

// CleanupConnections deletes connection entries older than configured value
func (m *UserManager) CleanupConnections() error {
	expireDate := time.Now().AddDate(0, 0, -m.config.ConnectionsRetention)
	result := m.db.Delete(&models.VPNConnection{}, "created_at < ?", expireDate)
	return result.Error
}
