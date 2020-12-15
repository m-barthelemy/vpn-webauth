package services

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gofrs/uuid"
	"github.com/m-barthelemy/vpn-webauth/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type UserManager struct {
	db     *gorm.DB
	config *models.Config
}

// New creates an instance of UserManager and sets its DB handle
func New(db *gorm.DB, config *models.Config) *UserManager {
	return &UserManager{db: db, config: config}
}

func (m *UserManager) Get(email string) (*models.User, error) {
	var user models.User

	result := m.db.Preload("MFAs").Preload("Identities").Where("email = ?", email).First(&user)
	if result.Error != nil {
		return nil, result.Error
	}
	return &user, nil
}

func (m *UserManager) GetById(id uuid.UUID) (*models.User, error) {
	var user models.User

	result := m.db.Preload("MFAs").Preload("Identities").Where("id = ?", id).First(&user)
	if result.Error != nil {
		return nil, result.Error
	}
	return &user, nil
}

func (m *UserManager) GetSSHIdentity(userName string, publicKey string) (*models.UserIdentity, error) {
	var identity models.UserIdentity
	result := m.db.Preload("User").Where("type = 'ssh' AND name = ? AND public_key = ? and validated = true", userName, publicKey).First(&identity)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, result.Error
	}
	return &identity, nil
}

// CreateIdentity creates a new UserIdentity for the specified username
// and returns the one-time code for the User to validate.
func (m *UserManager) CreateIdentity(userName string, publicKey string) (*string, error) {
	b := make([]byte, 32)
	rand.Read(b)
	//otc := base64.URLEncoding.EncodeToString(b)
	otc := base64.RawStdEncoding.EncodeToString(b)
	// remove / and + to ease copy/pasting of the challenge
	otc = strings.ReplaceAll(otc, "/", "0")
	otc = strings.ReplaceAll(otc, "+", "0")
	runes := []rune(otc)
	// Ensure temporary code is always 32 chars
	otc = string(runes[0:32])

	// We must later find the identity pending validation by its temporary code
	// so a simple hash is the only way to do so while offering _some_ kind of
	// protection for the temporary code
	hashedOTCBytes := sha256.Sum256([]byte(otc))
	//hashedOTCBytes := hashedOTCBytes32[:]
	hashedOTC := fmt.Sprintf("%x", hashedOTCBytes)

	identity := models.UserIdentity{
		Name:           userName,
		PublicKey:      publicKey,
		Validated:      false,
		ValidationData: hashedOTC,
		Type:           "ssh",
	}
	result := m.db.Create(&identity)
	if result.Error != nil {
		return nil, result.Error
	}
	return &otc, nil
}

func (m *UserManager) ValidateIdentity(user *models.User, otc string) (*models.UserIdentity, error) {
	hashedOTCBytes := sha256.Sum256([]byte(otc))
	//hashedOTCBytes := hashedOTCBytes32[:]
	hashedOTC := fmt.Sprintf("%x", hashedOTCBytes)

	var identity models.UserIdentity
	validity := time.Now().Add(-3 * time.Minute)
	result := m.db.Where("validation_data = ? and validated = false and created_at > ?", hashedOTC, validity).First(&identity)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, result.Error
	}

	identity.UserID = &user.ID
	identity.ValidationData = ""
	identity.Validated = true
	tx := m.db.Save(&identity)
	if tx.Error != nil {
		return nil, tx.Error
	}
	identity.User = user
	// Cleanup expired and never validated identities
	_ = m.db.Delete(&models.UserIdentity{}, "validated = false AND created_at < ?", validity)
	return &identity, nil

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

func (m *UserManager) CheckSystemSession(connectionType string, identity string, ip string) (*models.RemoteSession, bool, error) {
	var session models.RemoteSession
	//var user models.User

	duration := m.config.RemoteSessionValidity
	minDate := time.Now().Add(-duration)

	sessionResult := m.db.Order("created_at desc").Where("type = ? AND identity = ? AND source_ip = ?", connectionType, identity, ip).First(&session)
	if sessionResult.Error != nil {
		if !errors.Is(sessionResult.Error, gorm.ErrRecordNotFound) {
			return &session, false, sessionResult.Error
		} else {
			return nil, false, nil
		}
	}
	isValid := (session.CreatedAt.After(minDate))

	/*userResult := m.db.Where("id = ?", session.UserID).First(&user)
	if userResult.Error != nil {
		if errors.Is(userResult.Error, gorm.ErrRecordNotFound) {
			return nil, &session, isValid, nil
		} else {
			return nil, &session, isValid, userResult.Error
		}
	}

	return &user, &session, isValid, nil*/
	return &session, isValid, nil
}

// CreateSystemSession Creates a new VPN "Session" for the `User` from the specified IP address.
func (m *UserManager) CreateSystemSession(connectionType string, user *models.User, identity string, ip string) (*models.RemoteSession, error) {
	// First delete any existing session for the same user
	oldSession := models.RemoteSession{Type: connectionType, Identity: identity}
	deleteResult := m.db.Delete(&oldSession)
	if deleteResult.Error != nil {
		return nil, deleteResult.Error
	}

	// Then create the new "session"
	var remoteSession = models.RemoteSession{Type: connectionType, Identity: identity, SourceIP: ip, UserID: &user.ID}
	result := m.db.Create(&remoteSession)
	if result.Error != nil {
		return nil, result.Error
	}
	log.Printf("UserController: User %s created %s session from %s", user.Email, connectionType, ip)
	return &remoteSession, nil
}

func (m *UserManager) DeleteVpnSession(user *models.User, ip string) error {
	// First delete any existing session for the same user
	//oldSession := models.RemoteSession{UserID: &user.ID, SourceIP: ip}
	deleteResult := m.db.Where("user_id = ? AND source_ip = ?", user.ID, ip).Delete(&models.RemoteSession{})
	if deleteResult.Error != nil {
		return deleteResult.Error
	}
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

// Claims is used Used for the session cookie
type Claims struct {
	Username string `json:"username"`
	HasMFA   bool   `json:"has_mfa"`
	jwt.StandardClaims
}

// CreateSession generates and sends the JWT token cookie.
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
		// Only allows GET requests when reaching the app by clicking on a link
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, &cookie)
	return m.createIdentifierCookie(user, w)
}

func (m *UserManager) DeleteSession(w http.ResponseWriter) error {
	jwtKey := []byte(m.config.SigningKey)
	cookieName := "vpnwa_session"
	if m.config.SSLMode != "off" {
		cookieName = "__Host-" + cookieName
	}
	expirationTime := time.Now().Add(-24 * time.Hour)
	claims := &Claims{
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
	return nil
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
func (m *UserManager) CleanupConnectionsLog() error {
	expireDate := time.Now().AddDate(0, 0, -m.config.ConnectionsRetention)
	result := m.db.Delete(&models.ConnectionAuditEntry{}, "created_at < ?", expireDate)
	return result.Error
}
