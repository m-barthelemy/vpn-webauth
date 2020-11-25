package services

import (
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gofrs/uuid"
	"github.com/m-barthelemy/vpn-webauth/models"

	"gorm.io/gorm"
)

type UserManager struct {
	db     *gorm.DB
	config *models.Config
}

// New creates an instance of the controller and sets its DB handle
func New(db *gorm.DB, config *models.Config) *UserManager {
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

func (m *UserManager) CheckVpnSession(identity string, ip string, otpValid bool) (*models.User, *models.VpnSession, bool, error) {
	var session models.VpnSession
	var user models.User

	var duration int
	if otpValid {
		duration = m.config.MFAValidity
	} else {
		duration = m.config.VPNSessionValidity
	}
	minDate := time.Now().Add(time.Second * time.Duration(-duration))
	userResult := m.db.Where("email = ?", identity).First(&user)
	if userResult.Error != nil {
		if errors.Is(userResult.Error, gorm.ErrRecordNotFound) {
			return nil, nil, false, nil
		} else {
			return nil, nil, false, userResult.Error
		}
	}

	sessionResult := m.db.Where("email = ? AND source_ip = ? AND created_at > ?", identity, ip, minDate).First(&session)
	if sessionResult.Error != nil {
		if errors.Is(sessionResult.Error, gorm.ErrRecordNotFound) {
			return &user, nil, false, nil
		} else {
			return &user, nil, false, sessionResult.Error
		}
	}

	return &user, &session, true, nil
}

// CreateVpnSession Creates a new VPN "Session" for the `User` from the specified IP address.
func (m *UserManager) CreateVpnSession(mfaID uuid.UUID, user *models.User, ip string) error {
	// First delete any existing session for the same user
	oldSession := models.VpnSession{Email: user.Email}
	deleteResult := m.db.Delete(&oldSession)
	if deleteResult.Error != nil {
		return deleteResult.Error
	}
	// Then create the new "session"
	var vpnSession = models.VpnSession{MFAID: mfaID, Email: user.Email, SourceIP: ip}
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

// Claims is used Used for the session cookie
type Claims struct {
	Username string `json:"username"`
	HasMFA   bool   `json:"has_mfa"`
	jwt.StandardClaims
}

func (m *UserManager) CreateSession(email string, hasMFA bool, w http.ResponseWriter) error {
	jwtKey := []byte(m.config.SigningKey)
	expirationTime := time.Now().Add(time.Duration(m.config.MFAValidity) * time.Second)
	claims := &Claims{
		Username: email,
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
		Name:     "vpnwa_session",
		Value:    tokenString,
		Expires:  expirationTime,
		HttpOnly: true,
		Path:     "/",
		Secure:   m.config.SSLMode != "off",
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
