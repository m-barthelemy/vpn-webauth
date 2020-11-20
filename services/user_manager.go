package services

import (
	"errors"
	"log"
	"time"

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

func (m *UserManager) CheckVpnSession(identity string, ip string, otpValid bool) (bool, error) {
	var session models.VpnSession
	var duration int
	if otpValid {
		duration = m.config.MFAValidity
	} else {
		duration = m.config.SessionValidity
	}
	minDate := time.Now().Add(time.Second * time.Duration(-duration))
	result := m.db.Where("email = ? AND source_ip = ? AND created_at > ?", identity, ip, minDate).First(&session)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return false, nil
		} else {
			return false, result.Error
		}
	}

	return true, nil
}

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

func (m *UserManager) AddMFA(user *models.User, mfaType string, data string) (*models.UserMFA, error) {
	userMFA := models.UserMFA{
		Email:     user.Email,
		Validated: false,
		Type:      mfaType,
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

func (m *UserManager) ValidateMFA(user *models.User, mfaType string, data string) error {
	var userMFA models.UserMFA
	result := m.db.Where("email = ? AND type = ? AND validated = ?", user.Email, mfaType, false).First(&userMFA)
	if result.Error != nil {
		return result.Error
	}
	userMFA.Validated = true
	if data != "" {
		dp := NewDataProtector(m.config)
		encryptedData, err := dp.Encrypt(data)
		if err != nil {
			return err
		}
		userMFA.Data = encryptedData
	}

	if err := m.db.Save(&userMFA); err != nil {
		return result.Error
	}
	log.Printf("UserManager: Validated %s UserMFA for %s", mfaType, user.Email)
	return nil
}
