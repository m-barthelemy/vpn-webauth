package services

import (
	"fmt"
	"time"

	"github.com/m-barthelemy/vpn-webauth/models"
	"github.com/m-barthelemy/vpn-webauth/utils"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type WebSessionManager struct {
	db                   *gorm.DB
	config               *models.Config
	notificationsManager *NotificationsManager
	utils                *utils.Utils
}

func NewWebSessionManager(db *gorm.DB, config *models.Config, notificationsManager *NotificationsManager, utils *utils.Utils) *WebSessionManager {
	return &WebSessionManager{
		db:                   db,
		config:               config,
		notificationsManager: notificationsManager,
		utils:                utils,
	}
}

func (s *WebSessionManager) CheckSession(identity string, sourceIP string) error {
	if identity == "" || sourceIP == "" {
		return fmt.Errorf("both identity and sourceIP must be set")
	}
	start := time.Now() // report time taken to verify user for debugging purposes
	userManager := NewUserManager(s.db, s.config)
	user, session, allowed, err := userManager.CheckVpnSession(identity, sourceIP)
	if err != nil {
		log.Errorf("WebSessionController: error checking user session: %s", err.Error())
		return err
	}
	if user == nil {
		err := fmt.Errorf("received request for unknown identity '%s' from %s", identity, sourceIP)
		log.Errorf("WebSessionController: %s", err)
		return err
	}

	vpnConnection := models.VPNConnection{
		Allowed:  allowed,
		Identity: identity,
		SourceIP: sourceIP,
		// TODO: restablish
		//VPNSourceIP: s.utils.GetClientIP(r),
	}

	vpnConnection.UserID = &user.ID
	if allowed {
		vpnConnection.VPNSessionID = &session.ID
	}

	if allowed {
		if tx := s.db.Save(&vpnConnection); tx.Error != nil {
			log.Errorf("WebSessionManager: error saving Vpnconnection audit entry for %s: %s", user.Email, tx.Error.Error())
			return tx.Error
		}

	}

	_, notifUniqueID, err := s.notificationsManager.NotifyUser(user, sourceIP)
	hasValidBrowserSession := s.notificationsManager.WaitForBrowserProof(user, sourceIP, *notifUniqueID)
	vpnConnection.Allowed = hasValidBrowserSession
	if tx := s.db.Save(&vpnConnection); tx.Error != nil {
		log.Errorf("WebSessionManager: error saving Vpnconnection audit entry for %s: %s", user.Email, tx.Error.Error())
	}
	log.Debugf("checking web session took %s", time.Since(start))

	if !hasValidBrowserSession {
		return fmt.Errorf("WebSessionManager: no valid session found for user %s from %s", identity, sourceIP)
	}

	// Create a new VPNSession
	if err := userManager.CreateVpnSession(user, sourceIP); err != nil {
		return err
	}
	log.Infof("WebSessionManager: user %s VPN session extended from valid Web session.", user.Email)
	return nil
}
