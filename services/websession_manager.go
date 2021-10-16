package services

import (
	"errors"
	"time"

	"github.com/m-barthelemy/vpn-webauth/models"
	"github.com/m-barthelemy/vpn-webauth/utils"
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
		return errors.New("both identity and sourceIP must be set")
	}
	log := utils.ConfigureLogger(identity, sourceIP)

	// Early exit if identity is excluded from any additional auth.
	if utils.Contains(s.config.ExcludedIdentities, identity) {
		log.Infof("WebSessionController: client is excluded from web authentication, skipping")
		return nil
	}

	start := time.Now() // report time taken to verify user for debugging purposes
	userManager := NewUserManager(s.db, s.config)
	user, session, allowed, err := userManager.CheckVpnSession(identity, sourceIP)
	if err != nil {
		log.Errorf("WebSessionController: error checking user session: %s", err.Error())
		return err
	}
	if user == nil {
		err := errors.New("received request for unknown client identity")
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
			log.Errorf("WebSessionManager: error saving Vpnconnection audit entry: %s", tx.Error.Error())
			return tx.Error
		}

	}

	_, notifUniqueID, err := s.notificationsManager.NotifyUser(user, sourceIP)
	hasValidBrowserSession := s.notificationsManager.WaitForBrowserProof(user, sourceIP, *notifUniqueID)
	vpnConnection.Allowed = hasValidBrowserSession
	if tx := s.db.Save(&vpnConnection); tx.Error != nil {
		log.Errorf("WebSessionManager: error saving Vpnconnection audit entry: %s", tx.Error.Error())
	}
	log.Debugf("checking web session took %s", time.Since(start))

	if !hasValidBrowserSession {
		return errors.New("WebSessionManager: no valid session found")
	}

	// Create a new VPNSession
	if err := userManager.CreateVpnSession(user, sourceIP); err != nil {
		return err
	}
	log.Info("WebSessionManager: VPN session extended from valid Web session.")
	return nil
}
