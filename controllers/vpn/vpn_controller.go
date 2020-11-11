package controllers

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/m-barthelemy/vpn-webauth/models"
	"gorm.io/gorm"
)

type VpnController struct {
	db     *gorm.DB
	config *models.Config
}

// New creates an instance of the controller and sets its DB handle
func New(db *gorm.DB, config *models.Config) *VpnController {
	return &VpnController{db: db, config: config}
}

// VpnConnectionRequest is what is received from the Stringswan `ext-auth` script request
type VpnConnectionRequest struct {
	Identity string
	SourceIP string
}

func (v *VpnController) CheckSession(w http.ResponseWriter, r *http.Request) {
	var connRequest VpnConnectionRequest
	err := json.NewDecoder(r.Body).Decode(&connRequest)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	var session models.VpnSession
	minDate := time.Now().Add(time.Second * time.Duration(-v.config.SessionValidity))
	result := v.db.Where("email = ? AND source_ip = ? AND created_at > ?", connRequest.Identity, connRequest.SourceIP, minDate).First(&session)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			log.Printf("VpnController: Session not found for user %s", connRequest.Identity)
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		} else {
			log.Printf("VpnController: %s", result.Error.Error())
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	} else {
		http.Error(w, "Ok", http.StatusOK)
		return
	}
}
