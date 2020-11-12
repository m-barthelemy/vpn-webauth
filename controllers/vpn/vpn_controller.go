package controllers

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/m-barthelemy/vpn-webauth/models"
	userManager "github.com/m-barthelemy/vpn-webauth/services"
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

	userManager := userManager.New(v.db, v.config)
	allowed, err := userManager.CheckVpnSession(connRequest.Identity, connRequest.SourceIP, false)
	if err != nil {
		log.Printf("VpnController: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if !allowed {
		log.Printf("VpnController: Session not found for user %s", connRequest.Identity)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	} else {
		http.Error(w, "Ok", http.StatusOK)
		return
	}
}
