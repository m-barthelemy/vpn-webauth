package models

import (
	"time"

	"github.com/gofrs/uuid"
	"gorm.io/gorm"
)

// Connection represents a connection attempt to the VPN
type VPNConnection struct {
	ID           uuid.UUID `gorm:"type:uuid;primaryKey"`
	Identity     string
	UserID       *uuid.UUID `gorm:"type:uuid,index"`
	SourceIP     string     // VPN client/user IP
	VPNSourceIP  string     // Source IP of the request to `/vpn/check` (VPN server normally)
	Allowed      bool
	VPNSessionID *uuid.UUID `gorm:"type:uuid"`
	CreatedAt    time.Time  `gorm:"index"`
	User         User       `gorm:"primaryKey;foreignKey:UserID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;references:id"`
	VpnSession   VpnSession `gorm:"primaryKey;foreignKey:VPNSessionID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;references:id"`
}

// BeforeCreate ensures the model has an ID before saving it
func (vpnConn *VPNConnection) BeforeCreate(scope *gorm.DB) error {
	uuid, err := uuid.NewV4()
	if err != nil {
		return err
	}
	vpnConn.ID = uuid
	return nil
}
