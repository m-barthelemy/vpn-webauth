package models

import (
	"time"

	"github.com/gofrs/uuid"
	"gorm.io/gorm"
)

// ConnectionAuditEntry represents a connection attempt
type ConnectionAuditEntry struct {
	ID             uuid.UUID `gorm:"type:uuid;primaryKey"`
	Identity       string
	UserID         *uuid.UUID `gorm:"type:uuid,index"`
	Type           string     // "vpn" or "ssh"
	ClientSourceIP string     // Client/user IP
	CallerSourceIP string     // Source IP of the request to `/check/` (VPN server or remote SSH system)
	Allowed        bool
	SessionID      *uuid.UUID `gorm:"type:uuid"`
	CreatedAt      time.Time  `gorm:"index"`
	User           User       `gorm:"primaryKey;foreignKey:UserID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;references:id"`
}

// BeforeCreate ensures the model has an ID before saving it
func (entry *ConnectionAuditEntry) BeforeCreate(scope *gorm.DB) error {
	uuid, err := uuid.NewV4()
	if err != nil {
		return err
	}
	entry.ID = uuid
	return nil
}
