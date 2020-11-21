package models

import (
	"time"

	"github.com/gofrs/uuid"
	"gorm.io/gorm"
)

// User is a successfully authenticated OAuth2 account
type User struct {
	gorm.Model
	ID        uuid.UUID `gorm:"type:uuid;primaryKey"`
	Email     string    `gorm:"unique"`
	CreatedAt time.Time
	UpdatedAt time.Time
	MFAs      []UserMFA //`gorm:"foreignkey:ID"`
}

// BeforeCreate ensures the model has an ID before saving it
func (user *User) BeforeCreate(scope *gorm.DB) error {
	uuid, err := uuid.NewV4()
	if err != nil {
		return err
	}
	user.ID = uuid
	return nil
}
