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
	MFAs      []UserMFA
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

// HasMFA returns `true` if the `User` has at least one validated MFA provider
func (user *User) HasMFA() bool {
	if user.MFAs == nil {
		return false
	}
	for _, item := range user.MFAs {
		if item.IsValid() {
			return true
		}
	}
	return false
}
