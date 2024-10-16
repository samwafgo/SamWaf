package webplugin

import (
	"gorm.io/gorm"
)

type ModelTenant struct {
	*gorm.DB
}
