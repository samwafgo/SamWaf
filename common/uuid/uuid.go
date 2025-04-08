package uuid

import (
	uuidnew "github.com/google/uuid"
)

func GenUUID() string {
	return uuidnew.NewString()
}
