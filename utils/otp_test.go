package utils

import (
	"fmt"
	"testing"
)

func TestGenOtpSecret(t *testing.T) {
	secret, url, err := GenOtpSecret("admin")
	fmt.Println(secret, url, err)
}
func TestValidateOtpCode(t *testing.T) {
	ValidateOtpCode("937792", "MZTAH2NZ6AWGEPGMWOUETPQ6275TAMGX")
}
