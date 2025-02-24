package utils

import "testing"

func TestGenOtpSecret(t *testing.T) {
	GenOtpSecret("admin")
}
func TestValidateOtpCode(t *testing.T) {
	ValidateOtpCode("937792", "MZTAH2NZ6AWGEPGMWOUETPQ6275TAMGX")
}
