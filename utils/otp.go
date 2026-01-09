package utils

import (
	"SamWaf/global"
	"fmt"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func GenOtpSecret(userName string, issuer string) (string, string, error) {
	// 如果没有提供 issuer，使用默认值
	if issuer == "" {
		issuer = "SamWaf-" + global.GWAF_CUSTOM_SERVER_NAME
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: userName,
		Period:      30,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return "", "", err
	}
	return key.Secret(), key.URL(), nil
}
func ValidateOtpCode(passCode string, secret string) bool {
	// 验证一次性密码
	valid := totp.Validate(passCode, secret)
	if valid {
		fmt.Println("Valid passcode!")
	} else {
		fmt.Println("Invalid passcode!")
	}
	return valid
}
