package utils

import (
	"fmt"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"time"
)

func GenOtpSecret(userName string) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "SamWaf",
		AccountName: userName,
		Period:      30,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(key)
	// 模拟生成一个一次性密码
	now := time.Now()
	passcode, err := totp.GenerateCode(key.Secret(), now)
	if err != nil {
		panic(err)
	}

	// 验证一次性密码
	valid := totp.Validate(passcode, key.Secret())
	if valid {
		fmt.Println("Valid passcode!")
	} else {
		fmt.Println("Invalid passcode!")
	}

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
