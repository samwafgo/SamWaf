package wafdb

import (
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/utils"
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// selectAccount 列出所有账号，优先默认选中 admin，让用户选择后返回账号名
func selectAccount() (string, bool) {
	var accounts []model.Account
	if err := global.GWAF_LOCAL_DB.Find(&accounts).Error; err != nil || len(accounts) == 0 {
		fmt.Println("No accounts found in database.")
		return "", false
	}

	defaultIndex := -1
	for i, a := range accounts {
		if a.LoginAccount == "admin" {
			defaultIndex = i
			break
		}
	}

	fmt.Println("Available accounts:")
	for i, a := range accounts {
		marker := ""
		if i == defaultIndex {
			marker = " [default]"
		}
		fmt.Printf("  [%d] %s%s\n", i+1, a.LoginAccount, marker)
	}

	reader := bufio.NewReader(os.Stdin)
	if defaultIndex >= 0 {
		fmt.Printf("Please enter account number (press Enter to use default '%s'): ", accounts[defaultIndex].LoginAccount)
	} else {
		fmt.Print("Please enter account number: ")
	}

	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	if input == "" && defaultIndex >= 0 {
		return accounts[defaultIndex].LoginAccount, true
	}

	idx, err := strconv.Atoi(input)
	if err != nil || idx < 1 || idx > len(accounts) {
		fmt.Println("Invalid selection.")
		return "", false
	}
	return accounts[idx-1].LoginAccount, true
}

// ResetAdminPwd 重置密码
func ResetAdminPwd() {
	chosenAccount, ok := selectAccount()
	if !ok {
		return
	}

	randomPassword, _ := utils.GenerateRandomPassword(12)
	beanMap := map[string]interface{}{
		"LoginPassword": utils.Md5String(randomPassword + global.GWAF_DEFAULT_ACCOUNT_SALT),
		"UPDATE_TIME":   customtype.JsonTime(time.Now()),
	}
	err := global.GWAF_LOCAL_DB.Model(model.Account{}).Where("login_account = ?", chosenAccount).Updates(beanMap).Error
	if err != nil {
		fmt.Printf("Failed to reset password for '%s': %v\n", chosenAccount, err)
	} else {
		global.GWAF_LOCAL_DB.Where("login_account = ?", chosenAccount).Delete(model.TokenInfo{})
		fmt.Printf("Reset password for '%s' successfully, the new password is:\n", chosenAccount)
		fmt.Println(randomPassword)
		fmt.Println("Please keep it safe.")
	}
}

// ResetAdminOTP 重置OTP
func ResetAdminOTP() {
	chosenAccount, ok := selectAccount()
	if !ok {
		return
	}

	global.GWAF_LOCAL_DB.Where("user_name = ?", chosenAccount).Delete(model.Otp{})
	fmt.Printf("Reset 2FA for '%s' successfully.\n", chosenAccount)
}
