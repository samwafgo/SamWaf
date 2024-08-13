package wafdb

import (
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/utils"
	"fmt"
	"time"
)

/*
*
重置密码
*/
func ResetAdminPwd() {
	defaultAcount := "admin"
	randomPassword, _ := utils.GenerateRandomPassword(12)
	beanMap := map[string]interface{}{
		"LoginPassword": utils.Md5String(randomPassword + global.GWAF_DEFAULT_ACCOUNT_SALT),
		"UPDATE_TIME":   customtype.JsonTime(time.Now()),
	}
	err := global.GWAF_LOCAL_DB.Model(model.Account{}).Where(" login_account = ?", defaultAcount).Updates(beanMap).Error
	if err != nil {

	} else {
		err = global.GWAF_LOCAL_DB.Where("login_account = ? ", defaultAcount).Delete(model.TokenInfo{}).Error

		fmt.Println("Reset password is success,the new password is :")
		fmt.Println(randomPassword)
		fmt.Println("Please keep it safe.")
	}

}
