package wafreg

import (
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/wafsec"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"time"
)

/*
*
生成客户端机器信息
*/
func GenClientMachineInfo() model.MachineInfo {
	machineInfo := model.MachineInfo{
		Version:          "v1",
		ClientServerName: global.GWAF_CUSTOM_SERVER_NAME,
		ClientTenantId:   global.GWAF_TENANT_ID,
		ClientUserCode:   global.GWAF_USER_CODE,
		OtherFeature:     "",
	}
	//需要加签得字段
	needSignStr := machineInfo.ClientServerName + machineInfo.ClientTenantId + machineInfo.ClientUserCode
	machineInfo.MachineID = fmt.Sprintf("%x", sha256.Sum256([]byte(needSignStr)))
	return machineInfo
}

/*
*
生成客户端机器码加密信息
*/
func GenClientMachineInfoWithEncrypt() (string, error) {
	cryptoUtil := &wafsec.CryptoUtil{}
	publicKey := []byte(global.GWAF_REG_PUBLIC_KEY)
	machineInfo, err := json.Marshal(GenClientMachineInfo())
	if err != nil {
		return "转换json异常", err
	}
	rsaEncrypt, err := cryptoUtil.RsaEncrypt(machineInfo, publicKey)
	if err != nil {
		return "信息加密异常", err
	}
	encodeToString := base64.StdEncoding.EncodeToString(rsaEncrypt)

	return encodeToString, nil
}

/*
*

	校验注册服务信息
*/
func VerifyServerReg(binData []byte) (success bool, info model.RegistrationInfo, err error) {

	//社区信息处理
	var regInfo = model.RegistrationInfo{
		Version:    "v1",
		Username:   "user",
		MemberType: "社区版",
		MachineID:  "",
		ExpiryDate: time.Now().AddDate(1, 0, 0),
		IsExpiry:   false,
	}
	return true, regInfo, nil
}

/*
*

	校验注册服务信息
*/
func VerifyServerRegByDefaultFile() (bool, model.RegistrationInfo, error) {
	// 从文件中读取二进制数据
	binData, err := ioutil.ReadFile("./registration_data.bin")
	if err != nil {
		return false, model.RegistrationInfo{}, errors.New("not find reginfo")
	}
	return VerifyServerReg(binData)
}

// CheckExpiry 计算给定日期与当前日期的天数差，并返回是否到期
func CheckExpiry(date time.Time) (int, bool) {
	// 获取当前日期
	now := time.Now()

	// 将当前时间和给定时间都转为零点，以比较日期
	now = time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	date = time.Date(date.Year(), date.Month(), date.Day(), 0, 0, 0, 0, date.Location())

	// 计算日期差
	duration := date.Sub(now)

	// 计算天数差
	days := int(duration.Hours() / 24)

	// 判断是否到期
	expired := days < 0

	return days, expired
}
