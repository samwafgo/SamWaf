package wafreg

import (
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/wafsec"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
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
func genClientMachineInfo() model.MachineInfo {
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
	machineInfo, err := json.Marshal(genClientMachineInfo())
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
func VerifyServerReg() (bool, model.RegistrationInfo, error) {
	//根据用户传来得数据信息
	cryptoUtil := &wafsec.CryptoUtil{}
	publicKey := []byte(global.GWAF_REG_PUBLIC_KEY)

	// 假设读取当前机器的机器码
	currentMachineInfo := genClientMachineInfo()

	// 从文件中读取二进制数据
	binData, err := ioutil.ReadFile("./registration_data.bin")
	if err != nil {
		return false, model.RegistrationInfo{}, errors.New("验签失败-加载注册信息")
	}

	buffer := bytes.NewBuffer(binData)

	// 读取注册信息长度
	var dataLen int32
	err = binary.Read(buffer, binary.LittleEndian, &dataLen)
	if err != nil {
		return false, model.RegistrationInfo{}, errors.New("验签失败-读取注册信息长度失败")
	}

	// 读取注册信息
	data := make([]byte, dataLen)
	_, err = buffer.Read(data)
	if err != nil {
		return false, model.RegistrationInfo{}, errors.New("验签失败-读取注册信息失败")
	}

	// 读取签名长度
	var sigLen int32
	err = binary.Read(buffer, binary.LittleEndian, &sigLen)
	if err != nil {
		return false, model.RegistrationInfo{}, errors.New("验签失败-读取签名长度失败")
	}

	// 读取签名
	signature := make([]byte, sigLen)
	_, err = buffer.Read(signature)
	if err != nil {
		return false, model.RegistrationInfo{}, errors.New("验签失败-读取签名失败")
	}

	// 客户端验证签名
	signWithSha256Result := cryptoUtil.RsaVerySignWithSha256(data, signature, publicKey)
	if !signWithSha256Result {
		return false, model.RegistrationInfo{}, errors.New("验签失败")
	} else {
		decrypt, err := wafsec.AesDecrypt(string(data), global.GWAF_REG_KEY)
		data = decrypt
		// 解析数据
		var regInfo model.RegistrationInfo
		err = json.Unmarshal(data, &regInfo)
		if err != nil {
			return false, model.RegistrationInfo{}, errors.New("验签成功-转换json失败")
		}

		// 验证机器码
		if regInfo.MachineID != currentMachineInfo.MachineID {
			return false, model.RegistrationInfo{}, errors.New("验签成功-机器码不正确")
		} else {
			return true, regInfo, nil
		}
	}
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
