package wafonekey

import (
	"SamWaf/common/uuid"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"errors"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// 一键修改数据
func OneKeyModifyBt(btSavePath string) (error, string) {
	if btSavePath == "" {
		btSavePath = "/www/server/panel/vhost/nginx"
	}
	// 将路径标准化，处理斜杠问题
	btSavePath = filepath.Clean(btSavePath)
	subPath := "server/panel/vhost"
	subPath = filepath.Clean(subPath)

	if !strings.Contains(btSavePath, subPath) {
		return errors.New("路径不正确"), "路径不正确"
	}
	// 遍历目录并替换.conf文件中的端口
	files, err := ioutil.ReadDir(btSavePath)
	if err != nil {
		return err, ""
	}
	successCnt := 0
	for _, file := range files {
		if !file.IsDir() && filepath.Ext(file.Name()) == ".conf" {
			filePath := filepath.Join(btSavePath, file.Name())
			fmt.Printf("检查文件: %s\n", filePath)

			// 读取文件内容
			beforeContent, err := ioutil.ReadFile(filePath)
			if err != nil {
				return err, ""
			}

			// 检查是否包含目标字符串
			if strings.Contains(string(beforeContent), "listen 80") || strings.Contains(string(beforeContent), "listen 443") {

				fmt.Printf("修改文件: %s\n", filePath)
				if err := replaceListenPorts(filePath); err != nil {
					return err, ""
				} else {
					// 读取文件内容
					afterContent, _ := ioutil.ReadFile(filePath)
					//插入记录
					global.GQEQUE_LOG_DB.Enqueue(model.OneKeyMod{
						BaseOrm: baseorm.BaseOrm{
							Id:          uuid.GenUUID(),
							USER_CODE:   global.GWAF_USER_CODE,
							Tenant_ID:   global.GWAF_TENANT_ID,
							CREATE_TIME: customtype.JsonTime(time.Now()),
							UPDATE_TIME: customtype.JsonTime(time.Now())},
						OpSystem:      "宝塔",
						FilePath:      filePath,
						BeforeContent: string(beforeContent),
						AfterContent:  string(afterContent),
						Remarks:       "",
					})
					successCnt++
				}

			}
		}
	}
	if successCnt > 0 {
		return nil, "修改文件数：" + strconv.Itoa(successCnt) + " 请重启在宝塔面板上进行Nginx重启"
	} else {
		return nil, "修改文件数：" + strconv.Itoa(successCnt)
	}
}

// replaceListenPorts 读取文件内容，替换listen端口，并写回文件
func replaceListenPorts(filePath string) error {
	// 读取文件内容
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}

	// 检查并替换listen 80和listen 443
	lines := strings.Split(string(content), "\n")
	containsTarget := false
	for _, line := range lines {
		if strings.Contains(line, "listen 80") || strings.Contains(line, "listen 443") {
			containsTarget = true
			break
		}
	}

	if containsTarget {
		for i, line := range lines {
			lines[i] = strings.Replace(line, "listen 80", "listen 81", 1)
			lines[i] = strings.Replace(lines[i], "listen 443", "listen 444", 1)
			//fmt.Println(lines[i])
		}

		// 将修改后的内容写回文件
		return ioutil.WriteFile(filePath, []byte(strings.Join(lines, "\n")), 0644)
	}

	return nil
}
