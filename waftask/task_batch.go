package waftask

import (
	"SamWaf/common/zlog"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/request"
	"SamWaf/model/spec"
	"SamWaf/service/waf_service"
	"SamWaf/utils"
	"errors"
	"fmt"
	"gorm.io/gorm"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

var (
	wafBatchTaskService  = waf_service.WafBatchServiceApp
	wafIPAllowService    = waf_service.WafWhiteIpServiceApp
	wafBlockAllowService = waf_service.WafBlockIpServiceApp
)

/*
*
批量任务
*/
func BatchTask() {
	innerLogName := "BatchTask"
	zlog.Info(innerLogName, "准备进行自动执行批量任务")

	batchTaskList, size, err := wafBatchTaskService.GetAllListInner()
	if err != nil {
		zlog.Error(innerLogName, "批量任务:", err)
		return
	}
	if size <= 0 {
		zlog.Info(innerLogName, "没有需要批量执行的任务")
		return
	}
	for _, batchTask := range batchTaskList {

		switch batchTask.BatchType {
		case enums.BATCHTASK_IPALLOW:
			IPAllowBatch(batchTask)
			break
		case enums.BATCHTASK_IPDENY:
			IPDenyBatch(batchTask)
			break
		}
		zlog.Info(innerLogName, "批量已处理完")

	}
}

// handleLocalSource 从本地路径读取数据
func handleLocalSource(task model.BatchTask) (string, error) {
	data, err := ioutil.ReadFile(task.BatchSource)
	if err != nil {
		return "", fmt.Errorf("failed to read local file: %v", err)
	}
	return string(data), nil
}

// handleRemoteSource  从远程 URL 获取数据
func handleRemoteSource(task model.BatchTask) (string, error) {
	resp, err := http.Get(task.BatchSource)
	if err != nil {
		return "", fmt.Errorf("failed to fetch remote data: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read remote response body: %v", err)
	}
	return string(data), nil
}

// IPAllowBatch 白名单IP批量处理
func IPAllowBatch(task model.BatchTask) {
	innerLogName := "BatchTask-IPAllowBatch"
	//1.取数据
	//2.处理数据
	content := ""
	if task.BatchSourceType == "local" {
		cnt, err := handleLocalSource(task)
		if err != nil {
			zlog.Error(innerLogName, err.Error())
			return
		}
		content = cnt
	} else if task.BatchSourceType == "remote" {
		cnt, err := handleRemoteSource(task)
		if err != nil {
			zlog.Error(innerLogName, err.Error())
			return
		}
		content = cnt
	}
	if content == "" {
		zlog.Error(innerLogName, task.BatchTaskName+"没有数据需要处理")
		return
	}
	hasAffectInfo := false
	lines := strings.Split(content, "\n")
	// 遍历每一行数据进行处理
	for _, line := range lines {
		if line == "" {
			continue // 跳过空行
		}
		line = strings.TrimSpace(line)
		validRet, _ := utils.IsValidIPOrNetwork(line)
		if !validRet {
			continue
		}
		if task.BatchExecuteMethod == enums.BATCHTASK_EXECUTEMETHODAPPEND {
			//添加
			err := wafIPAllowService.CheckIsExistApi(request.WafAllowIpAddReq{task.BatchHostCode, line, ""})
			if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
				wafIPAllowService.AddApi(request.WafAllowIpAddReq{task.BatchHostCode, line, time.Now().Format("20060102") + "批量导入 任务ID:" + task.Id})
				hasAffectInfo = true
			}
		} else if task.BatchExecuteMethod == enums.BATCHTASK_EXECUTEMETHODOVERWRITE {
			//覆写
			bean := wafIPAllowService.GetDetailByIPApi(line, task.BatchHostCode)
			if bean.HostCode == "" {
				wafIPAllowService.AddApi(request.WafAllowIpAddReq{task.BatchHostCode, line, time.Now().Format("20060102") + "批量导入 任务ID:" + task.Id})
				hasAffectInfo = true
			} else {
				wafIPAllowService.ModifyApi(request.WafAllowIpEditReq{bean.Id, task.BatchHostCode, line, time.Now().Format("20060102") + "批量导入编辑 任务ID:" + task.Id})
				hasAffectInfo = true
			}

		}
	}
	if hasAffectInfo {
		//发送通知到引擎进行实时生效
		var ipWhites []model.IPAllowList
		global.GWAF_LOCAL_DB.Where("host_code = ? ", task.BatchHostCode).Find(&ipWhites)
		var chanInfo = spec.ChanCommonHost{
			HostCode: task.BatchHostCode,
			Type:     enums.ChanTypeAllowIP,
			Content:  ipWhites,
		}
		global.GWAF_CHAN_MSG <- chanInfo
	}

}

// IPDenyBatch 黑名单IP批量处理
func IPDenyBatch(task model.BatchTask) {
	innerLogName := "BatchTask-IPDenyBatch"
	//1.取数据
	//2.处理数据
	content := ""
	if task.BatchSourceType == "local" {
		cnt, err := handleLocalSource(task)
		if err != nil {
			zlog.Error(innerLogName, err.Error())
			return
		}
		content = cnt
	} else if task.BatchSourceType == "remote" {
		cnt, err := handleRemoteSource(task)
		if err != nil {
			zlog.Error(innerLogName, err.Error())
			return
		}
		content = cnt
	}
	if content == "" {
		zlog.Error(innerLogName, task.BatchTaskName+"没有数据需要处理")
		return
	}
	hasAffectInfo := false
	lines := strings.Split(content, "\n")
	// 遍历每一行数据进行处理
	for _, line := range lines {
		if line == "" {
			continue // 跳过空行
		}
		line = strings.TrimSpace(line)
		validRet, _ := utils.IsValidIPOrNetwork(line)
		if !validRet {
			continue
		}
		if task.BatchExecuteMethod == enums.BATCHTASK_EXECUTEMETHODAPPEND {
			//添加
			err := wafBlockAllowService.CheckIsExistApi(request.WafBlockIpAddReq{task.BatchHostCode, line, ""})
			if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
				wafBlockAllowService.AddApi(request.WafBlockIpAddReq{task.BatchHostCode, line, time.Now().Format("20060102") + "批量导入 任务ID:" + task.Id})
				hasAffectInfo = true
			}
		} else if task.BatchExecuteMethod == enums.BATCHTASK_EXECUTEMETHODOVERWRITE {
			//覆写
			bean := wafBlockAllowService.GetDetailByIPApi(line, task.BatchHostCode)
			if bean.HostCode == "" {
				wafBlockAllowService.AddApi(request.WafBlockIpAddReq{task.BatchHostCode, line, time.Now().Format("20060102") + "批量导入 任务ID:" + task.Id})
				hasAffectInfo = true
			} else {
				wafBlockAllowService.ModifyApi(request.WafBlockIpEditReq{bean.Id, task.BatchHostCode, line, time.Now().Format("20060102") + "批量导入编辑 任务ID:" + task.Id})
				hasAffectInfo = true
			}

		}
	}
	if hasAffectInfo {
		//发送通知到引擎进行实时生效
		var ipBlocks []model.IPBlockList
		global.GWAF_LOCAL_DB.Where("host_code = ? ", task.BatchHostCode).Find(&ipBlocks)
		var chanInfo = spec.ChanCommonHost{
			HostCode: task.BatchHostCode,
			Type:     enums.ChanTypeBlockIP,
			Content:  ipBlocks,
		}
		global.GWAF_CHAN_MSG <- chanInfo
	}

}
