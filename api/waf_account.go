package api

import (
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"errors"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type WafAccountApi struct {
}

// currentRole 从上下文取当前登录角色（经鉴权中间件归一化）
func currentRole(c *gin.Context) string {
	if v, ok := c.Get("userRole"); ok {
		if r, ok := v.(string); ok {
			return enums.NormalizeRole(r)
		}
	}
	return enums.ROLE_SUPER_ADMIN
}

// AddApi 新增账号
func (w *WafAccountApi) AddApi(c *gin.Context) {
	var req request.WafAccountAddReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		// N7 防提权：账号创建集中到超级管理员，杜绝 systemAdmin 横向新建 security/audit/其它 system 管理员自我提权。
		if currentRole(c) != enums.ROLE_SUPER_ADMIN {
			response.ForbiddenWithMessage("仅超级管理员可创建管理账号", c)
			return
		}
		err = wafAccountService.CheckIsExistApi(req)
		if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
			err = wafAccountService.AddApi(req)
			if err == nil {
				response.OkWithMessage("添加成功", c)
			} else {
				response.FailWithMessage(err.Error(), c)
			}
			return
		} else {
			response.FailWithMessage("当前数据已经存在", c)
			return
		}

	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// GetDetailApi 获取账号详情
func (w *WafAccountApi) GetDetailApi(c *gin.Context) {
	var req request.WafAccountDetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafAccountService.GetDetailApi(req)
		response.OkWithDetailed(bean, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// GetListApi 获取账号列表
func (w *WafAccountApi) GetListApi(c *gin.Context) {
	var req request.WafAccountSearchReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		beans, total, _ := wafAccountService.GetListApi(req)
		response.OkWithDetailed(response.PageResult{
			List:      beans,
			Total:     total,
			PageIndex: req.PageIndex,
			PageSize:  req.PageSize,
		}, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// DelAccountApi 删除账号
func (w *WafAccountApi) DelAccountApi(c *gin.Context) {
	var req request.WafAccountDelReq
	err := c.ShouldBind(&req)
	if err == nil {
		// N7 防提权：账号删除集中到超级管理员，防止 systemAdmin 删除超管/他域账号（原先无任何角色/目标校验）。
		if currentRole(c) != enums.ROLE_SUPER_ADMIN {
			response.ForbiddenWithMessage("仅超级管理员可删除管理账号", c)
			return
		}
		err = wafAccountService.DelApi(req)
		if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
			response.FailWithMessage("请检测参数", c)
		} else if err != nil {
			response.FailWithMessage("发生错误", c)
		} else {
			response.OkWithMessage("删除成功", c)
		}

	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// ModifyAccountApi 编辑账号
func (w *WafAccountApi) ModifyAccountApi(c *gin.Context) {
	var req request.WafAccountEditReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		// N7 防提权：角色变更仅超级管理员可为（在 service 内按目标账号"当前角色"精确判定，
		// 只拦真正的角色变化，不影响非角色字段的正常编辑）。
		err = wafAccountService.ModifyApi(req, currentRole(c))
		if err != nil {
			response.FailWithMessage(err.Error(), c)
		} else {
			response.OkWithMessage("编辑成功", c)
		}

	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// ChangeMyPasswordApi 当前登录账号自助改密（用于首次登录/口令到期强制改密）
func (w *WafAccountApi) ChangeMyPasswordApi(c *gin.Context) {
	var req request.WafAccountChangeMyPwdReq
	err := c.ShouldBindJSON(&req)
	if err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	if req.NewPassword != req.NewPassword2 {
		response.FailWithMessage("两次输入的新密码不同", c)
		return
	}
	loginAccount := ""
	if v, ok := c.Get("loginAccount"); ok {
		loginAccount, _ = v.(string)
	}
	if loginAccount == "" {
		response.FailWithMessage("登录状态异常，请重新登录", c)
		return
	}
	if err = wafAccountService.ChangeMyPasswordApi(loginAccount, req.OldPassword, req.NewPassword); err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	// 改密成功后清除当前令牌缓存里的强制改密标记，使其可正常访问其他接口（无需重新登录）
	clearTokenNeedChangePassword(c)
	response.OkWithMessage("修改密码成功", c)
}

// clearTokenNeedChangePassword 改密成功后，把当前令牌缓存里的强制改密标记清零。
func clearTokenNeedChangePassword(c *gin.Context) {
	tokenStr := c.GetHeader("X-Token")
	if tokenStr == "" && c.GetHeader("X-Login-Type") == "mobile" {
		tokenStr = c.GetHeader("X-Mobile-Token")
	}
	if tokenStr == "" {
		return
	}
	key := enums.CACHE_TOKEN + tokenStr
	var tokenInfo model.TokenInfo
	if err := global.GCACHE_WAFCACHE.GetAs(key, &tokenInfo); err != nil {
		return
	}
	tokenInfo.NeedChangePassword = 0
	if expireTime, err := global.GCACHE_WAFCACHE.GetExpireTime(key); err == nil {
		if remain := time.Until(expireTime); remain > 0 {
			global.GCACHE_WAFCACHE.SetWithTTl(key, tokenInfo, remain)
			return
		}
	}
	global.GCACHE_WAFCACHE.SetWithTTl(key, tokenInfo, time.Duration(global.GCONFIG_RECORD_TOKEN_EXPIRE_MINTUTES)*time.Minute)
}

func (w *WafAccountApi) ResetAccountPwdApi(c *gin.Context) {
	var req request.WafAccountResetPwdReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		if req.LoginNewPassword != req.LoginNewPassword2 {
			response.OkWithMessage("两次输入的密码不同", c)
			return
		}
		err = wafAccountService.ResetPwdApi(req)
		if err != nil {
			response.FailWithMessage(err.Error(), c)
		} else {
			response.OkWithMessage("重置密码成功", c)
		}

	} else {
		response.FailWithMessage("重置密码失败", c)
	}
}

func (w *WafAccountApi) ResetAccountOTPApi(c *gin.Context) {
	var req request.WafAccountResetOTPReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		tokenStr := c.GetHeader("X-Token")
		tokenInfo := wafTokenInfoService.GetInfoByAccessToken(tokenStr)
		if tokenInfo.LoginAccount == "" {
			response.FailWithMessage("token可能已经失效", c)
			return
		}
		// N4 修复：原判断写反（== "admin"）——把 admin/超管自己挡在门外，却放行其它 systemAdmin 删他人 2FA。
		// 正确策略：仅超级管理员可重置他人 2FA（角色经 Auth 中间件归一化后写入上下文）。
		if currentRole(c) != enums.ROLE_SUPER_ADMIN {
			response.ForbiddenWithMessage("仅超级管理员可以重置双因素认证(2FA)", c)
			return
		}
		if req.LoginAccount == "admin" {
			response.OkWithMessage("admin帐号需要用控制台命令重置详情查看常见问题", c)
			return
		}
		global.GWAF_LOCAL_DB.Where("user_name = ? ", req.LoginAccount).Delete(model.Otp{})
		response.OkWithMessage("重置2FA成功", c)

	} else {
		response.FailWithMessage("重置2FA失败", c)
	}
}
