package api

import (
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"errors"

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
		// 防提权：仅超级管理员可创建超级管理员
		if req.Role == enums.ROLE_SUPER_ADMIN && currentRole(c) != enums.ROLE_SUPER_ADMIN {
			response.ForbiddenWithMessage("仅超级管理员可创建超级管理员账号", c)
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
		// 防提权：仅超级管理员可将账号提升为超级管理员
		if req.Role == enums.ROLE_SUPER_ADMIN && currentRole(c) != enums.ROLE_SUPER_ADMIN {
			response.ForbiddenWithMessage("仅超级管理员可指派超级管理员角色", c)
			return
		}
		err = wafAccountService.ModifyApi(req)
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
	response.OkWithMessage("修改密码成功", c)
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
		if tokenInfo.LoginAccount == "admin" {
			response.FailWithMessage("仅admin用户可以重置2FA", c)
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
