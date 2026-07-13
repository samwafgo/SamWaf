package detection

/*
*
检测结果
*/
type Result struct {
	/**
	Guard 检测  true 跳过检测 false 不跳过检测
	*/
	JumpGuardResult bool
	/**
	是否拦截
	*/
	IsBlock bool
	/**
	检测名称
	*/
	Title string
	/**
	检测内容
	*/
	Content string
	/**
	仅记录：命中了但不拦截，记录日志后继续走后续检测
	*/
	IsLogOnly bool
	/**
	自定义规则放行：不拦截，可按 SkipModules 跳过后续指定检测
	*/
	IsRuleAllow bool
	/**
	放行时要跳过的检测模块（大写模块名，含 "ALL" 表示跳过全部）
	*/
	SkipModules []string
}
