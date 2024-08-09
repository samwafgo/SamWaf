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
}
