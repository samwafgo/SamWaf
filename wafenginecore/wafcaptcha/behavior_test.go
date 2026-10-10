package wafcaptcha

import "testing"

func TestCheckCaptchaBehavior(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want bool
	}{
		{"无数据放行（旧页面兼容）", "", true},
		{"旧版格式只判自动化特征", `{"mouseTrack":[{"x":1,"y":2}],"timing":1730000000000,"pattern":[]}`, true},
		{"旧版格式命中自动化特征仍拒绝", `{"mouseTrack":[],"timing":1,"auto":1}`, false},
		{"非法 JSON 拒绝", `{oops`, false},
		{"自动化特征拒绝", `{"v":1,"auto":1,"mousePoints":9,"pointerPoints":9,"clicks":3,"elapsedMs":3000}`, false},
		{"缺少耗时拒绝", `{"v":1,"auto":0,"mousePoints":9,"pointerPoints":9,"clicks":3}`, false},
		{"答题过快拒绝", `{"v":1,"mousePoints":9,"pointerPoints":9,"clicks":3,"elapsedMs":120}`, false},
		{"无任何交互轨迹拒绝", `{"v":1,"mousePoints":0,"touchPoints":0,"pointerPoints":0,"clicks":3,"elapsedMs":3000}`, false},
		{"点击次数过少拒绝", `{"v":1,"mousePoints":5,"pointerPoints":5,"clicks":1,"elapsedMs":3000}`, false},
		{"轨迹时间倒序拒绝", `{"v":1,"mousePoints":2,"pointerPoints":2,"clicks":2,"elapsedMs":3000,"mouseTrack":[{"x":1,"y":1,"t":20},{"x":2,"y":2,"t":10}]}`, false},
		{"触摸设备正常通过", `{"v":1,"mousePoints":0,"touchPoints":7,"pointerPoints":7,"clicks":3,"elapsedMs":3000}`, true},
		{"鼠标操作正常通过", `{"v":1,"mousePoints":30,"touchPoints":0,"pointerPoints":31,"clicks":3,"elapsedMs":4200,"mouseTrack":[{"x":1,"y":1,"t":10},{"x":2,"y":2,"t":20}]}`, true},
	}

	for _, c := range cases {
		ok, reason := checkCaptchaBehavior(c.raw)
		if ok != c.want {
			t.Fatalf("%s: 期望 %v，实际 %v（%s）", c.name, c.want, ok, reason)
		}
	}
}
