package api

import "testing"

func TestNormalizeGeneratedRule(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "动作漏分号自动补上",
			in: `rule R001 "x" salience 10 {
    when
        MF.URL.HasPrefix("/admin") == true
    then
        RF.Deny()
}`,
			want: `rule R001 "x" salience 10 {
    when
        MF.URL.HasPrefix("/admin") == true
    then
        RF.Deny();
}`,
		},
		{
			name: "已有分号不重复",
			in: `rule R001 "x" salience 10 {
    when
        MF.URL.HasPrefix("/admin") == true
    then
        RF.Deny();
}`,
			want: `rule R001 "x" salience 10 {
    when
        MF.URL.HasPrefix("/admin") == true
    then
        RF.Deny();
}`,
		},
		{
			name: "去掉markdown围栏",
			in:   "```grl\nrule R001 \"x\" salience 10 {\n    when\n        MF.PORT == 80\n    then\n        RF.Log()\n}\n```",
			want: `rule R001 "x" salience 10 {
    when
        MF.PORT == 80
    then
        RF.Log();
}`,
		},
		{
			name: "Allow带参数补分号",
			in: `rule R001 "x" salience 100 {
    when
        RF.IPEquals(MF.SRC_IP, "1.2.3.4") == true
    then
        RF.Allow("CC", "AI")
}`,
			want: `rule R001 "x" salience 100 {
    when
        RF.IPEquals(MF.SRC_IP, "1.2.3.4") == true
    then
        RF.Allow("CC", "AI");
}`,
		},
		{
			name: "AllowAll补分号",
			in: `rule R001 "x" salience 200 {
    when
        RF.IPInCIDR(MF.SRC_IP, "10.0.0.0/8") == true
    then
        RF.AllowAll()
}`,
			want: `rule R001 "x" salience 200 {
    when
        RF.IPInCIDR(MF.SRC_IP, "10.0.0.0/8") == true
    then
        RF.AllowAll();
}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeGeneratedRule(tc.in)
			if got != tc.want {
				t.Fatalf("normalizeGeneratedRule 不匹配\n--- got ---\n%s\n--- want ---\n%s", got, tc.want)
			}
		})
	}
}
