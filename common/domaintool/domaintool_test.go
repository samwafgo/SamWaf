package domaintool

import (
	"fmt"
	"testing"
)

func TestMaskSubdomain(t *testing.T) {
	fmt.Println(MaskSubdomain("samwaf.com:80"))              // 输出: *.mybaidu1.com:443
	fmt.Println(MaskSubdomain("samwaf.com:443"))             // 输出: *.mybaidu1.com:443
	fmt.Println(MaskSubdomain("bbb.samwaf.com:443"))         // 输出: *.mybaidu1.com:443
	fmt.Println(MaskSubdomain("ccc.bbb.samwaf.com:443"))     // 输出: *.bbb.mybaidu1.com:443
	fmt.Println(MaskSubdomain("ddd.ccc.bbb.samwaf.com:443")) // 输出: *.ccc.bbb.mybaidu1.com:443
}
