package test

import (
	"fmt"
	"testing"
	"time"
)

func TestTimemyt(t *testing.T) {
	tmpTime := time.Now()
	fmt.Println(tmpTime.Format("20060102")) // 输出: 2019-04-30
}
