package test

import (
	"SamWaf/utils"
	"fmt"
	"strconv"
	"testing"
	"time"
)

func TestTimemyt(t *testing.T) {
	tmpTime := time.Now()
	fmt.Println(tmpTime.Format("20060102")) // 输出: 2019-04-30

	fmt.Println(utils.Str2Time(strconv.Itoa(20220101)))

	fmt.Println(utils.Str2Time(strconv.Itoa(20220130)).Sub(utils.Str2Time(strconv.Itoa(20220101))).Hours() / 24)

	var rangeDay = utils.DiffNatureDays(20220101, 20221212)

	var rangeMap = map[int]int64{}

	var rangeInt = (int)(utils.Str2Time("20220130").Sub(utils.Str2Time("20220101")).Hours() / 24)

	for i := 0; i < rangeInt; i++ {
		tempTime := utils.Str2Time("20220101").AddDate(0, 0, i)
		rangeMap[utils.TimeToDayInt(tempTime)] = 0
	}
	for i, _ := range rangeMap {
		fmt.Println(i)
	}

	fmt.Println(rangeDay)
}
