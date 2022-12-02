package utils

import (
	"SamWaf/model"
	"strconv"
	"time"
)

func GetServerByHosts(hosts model.Hosts) string {
	if hosts.Ssl == 1 {
		return "https"
	} else {
		return "http"
	}
}

/*
*

	计算两个自然天数的间隔数
*/
func DiffNatureDays(t1, t2 int64) int {
	var SecondsOfDay int64 = 86400
	if t1 == t2 {
		return -1
	}
	if t1 > t2 {
		t1, t2 = t2, t1
	}

	diffDays := 0
	secDiff := t2 - t1
	if secDiff > SecondsOfDay {
		tmpDays := int(secDiff / SecondsOfDay)
		t1 += int64(tmpDays) * SecondsOfDay
		diffDays += tmpDays
	}

	st := time.Unix(t1, 0)
	et := time.Unix(t2, 0)
	dateFormatTpl := "20060102"
	if st.Format(dateFormatTpl) != et.Format(dateFormatTpl) {
		diffDays += 1
	}

	return diffDays
}

/**字符串->时间对象*/
func Str2Time(formatTimeStr string) time.Time {
	timeLayout := "20060102"
	loc, _ := time.LoadLocation("Local")
	theTime, _ := time.ParseInLocation(timeLayout, formatTimeStr, loc) //使用模板在对应时区转化为time.time类型

	return theTime
}

/*
*
时间转int天
*/
func TimeToDayInt(t time.Time) int {
	day, _ := strconv.Atoi(t.Format("20060102"))
	return day
}
