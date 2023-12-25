package customtype

import (
	"database/sql/driver"
	"fmt"
	"time"
)

type JsonTime time.Time

func (t JsonTime) MarshalJSON() ([]byte, error) {
	s := fmt.Sprintf(`"%s"`, time.Time(t).Format("2006-01-02 15:04:05"))
	return []byte(s), nil
}

func (t *JsonTime) UnmarshalJSON(data []byte) error {
	if data == nil || len(data) <= 1 {
		dateTime, _ := time.Parse("2006-01-02 15:04:05", "0000-00-00 00:00:00")
		*t = JsonTime(dateTime)
		return nil
	}
	// 因为实际接收到值是""2018-11-25 20:04:51""格式的，所以这里去除前后各一个"号
	str := string(data[1 : len(data)-1])
	st, err := time.Parse("2006-01-02 15:04:05", str)
	if err == nil {
		*t = JsonTime(st)
	} else {
		return err
	}
	return nil
}

func (t JsonTime) Value() (driver.Value, error) {
	tm := time.Time(t)
	//return tm.Format(constant.TimeLayout), nil
	return tm, nil
}

func (t *JsonTime) Scan(value interface{}) error {
	if value == nil {
		return nil
	}
	switch st := value.(type) {
	case time.Time:
		*t = JsonTime(st)
	case string:
		tm, err := time.Parse("2006-01-02 15:04:05", st)
		if err != nil {
			return err
		}
		*t = JsonTime(tm)
	}
	return nil
}
func (t *JsonTime) ToPtr() *JsonTime {
	return t
}
