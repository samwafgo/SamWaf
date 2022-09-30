package model

type Base_config struct {
	Id    int    `gorm:"primary_key" json:" - "` //
	Name  string `json:"name"`                   //
	Value string `json:"value"`                  //
}
