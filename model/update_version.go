package model

// 生成结构体{"versioncode":100,"versiondesp":"最新内容","isforce":0,"versionurl":"http://update.binaite.net/bin/","versionsign":"DSDFDFFFFF"}
type UpdateVersion struct {
	VersionCode int    `json:"versioncode"`
	VersionDesp string `json:"versiondesp"`
	IsForce     int    `json:"isforce"`
	VersionUrl  string `json:"versionurl"`
	VersionSign string `json:"versionsign"`
}
