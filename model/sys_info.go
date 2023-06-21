package model

type VersionInfo struct {
	NeedUpdate     bool   `json:"need_update"`
	Version        string `json:"version"`
	VersionName    string `json:"version_name"`
	VersionRelease string `json:"version_release"`
}
