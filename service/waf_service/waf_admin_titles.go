package waf_service

import "SamWaf/wafconfig"

type WafAdminTitlesService struct{}

func (WafAdminTitlesService) Get() wafconfig.AdminTitles {
	return wafconfig.GetAdminTitles()
}

func (WafAdminTitlesService) Update(titles wafconfig.AdminTitles) error {
	return wafconfig.UpdateAdminTitles(titles)
}
