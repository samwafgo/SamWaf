package enums

const (
	ChanTypeHost = iota
	ChanTypeRule
	ChanTypeAnticc
	ChanTypeAntiCCRule //CC多规则变更
	ChanTypeLdp
	ChanTypeAllowIP
	ChanTypeAllowURL
	ChanTypeBlockIP
	ChanTypeBlockURL
	ChanTypeDelHost
	ChanTypeSensitive
	ChanTypeLoadBalance
	ChanTypeSSL
	ChanTypeHttpauth
	ChanTypeBlockingPage
	ChanTypeCacheRule
	ChanTypeHostPathRule
	ChanTypeTamperRule
)
