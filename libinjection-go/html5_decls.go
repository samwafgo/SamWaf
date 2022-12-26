package libinjection

const (
	byteEOF      = -1
	byteBang     = 33
	bytePercent  = 37
	byteDash     = 45
	byteSlash    = 47
	byteLT       = 60
	byteEquals   = 61
	byteGT       = 62
	byteQuestion = 63
	byteRightB   = 93
)

const (
	html5TypeDataText = iota
	html5TypeTagNameOpen
	html5TypeTagNameClose
	html5TypeTagNameSelfClose
	html5TypeTagData
	html5TypeTagClose
	html5TypeAttrName
	html5TypeAttrValue
	html5TypeTagComment
	html5TypeDocType
)

const (
	html5FlagsDataState = iota
	html5FlagsValueNoQuote
	html5FlagsValueSingleQuote
	html5FlagsValueDoubleQuote
	html5FlagsValueBackQuote
)

type fnH5State func() bool

type h5State struct {
	s          string
	len        int
	pos        int
	isClose    bool
	state      fnH5State
	tokenStart string
	tokenLen   int
	tokenType  int
}
