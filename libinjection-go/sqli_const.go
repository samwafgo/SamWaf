package libinjection

const (
	// sqliFlagNone        = 0
	sqliFlagQuoteNone   = 1
	sqliFlagQuoteSingle = 2
	sqliFlagQuoteDouble = 4
	sqliFlagSQLAnsi     = 8
	sqliFlagSQLMysql    = 16
)

const (
	sqliLookupWord = 1
	// sqliLookupType        = 2
	sqliLookupOperator    = 3
	sqliLookupFingerprint = 4
)

const (
	byteNull   uint8 = 0
	byteSingle uint8 = '\''
	byteDouble uint8 = '"'
	byteTick   uint8 = '`'
)

const (
	sqliTokenTypeNone             byte = 0
	sqliTokenTypeKeyword          byte = 'k'
	sqliTokenTypeUnion            byte = 'U'
	sqliTokenTypeGroup            byte = 'B'
	sqliTokenTypeExpression       byte = 'E'
	sqliTokenTypeSQLType          byte = 't'
	sqliTokenTypeFunction         byte = 'f'
	sqliTokenTypeBareWord         byte = 'n'
	sqliTokenTypeNumber           byte = '1'
	sqliTokenTypeVariable         byte = 'v'
	sqliTokenTypeString           byte = 's'
	sqliTokenTypeOperator         byte = 'o'
	sqliTokenTypeLogicOperator    byte = '&'
	sqliTokenTypeComment          byte = 'c'
	sqliTokenTypeCollate          byte = 'A'
	sqliTokenTypeLeftParenthesis  byte = '('
	sqliTokenTypeRightParenthesis byte = ')'
	sqliTokenTypeLeftBrace        byte = '{'
	sqliTokenTypeRightBrace       byte = '}'
	sqliTokenTypeDot              byte = '.'
	sqliTokenTypeComma            byte = ','
	sqliTokenTypeColon            byte = ':'
	sqliTokenTypeSemiColon        byte = ';'
	sqliTokenTypeTSQL             byte = 'T'
	sqliTokenTypeUnknown          byte = '?'
	sqliTokenTypeEvil             byte = 'X'
	sqliTokenTypeFingerprint      byte = 'F'
	sqliTokenTypeBackslash        byte = '\\'
)
