package libinjection

import "strings"

type sqliToken struct {
	// position and length of token in original string
	pos int
	len int

	// count: in type 'v', used for number of opening '@', but maybe used in other contexts
	count int

	category byte
	strOpen  byte
	strClose byte
	val      string
}

const (
	maxTokens = 5
	tokenSize = 32
)

// Look forward for doubling of delimiter
//
// case 'foo''bar' -> foo''bar
//
// ending quote is not duplicated (i.e. escaped)
// since it's the wrong or EOL
func (t *sqliToken) parseStringCore(s string, length, pos, offset int, delimiter byte) int {
	// offset is to skip the perhaps first quote char
	var (
		str = s[pos+offset:]
	)

	if offset > 0 {
		// this is real quote
		t.strOpen = delimiter
	} else {
		// this was a simulated quote
		t.strOpen = byteNull
	}

	for {
		index := strings.IndexByte(str, delimiter)
		if index != -1 {
			str = str[index:]
		}

		switch {
		case index == -1:
			// string ended with no trailing quote
			// assign what we have
			t.assign(sqliTokenTypeString, pos+offset, length-pos-offset, s[pos+offset:])
			t.strClose = byteNull
			return length
		case isBackslashEscaped(s[pos+offset : pos+offset+strings.Index(s[pos+offset:], str)]):
			// keep going, move ahead one character
			str = str[1:]
			continue
		case isDoubleDelimiterEscaped(str):
			// keep going, move ahead two characters
			str = str[2:]
			continue
		default:
			// hey it's a normal string
			t.assign(sqliTokenTypeString, pos+offset, len(s[pos+offset:])-len(str), s[pos+offset:])
			t.strClose = delimiter
			return len(s) - len(str) + 1
		}
	}
}

func (t *sqliToken) assign(tokenType byte, pos, length int, value string) {
	var last int
	if length < tokenSize {
		last = length
	} else {
		last = tokenSize - 1
	}

	t.category = tokenType
	t.pos = pos
	t.len = last
	t.val = value[:last]
}

func (t *sqliToken) isUnaryOp() bool {
	if t.category != sqliTokenTypeOperator {
		return false
	}

	switch t.len {
	case 1:
		return t.val[0] == '+' || t.val[0] == '-' || t.val[0] == '!' || t.val[0] == '~'
	case 2:
		return t.val[0] == '!' && t.val[1] == '!'
	case 3:
		return toUpperCmp("NOT", t.val[:3])
	default:
		return false
	}
}

func (t *sqliToken) isArithmeticOp() bool {
	return t.category == sqliTokenTypeOperator && t.len == 1 &&
		(t.val[0] == '*' || t.val[0] == '/' || t.val[0] == '+' || t.val[0] == '-' || t.val[0] == '%')
}
