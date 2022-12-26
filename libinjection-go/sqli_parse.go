package libinjection

import (
	"bytes"
	"strings"
)

var wordAcceptTable = buildAcceptTable(" []{}<>:\\?=@!#~+-*/&|^%(),';\t\n\v\f\r\"\240\000")
var varAcceptTable = buildAcceptTable(" <>:\\?=@!#~+-*/&|^%(),';\t\n\v\f\r'`\"")

func parseEolComment(s *sqliState) int {
	index := strings.IndexByte(s.input[s.pos:], '\n')

	if index == -1 {
		s.current.assign(sqliTokenTypeComment, s.pos, s.length-s.pos, s.input[s.pos:])
		return s.length
	}
	s.current.assign(sqliTokenTypeComment, s.pos, index, s.input[s.pos:])
	return s.pos + index + 1
}

func parseMoney(s *sqliState) int {
	if s.pos+1 == s.length {
		s.current.assign(sqliTokenTypeBareWord, s.pos, 1, "$")
		return s.length
	}

	// $1,000.00 or $1.000,00 ok!
	// This also parses $.....,,111 but that's ok
	length := strLenSpn(s.input[s.pos+1:], s.length-s.pos-1, "0123456789.,")
	switch {
	case length == 0:
		if s.input[s.pos+1] == '$' {
			// we have $$ .. find ending $$ and make string
			index := strings.Index(s.input[s.pos+2:], "$$")
			if index == -1 {
				s.current.assign(sqliTokenTypeString, s.pos+2, s.length-(s.pos+2), s.input[s.pos+2:])
				s.current.strOpen = '$'
				s.current.strClose = byteNull
				return s.length
			}
			s.current.assign(sqliTokenTypeString, s.pos+2, index, s.input[s.pos+2:])
			s.current.strOpen = '$'
			s.current.strClose = '$'
			return s.pos + 2 + index + 2
		}
		// ok it's not a number or '$$', but maybe it's pgsql "$ quoted strings"
		xlen := strLenSpn(s.input[s.pos+1:], s.length-s.pos-1, "abcdefghjiklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
		if xlen == 0 {
			// hmm, it's "$" _something_ .. just add $ and keep going
			s.current.assign(sqliTokenTypeBareWord, s.pos, 1, "$")
			return s.pos + 1
		}

		// we have $foobar?????
		if s.pos+xlen+1 == s.length || s.input[s.pos+xlen+1] != '$' {
			// not $foobar$, or fell off edge
			s.current.assign(sqliTokenTypeBareWord, s.pos, 1, "$")
			return s.pos + 1
		}

		// we have $foobar$ ... find it again
		index := strings.Index(s.input[s.pos+xlen+2:], s.input[s.pos:s.pos+xlen+2])
		if index == -1 {
			s.current.assign(sqliTokenTypeString, s.pos+xlen+2, s.length-s.pos-xlen-2, s.input[s.pos+xlen+2:])
			s.current.strOpen = '$'
			s.current.strClose = byteNull
			return s.length
		}
		// get one
		s.current.assign(sqliTokenTypeString, s.pos+xlen+2, index, s.input[s.pos+xlen+2:])
		s.current.strOpen = '$'
		s.current.strClose = '$'
		return s.pos + xlen + 2 + index + xlen + 2
	case length == 1 && s.input[s.pos+1] == '.':
		return parseWord(s)
	default:
		s.current.assign(sqliTokenTypeNumber, s.pos, length+1, s.input[s.pos:])
		return s.pos + length + 1
	}
}

func parseOther(s *sqliState) int {
	s.current.assign(sqliTokenTypeUnknown, s.pos, 1, s.input[s.pos:])
	return s.pos + 1
}

func parseWhite(s *sqliState) int {
	return s.pos + 1
}

func parseOperator1(s *sqliState) int {
	s.current.assign(sqliTokenTypeOperator, s.pos, 1, s.input[s.pos:])
	return s.pos + 1
}

func parseByte(s *sqliState) int {
	s.current.assign(s.input[s.pos], s.pos, 1, s.input[s.pos:])
	return s.pos + 1
}

// In ANSI mode, hash is an operator
// In MYSQL mode, it's a EOL comment like '--'
func parseHash(s *sqliState) int {
	s.statsCommentHash++
	if (s.flags & sqliFlagSQLMysql) != 0 {
		s.statsCommentHash++
		return parseEolComment(s)
	}
	s.current.assign(sqliTokenTypeOperator, s.pos, 1, "#")
	return s.pos + 1
}

func parseDash(s *sqliState) int {
	// five cases
	// 1) --[white] this is always a SQL comment
	// 2) --[EOL] this is a comment
	// 3) --[not white] in MYSQL this is NOT a comment but two unary operators
	// 4) --[not white] everyone else thinks this is a comment
	// 5) -[not dash] '-' is a unary operator
	switch {
	case s.pos+2 < s.length && s.input[s.pos+1] == '-' && isByteWhite(s.input[s.pos+2]):
		return parseEolComment(s)
	case s.pos+2 == s.length && s.input[s.pos+1] == '-':
		return parseEolComment(s)
	case s.pos+1 < s.length && s.input[s.pos+1] == '-' && (s.flags&sqliFlagSQLAnsi) != 0:
		// --[not white] not white case
		s.statsCommentDDX++
		return parseEolComment(s)
	default:
		s.current.assign(sqliTokenTypeOperator, s.pos, 1, "-")
		return s.pos + 1
	}
}

func parseSlash(s *sqliState) int {
	var (
		length int
		ctype  = sqliTokenTypeComment
	)
	if s.pos+1 == s.length || s.input[s.pos+1] != '*' {
		return parseOperator1(s)
	}

	// skip over initial '/*'
	index := strings.Index(s.input[s.pos+2:], "*/")
	if index == -1 {
		length = s.length - s.pos
	} else {
		length = 2 + index + 2
	}

	// postgresql allows nested comments which makes
	// which is incompatible with parsing so
	// if we find a '/x' inside the comment, then
	// make a new token.
	//
	// Also, Mysql's "conditional" comments for version
	// are an automatic black ban!
	if index != -1 &&
		strings.Contains(s.input[s.pos+2:s.pos+2+index+1], "/*") {
		ctype = sqliTokenTypeEvil
	} else if isMysqlComment(s.input, s.pos) {
		ctype = sqliTokenTypeEvil
	}

	s.current.assign(ctype, s.pos, length, s.input[s.pos:])
	return s.pos + length
}

// weird MySQL alias for NULL, "\N"(capital N only)
func parseBackSlash(s *sqliState) int {
	if s.pos+1 < s.length && s.input[s.pos+1] == 'N' {
		s.current.assign(sqliTokenTypeNumber, s.pos, 2, s.input[s.pos:])
		return s.pos + 2
	}
	s.current.assign(sqliTokenTypeBackslash, s.pos, 1, s.input[s.pos:])
	return s.pos + 1
}

func parseOperator2(s *sqliState) int {
	if s.pos+1 >= s.length {
		return parseOperator1(s)
	}

	if s.pos+2 < s.length && s.input[s.pos] == '<' && s.input[s.pos+1] == '=' && s.input[s.pos+2] == '>' {
		// special 3-char operator
		s.current.assign(sqliTokenTypeOperator, s.pos, 3, s.input[s.pos:])
		return s.pos + 3
	}

	ch := s.lookupWord(sqliLookupOperator, s.input[s.pos:s.pos+2])
	if ch != byteNull {
		s.current.assign(ch, s.pos, 2, s.input[s.pos:])
		return s.pos + 2
	}

	// not an operator, what to do with the two characters we got?
	if s.input[s.pos] == ':' {
		// ':' is not an operator
		s.current.assign(sqliTokenTypeColon, s.pos, 1, s.input[s.pos:])
		return s.pos + 1
	}
	// must be a single char operator
	return parseOperator1(s)
}

// Used when first char is a ' or "
func parseString(s *sqliState) int {
	return s.current.parseStringCore(s.input, s.length, s.pos, 1, s.input[s.pos])
}

func parseWord(s *sqliState) int {
	length := strLenCSpn(s.input[s.pos:], s.length-s.pos, wordAcceptTable)
	s.current.assign(sqliTokenTypeBareWord, s.pos, length, s.input[s.pos:])

	// now we need to look inside what we good for "." and "`"
	// and see of what is before is a keyword or not
	for i := 0; i < s.current.len; i++ {
		delimiter := s.current.val[i]
		if delimiter == '.' || delimiter == '`' {
			ch := s.lookupWord(sqliLookupWord, s.current.val[:i])
			if ch != sqliTokenTypeNone && ch != sqliTokenTypeBareWord {
				*s.current = sqliToken{}
				// we got something like "SELECT.1"
				// or SELECT `column`
				s.current.assign(ch, s.pos, i, s.input[s.pos:])
				return s.pos + i
			}
		}
	}

	// do normal lookup with word including '.'
	if length < tokenSize {
		ch := s.lookupWord(sqliLookupWord, s.current.val[:length])
		if ch == byteNull {
			ch = sqliTokenTypeBareWord
		}
		s.current.category = ch
	}
	return s.pos + length
}

func parseVar(s *sqliState) int {
	pos := s.pos + 1

	// var count is only used to reconstruct
	// the input. It counts the number of '@'
	// seen 0 in the case of NULL, 1 or 2
	//
	// move past optional other '@'
	if pos < s.length && s.input[pos] == '@' {
		pos++
		s.current.count = 2
	} else {
		s.current.count = 1
	}

	// MySQL allows @@`version`
	if pos < s.length {
		if s.input[pos] == '`' {
			s.pos = pos
			pos = parseTick(s)
			s.current.category = sqliTokenTypeVariable
			return pos
		} else if s.input[pos] == byteSingle || s.input[pos] == byteDouble {
			s.pos = pos
			pos = parseString(s)
			s.current.category = sqliTokenTypeVariable
			return pos
		}
	}

	length := strLenCSpn(s.input[pos:], s.length-pos, varAcceptTable)
	if length == 0 {
		s.current.assign(sqliTokenTypeVariable, pos, 0, s.input[pos:])
		return pos
	}
	s.current.assign(sqliTokenTypeVariable, pos, length, s.input[pos:])
	return pos + length
}

func parseNumber(s *sqliState) int {
	var (
		digits  string
		haveE   int
		haveExp int
	)

	// s.input[s.pos] == '0' has 1/10 chance of being true,
	// while s.pos+1 < s.length is almost always true
	if s.input[s.pos] == '0' && s.pos+1 < s.length {
		if s.input[s.pos+1] == 'X' || s.input[s.pos+1] == 'x' {
			digits = "0123456789ABCDEFabcdef"
		} else if s.input[s.pos+1] == 'B' || s.input[s.pos+1] == 'b' {
			digits = "01"
		}

		if digits != "" {
			length := strLenSpn(s.input[s.pos+2:], s.length-s.pos-2, digits)
			if length == 0 {
				s.current.assign(sqliTokenTypeBareWord, s.pos, 2, s.input[s.pos:])
				return s.pos + 2
			}
			s.current.assign(sqliTokenTypeNumber, s.pos, 2+length, s.input[s.pos:])
			return s.pos + 2 + length
		}
	}

	pos := s.pos
	start := s.pos
	for pos < s.length && s.input[pos]-'0' <= 9 {
		pos++
	}

	if pos < s.length && s.input[pos] == '.' {
		pos++
		for pos < s.length && s.input[pos]-'0' <= 9 {
			pos++
		}

		if pos-start == 1 {
			// only one character read so far
			s.current.assign(sqliTokenTypeDot, start, 1, ".")
			return pos
		}
	}

	if pos < s.length {
		if s.input[pos] == 'E' || s.input[pos] == 'e' {
			haveE = 1
			pos++

			if pos < s.length && (s.input[pos] == '+' || s.input[pos] == '-') {
				pos++
			}

			for pos < s.length && s.input[pos]-'0' <= 9 {
				haveExp = 1
				pos++
			}
		}
	}

	// oracle's ending float or double suffix
	// http://docs.oracle.com/cd/B19306_01/server.102/b14200/sql_elements003.htm#i139891
	if pos < s.length && (s.input[pos] == 'd' || s.input[pos] == 'D' || s.input[pos] == 'f' || s.input[pos] == 'F') {
		switch {
		case pos+1 == s.length:
			// line ends evaluate "... 1.2f$" as '1.2f'
			pos++
		case isByteWhite(s.input[pos+1]) || s.input[pos+1] == ';':
			// easy case, evaluate "... 1.2f ..." as '1.2f'
			pos++
		case s.input[pos+1] == 'u' || s.input[pos+1] == 'U':
			// a bit of a hack but makes '1fUNION' parse as '1f UNION'
			pos++
		default:
			// it's like "123FROM"
			// parse as "123" only
		}
	}

	if haveE == 1 && haveExp == 0 {
		// very special form of
		// "1234.e" "10.10E" ".E" "1e+"
		// this is a WORD not a number
		s.current.assign(sqliTokenTypeBareWord, start, pos-start, s.input[start:])
	} else {
		s.current.assign(sqliTokenTypeNumber, start, pos-start, s.input[start:])
	}
	return pos
}

// MySQL back ticks are a cross between string and a bare word.
func parseTick(s *sqliState) int {
	pos := s.current.parseStringCore(s.input, s.length, s.pos, 1, byteTick)

	// we could check to see if start and end of
	// string are both "`", i.e. make sure we have
	// matching set. `foo` vs `foo
	// but I don't think it matters much
	//
	// check value of string to see if it's a keyword,
	// function, operator, etc
	ch := s.lookupWord(sqliLookupWord, s.current.val[:s.current.len])
	if ch == sqliTokenTypeFunction {
		// if it's a function, then covert token
		s.current.category = sqliTokenTypeFunction
	} else {
		// otherwise it's a 'n' type -- mysql treats
		// everything as a bare word
		s.current.category = sqliTokenTypeBareWord
	}
	return pos
}

func parseUString(s *sqliState) int {
	pos := s.pos
	if pos+2 < s.length && s.input[pos+1] == '&' && s.input[pos+2] == byteSingle {
		s.pos += 2
		pos = parseString(s)
		s.current.strOpen = 'u'
		if s.current.strClose == byteSingle {
			s.current.strClose = 'u'
		}

		return pos
	}
	return parseWord(s)
}

// Oracle's q string
// https://livesql.oracle.com/apex/livesql/file/content_CIREYU9EA54EOKQ7LAMZKRF6P.html
func parseQString(s *sqliState) int {
	return parseQStringCore(s, 0)
}

func parseNqString(s *sqliState) int {
	if s.pos+2 < s.length && s.input[s.pos+1] == byteSingle {
		return parseEString(s)
	}
	return parseQStringCore(s, 1)
}

// hex literal string
// re: [xX]'[0123456789abcdefABCDEF]*'
// mysql has requirement if having EVEN number of chars,
// but pgsql does not
func parseXString(s *sqliState) int {
	// need at least 2 more characters
	// if next char isn't a single quote, then
	// continue as a normal word
	if s.pos+2 >= s.length || s.input[s.pos+1] != byteSingle {
		return parseWord(s)
	}

	length := strLenSpn(s.input[s.pos+2:], s.length-s.pos-2, "0123456789abcdefABCDEF")
	if s.pos+2+length >= s.length || s.input[s.pos+2+length] != byteSingle {
		return parseWord(s)
	}

	s.current.assign(sqliTokenTypeNumber, s.pos, length+3, s.input[s.pos:])
	return s.pos + 2 + length + 1
}

// binary literal string
// re: [bB]'[01]*'
func parseBString(s *sqliState) int {
	// need at least 3 characters
	// if next byte isn't a single quote, then
	// continue as normal word
	if s.pos+2 >= s.length || s.input[s.pos+1] != byteSingle {
		return parseWord(s)
	}

	length := strLenSpn(s.input[s.pos+2:], s.length-s.pos-2, "01")
	if s.pos+2+length >= s.length || s.input[s.pos+2+length] != byteSingle {
		return parseWord(s)
	}
	s.current.assign(sqliTokenTypeNumber, s.pos, length+3, s.input[s.pos:])
	return s.pos + 2 + length + 1
}

// used when first byte is E or e:
//
//	N or n: mysql "National Character set"
//	E     : psql  "Escaped String"
func parseEString(s *sqliState) int {
	if s.pos+2 >= s.length || s.input[s.pos+1] != byteSingle {
		return parseWord(s)
	}

	return s.current.parseStringCore(s.input, s.length, s.pos, 2, byteSingle)
}

// This handles MS SQLSERVER bracket words
// http://stackoverflow.com/questions/3551284/sql-serverwhat-do-brackets-mean-around-column-name
func parseBWord(s *sqliState) int {
	end := strings.IndexByte(s.input[s.pos:], ']')
	if end == -1 {
		s.current.assign(sqliTokenTypeBareWord, s.pos, s.length-s.pos, s.input[s.pos:])
		return s.length
	}
	s.current.assign(sqliTokenTypeBareWord, s.pos, end+1, s.input[s.pos:])
	return s.pos + end + 1
}

func buildAcceptTable(acceptStr string) []byte {
	accept := []byte(acceptStr)
	acceptTable := make([]byte, 256)
	for i := 0; i < 256; i++ {
		if bytes.IndexByte(accept, byte(i)) != -1 {
			acceptTable[i] = 1
		}
	}
	return acceptTable
}
