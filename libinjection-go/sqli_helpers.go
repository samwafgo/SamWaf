package libinjection

import (
	"strings"
)

func flag2Delimiter(flag int) byte {
	switch {
	case (flag & sqliFlagQuoteSingle) != 0:
		return byteSingle
	case (flag & sqliFlagQuoteDouble) != 0:
		return byteDouble
	default:
		return byteNull
	}
}

// OK! "	\"	" one backslash = escaped!
//
//		   "   \\"	" two backslash = not escaped!
//	    "  \\\"	" three backslash = escaped!
func isBackslashEscaped(str string) bool {
	if strings.IndexByte(str, '\\') == -1 {
		return false
	}

	var count = 0
	for i := len(str) - 1; i >= 0; i-- {
		if str[i] == '\\' {
			count++
		} else {
			break
		}
	}
	// if number of backslashes is odd, it is escaped
	return count%2 != 0
}

func isDoubleDelimiterEscaped(str string) bool {
	return len(str) >= 2 && str[0] == str[1]
}

func isByteWhite(ch byte) bool {
	// ' '  space is 0x32
	// '\t  0x09 \011 horizontal tab
	// '\n' 0x0a \012 new line
	// '\v' 0x0b \013 vertical tab
	// '\f' 0x0c \014 new page
	// '\r' 0x0d \015 carriage return
	// 0x00 \000 null (oracle)
	// 0xa0 \240 is Latin-1
	return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\v' || ch == '\f' || ch == '\r' || ch == '\240' || ch == '\000'
}

// Find the largest string containing certain characters.
//
// if accept is "ABC", then this function would be similar to
// regexp.match(str, "[ABC]*")
func strLenSpn(s string, length int, accept string) int {
	for i := 0; i < length; i++ {
		if strings.IndexByte(accept, s[i]) == -1 {
			return i
		}
	}

	return length
}

func strLenCSpn(s string, length int, accept []byte) int {
	for i := 0; i < length; i++ {
		if accept[s[i]] == 1 {
			return i
		}
	}

	return length
}

// This detects MySQL comments, comments that
// start with /x! We just ban these now but
// previously we attempted to parse the inside.
//
// For reference:
// the form of /x![anything]x/ or /x!12345[anything]x/
//
// MySQL3 (maybe 4), allowed this:
//
//	/x!0selectx/ 1;
//
// where 0 could be any number
//
// The last version of MySQL 3 was in 2003.
//
// It is unclear if the MySQL 3 syntax was allowed
// in MySQL 4. The last version of MySQL 4 was in 2008.
func isMysqlComment(s string, pos int) bool {
	// so far...
	// s[pos] == '/' && s[pos+1] == '*'
	if pos+2 >= len(s) {
		return false
	}

	if s[pos+2] != '!' {
		return false
	}

	return true
}

func toUpperCmp(a, b string) bool {
	return a == strings.ToUpper(b)
}

func isKeyword(key string) byte {
	return searchKeyword(key, sqlKeywords)
}

func searchKeyword(key string, keywords map[string]byte) byte {
	upperKey := strings.ToUpper(key)

	if val, ok := keywords[upperKey]; ok {
		return val
	}

	return byteNull
}
