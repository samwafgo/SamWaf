package libinjection

import (
	"strings"
)

func isH5White(ch byte) bool {
	return ch == '\n' || ch == '\t' || ch == '\v' || ch == '\f' || ch == '\r' || ch == ' '
}

func isBlackTag(s string) bool {
	if len(s) < 3 {
		return false
	}

	for i := 0; i < len(blackTags); i++ {
		if strings.ToUpper(strings.ReplaceAll(s, "\x00", "")) == blackTags[i] {
			return true
		}
	}

	// anything SVG related
	if strings.ToUpper(s) == "SVG" {
		return true
	}

	// anything XSL(t) related
	if strings.ToUpper(s) == "XSL" {
		return true
	}

	return false
}

func isBlackAttr(s string) int {
	length := len(s)
	if length < 2 {
		return attributeTypeNone
	}

	if length >= 5 {
		// javascript on.*
		if strings.ToUpper(s[:2]) == "ON" {
			// got javascript on- attribute name
			return attributeTypeBlack
		}

		if strings.ToUpper(strings.ReplaceAll(s, "\x00", "")) == "XMLNS" ||
			strings.ToUpper(strings.ReplaceAll(s, "\x00", "")) == "XLINK" {
			// got xmlns or xlink tags
			return attributeTypeBlack
		}
	}

	for _, black := range blacks {
		if strings.ToUpper(strings.ReplaceAll(s, "\x00", "")) == black.name {
			// got banner attribute name
			return black.attributeType
		}
	}
	return attributeTypeNone
}

func htmlDecodeByteAt(s string, consumed *int) int {
	length := len(s)
	val := 0

	if length == 0 {
		*consumed = 0
		return byteEOF
	}

	*consumed = 1
	if s[0] != '&' || length < 2 {
		return int(s[0])
	}

	if s[1] != '#' {
		// normally this would be for named entities
		// but for this case we don't actually care
		return '&'
	}

	if s[2] == 'x' || s[2] == 'X' {
		ch := int(s[3])
		ch = gsHexDecodeMap[ch]
		if ch == 256 {
			// degenerate case '&#[?]'
			return '&'
		}
		val = ch
		i := 4

		for i < length {
			ch = int(s[i])
			if ch == ';' {
				*consumed = i + 1
				return val
			}
			ch = gsHexDecodeMap[ch]
			if ch == 256 {
				*consumed = i
				return val
			}
			val = val*16 + ch
			if val > 0x1000FF {
				return '&'
			}
			i++
		}
		*consumed = i
	} else {
		i := 2
		ch := int(s[i])
		if ch < '0' || ch > '9' {
			return '&'
		}
		val = ch - '0'
		i++
		for i < length {
			ch = int(s[i])
			if ch == ';' {
				*consumed = i + 1
				return val
			}
			if ch < '0' || ch > '9' {
				*consumed = i
				return val
			}
			val = val*10 + (ch - '0')
			if val > 0x1000FF {
				return '&'
			}
			i++
		}
		*consumed = i
	}
	return val
}

// Does an HTML encoded  binary string (const char*, length) start with
// a all uppercase c-string (null terminated), case insensitive!
//
// also ignore any embedded nulls in the HTML string!
func htmlEncodeStartsWith(a, b string) bool {
	var (
		consumed = 0
		first    = true
		bs       []byte
		pos      = 0
		length   = len(b)
	)

	for length > 0 {
		cb := htmlDecodeByteAt(b[pos:], &consumed)
		pos += consumed
		length -= consumed

		if first && cb <= 32 {
			// ignore all leading whitespace and control characters
			continue
		}
		first = false

		if cb == 0 || cb == 10 {
			// always ignore null characters in user input
			// always ignore vertical tab characters in user input
			continue
		}
		if cb >= 'a' && cb <= 'z' {
			cb -= 0x20
		}
		bs = append(bs, byte(cb))
	}

	return strings.Contains(string(bs), a)
}

func isBlackURL(s string) bool {
	urls := []string{
		"DATA",        // data url
		"VIEW-SOURCE", // view source url
		"VBSCRIPT",    // obsolete but interesting signal
		"JAVA",        // covers JAVA, JAVASCRIPT, + colon
	}

	//  HEY: this is a signed character.
	//  We are intentionally skipping high-bit characters too
	//  since they are not ASCII, and Opera sometimes uses UTF-8 whitespace.
	//
	//  Also in EUC-JP some of the high bytes are just ignored.
	str := strings.TrimLeftFunc(s, func(r rune) bool {
		return r <= 32 || r >= 127
	})

	for _, url := range urls {
		if htmlEncodeStartsWith(url, str) {
			return true
		}
	}
	return false
}
