package libinjection

import (
	"strings"
)

func (h *h5State) skipWhite() int {
	for h.pos < h.len {
		ch := h.s[h.pos]
		switch ch {
		case 0x00, 0x20, 0x09, 0x0A, 0x0B, 0x0C, 0x0D:
			h.pos++
		default:
			return int(ch)
		}
	}
	return byteEOF
}

func (h *h5State) stateEOF() bool {
	return false
}

// 12.2.4.44
func (h *h5State) stateBogusComment() bool {
	index := strings.IndexByte(h.s[h.pos:], byteGT)
	if index == -1 {
		h.tokenStart = h.s[h.pos:]
		h.tokenLen = h.len - h.pos
		h.pos = h.len
		h.state = h.stateEOF
	} else {
		h.tokenStart = h.s[h.pos:]
		h.tokenLen = index
		h.pos = h.pos + index + 1
		h.state = h.stateData
	}

	h.tokenType = html5TypeTagComment
	return true
}

// 12.2.4.44 ALT
func (h *h5State) stateBogusComment2() bool {
	pos := h.pos
	for {
		index := strings.IndexByte(h.s[pos:], bytePercent)
		if index == -1 || pos+index+1 >= h.len {
			h.tokenStart = h.s[h.pos:]
			h.tokenLen = h.len - h.pos
			h.pos = h.len
			h.tokenType = html5TypeTagComment
			h.state = h.stateEOF
			return true
		}

		if h.s[h.pos+index+1] != byteGT {
			pos = pos + index + 1
			continue
		}

		// ends in %>
		h.tokenStart = h.s[h.pos:]
		h.tokenLen = index
		h.pos = pos + index + 2
		h.state = h.stateData
		h.tokenType = html5TypeTagComment
		return true
	}
}

// 12.2.4.48
// 12.2.4.49
// 12.2.4.50
// 12.2.4.51
//   state machine spec is confusing since it can only look
//   at one character at a time but simply it's comments end by:
//   1) EOF
//   2) ending in -->
//   3) ending in -!>
func (h *h5State) stateComment() bool {
	pos := h.pos

	for {
		index := strings.IndexByte(h.s[pos:], byteDash)

		// did not find anything or has less than 3 characters
		if index == -1 || pos+index+3 > h.len {
			h.state = h.stateEOF
			h.tokenStart = h.s[h.pos:]
			h.tokenLen = h.len - h.pos
			h.tokenType = html5TypeTagComment
			return true
		}
		offset := 1

		// skip all nulls
		for pos+index+offset < h.len && h.s[pos+index+offset] == 0x00 {
			offset++
		}

		if pos+index+offset == h.len {
			h.state = h.stateEOF
			h.tokenStart = h.s[h.pos:]
			h.tokenLen = h.len - h.pos
			h.tokenType = html5TypeTagComment
			return true
		}

		ch := h.s[pos+index+offset]
		if ch != byteDash && ch != byteBang {
			pos = pos + index + 1
			continue
		}
		offset++

		if pos+index+offset == h.len {
			h.state = h.stateEOF
			h.tokenStart = h.s[h.pos:]
			h.tokenLen = h.len - h.pos
			h.tokenType = html5TypeTagComment
			return true
		}

		if h.s[pos+index+offset] != byteGT {
			pos = pos + index + 1
			continue
		}
		offset++

		// ends in --> or -!>
		h.tokenStart = h.s[h.pos:]
		h.tokenLen = index + pos - h.pos
		h.pos = pos + index + offset
		h.state = h.stateData
		h.tokenType = html5TypeTagComment
		return true
	}
}

func (h *h5State) stateCData() bool {
	pos := h.pos

	for {
		index := strings.IndexByte(h.s[pos:], byteRightB)

		// did not find anything or has less 3 chars left
		switch {
		case index == -1 || h.pos+index+3 > h.len:
			h.state = h.stateEOF
			h.tokenStart = h.s[h.pos:]
			h.tokenLen = h.len - h.pos
			h.tokenType = html5TypeDataText
			return true
		case h.s[pos+index+1] == byteRightB && h.s[pos+index+2] == byteGT:
			h.state = h.stateData
			h.tokenStart = h.s[h.pos:]
			h.tokenLen = pos + index - h.pos
			h.pos = pos + index + 3
			h.tokenType = html5TypeDataText
			return true
		default:
			pos = pos + index + 1
		}
	}

}

func (h *h5State) stateDoctype() bool {
	h.tokenStart = h.s[h.pos:]
	h.tokenType = html5TypeDocType

	index := strings.IndexByte(h.s[h.pos:], byteGT)
	if index == -1 {
		h.state = h.stateEOF
		h.tokenLen = h.len - h.pos
	} else {
		h.state = h.stateData
		h.tokenLen = index
		h.pos = h.pos + index + 1
	}

	return true
}

func (h *h5State) stateMarkupDeclarationOpen() bool {
	remaining := h.len - h.pos
	switch {
	case remaining >= 7 &&
		strings.ToLower(h.s[h.pos:h.pos+7]) == "doctype":
		return h.stateDoctype()
	case remaining >= 7 &&
		h.s[h.pos:h.pos+7] == "[CDATA[":
		h.pos += 7
		return h.stateCData()
	case remaining >= 2 &&
		h.s[h.pos:h.pos+2] == "--":
		h.pos += 2
		return h.stateComment()
	}

	return h.stateBogusComment()
}

func (h *h5State) stateSelfClosingStartTag() bool {
	if h.pos >= h.len {
		return false
	}

	ch := h.s[h.pos]
	if ch == byteGT {
		h.tokenStart = h.s[h.pos-1:]
		h.tokenLen = 2
		h.tokenType = html5TypeTagNameSelfClose
		h.state = h.stateData
		h.pos++
		return true
	}
	return h.stateBeforeAttributeName()
}

func (h *h5State) stateTagNameClose() bool {
	h.isClose = false
	h.tokenStart = h.s[h.pos:]
	h.tokenLen = 1
	h.tokenType = html5TypeTagNameClose
	h.pos++
	if h.pos < h.len {
		h.state = h.stateData
	} else {
		h.state = h.stateEOF
	}
	return true
}

// 12.2.4.10
func (h *h5State) stateTagName() bool {
	pos := h.pos

	for pos < h.len {
		ch := h.s[pos]
		switch {

		case ch == 0:
			// special non-standard case
			// allow nulls in tag name
			// some old browsers apparently allow and ignore them
			pos++
		case isH5White(ch):
			h.tokenStart = h.s[h.pos:]
			h.tokenLen = pos - h.pos
			h.tokenType = html5TypeTagNameOpen
			h.pos = pos + 1
			h.state = h.stateBeforeAttributeName
			return true
		case ch == byteSlash:
			h.tokenStart = h.s[h.pos:]
			h.tokenLen = pos - h.pos
			h.tokenType = html5TypeTagNameOpen
			h.pos = pos + 1
			h.state = h.stateSelfClosingStartTag
			return true
		case ch == byteGT:
			h.tokenStart = h.s[h.pos:]
			h.tokenLen = pos - h.pos
			if h.isClose {
				h.pos = pos + 1
				h.isClose = false
				h.tokenType = html5TypeTagClose
				h.state = h.stateData
			} else {
				h.pos = pos
				h.tokenType = html5TypeTagNameOpen
				h.state = h.stateTagNameClose
			}
			return true
		default:
			pos++
		}
	}

	h.tokenStart = h.s[h.pos:]
	h.tokenLen = h.len - h.pos
	h.tokenType = html5TypeTagNameOpen
	h.state = h.stateEOF
	return true
}

// 12.2.4.9
func (h *h5State) stateEndTagOpen() bool {
	if h.pos >= h.len {
		return false
	}

	ch := h.s[h.pos]
	if ch == byteGT {
		return h.stateData()
	} else if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') {
		return h.stateTagName()
	}

	h.isClose = false
	return h.stateBogusComment()
}

func (h *h5State) stateTagOpen() bool {
	if h.pos >= h.len {
		return false
	}

	ch := h.s[h.pos]
	switch {
	case ch == byteBang:
		h.pos++
		return h.stateMarkupDeclarationOpen()
	case ch == byteSlash:
		h.pos++
		h.isClose = true
		return h.stateEndTagOpen()
	case ch == byteQuestion:
		h.pos++
		return h.stateBogusComment()
	case ch == bytePercent:
		// this is not in spec.. alternative comment format used
		// by IE <= 9 and Safari < 4.0.3
		h.pos++
		return h.stateBogusComment2()
	case (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z'):
		return h.stateTagName()
	case ch == byteNull:
		// IE-ism NULL characters are ignored
		return h.stateTagName()
	default:
		// user input mistake in configuring state
		if h.pos == 0 {
			return h.stateData()
		}

		h.tokenStart = h.s[h.pos-1:]
		h.tokenLen = 1
		h.tokenType = html5TypeDataText
		h.state = h.stateData
		return true
	}
}

func (h *h5State) stateData() bool {
	index := strings.IndexByte(h.s[h.pos:], byteLT)
	if index == -1 {
		h.tokenStart = h.s[h.pos:]
		h.tokenLen = h.len - h.pos
		h.tokenType = html5TypeDataText
		h.state = h.stateEOF
		if h.tokenLen == 0 {
			return false
		}

	} else {
		h.tokenStart = h.s[h.pos:]
		h.tokenType = html5TypeDataText
		h.tokenLen = index
		h.pos = h.pos + index + 1
		h.state = h.stateTagOpen
		if h.tokenLen == 0 {
			return h.stateTagOpen()
		}
	}

	return true
}

func (h *h5State) stateAttributeValueNoQuote() bool {
	pos := h.pos

	for pos < h.len {
		ch := h.s[pos]
		if isH5White(ch) {
			h.tokenType = html5TypeAttrValue
			h.tokenStart = h.s[h.pos:]
			h.tokenLen = pos - h.pos
			h.pos = pos + 1
			h.state = h.stateBeforeAttributeName
			return true
		} else if ch == byteGT {
			h.tokenType = html5TypeAttrValue
			h.tokenStart = h.s[h.pos:]
			h.tokenLen = pos - h.pos
			h.pos = pos
			h.state = h.stateTagNameClose
			return true
		}

		pos++
	}

	h.state = h.stateEOF
	h.tokenStart = h.s[h.pos:]
	h.tokenLen = h.len - h.pos
	h.tokenType = html5TypeAttrValue
	return true
}

// 12.2.4.37
func (h *h5State) stateBeforeAttributeValue() bool {
	ch := h.skipWhite()

	if ch == byteEOF {
		h.state = h.stateEOF
		return false
	}

	switch uint8(ch) {
	case byteDouble:
		return h.stateAttributeValueDoubleQuote()
	case byteSingle:
		return h.stateAttributeValueSingleQuote()
	case byteTick:
		// non standard IE
		return h.stateAttributeValueBackQuote()
	default:
		return h.stateAttributeValueNoQuote()
	}
}

func (h *h5State) stateAfterAttributeName() bool {
	ch := h.skipWhite()

	switch ch {
	case byteEOF:
		return false

	case byteSlash:
		h.pos++
		return h.stateSelfClosingStartTag()

	case byteEquals:
		h.pos++
		return h.stateBeforeAttributeValue()

	case byteGT:
		return h.stateTagNameClose()

	default:
		return h.stateAttributeName()
	}
}

func (h *h5State) stateAttributeName() bool {
	pos := h.pos + 1

	for pos < h.len {
		ch := h.s[pos]
		switch {
		case isH5White(ch):
			h.tokenStart = h.s[h.pos:]
			h.tokenLen = pos - h.pos
			h.tokenType = html5TypeAttrName
			h.state = h.stateAfterAttributeName
			h.pos = pos + 1
			return true
		case ch == byteSlash:
			h.tokenStart = h.s[h.pos:]
			h.tokenLen = pos - h.pos
			h.tokenType = html5TypeAttrName
			h.state = h.stateSelfClosingStartTag
			h.pos = pos + 1
			return true
		case ch == byteEquals:
			h.tokenStart = h.s[h.pos:]
			h.tokenLen = pos - h.pos
			h.tokenType = html5TypeAttrName
			h.state = h.stateBeforeAttributeValue
			h.pos = pos + 1
			return true
		case ch == byteGT:
			h.tokenStart = h.s[h.pos:]
			h.tokenLen = pos - h.pos
			h.tokenType = html5TypeAttrName
			h.state = h.stateTagNameClose
			h.pos = pos
			return true
		default:
			pos++
		}
	}

	// EOF
	h.tokenStart = h.s[h.pos:]
	h.tokenLen = h.len - h.pos
	h.tokenType = html5TypeAttrName
	h.state = h.stateEOF
	h.pos = h.len
	return true
}

func (h *h5State) stateBeforeAttributeName() bool {
	ch := h.skipWhite()
	switch ch {
	case byteEOF:
		return false

	case byteSlash:
		h.pos++
		return h.stateSelfClosingStartTag()

	case byteGT:
		h.state = h.stateData
		h.tokenStart = h.s[h.pos:]
		h.tokenLen = 1
		h.tokenType = html5TypeTagNameClose
		h.pos++
		return true

	default:
		return h.stateAttributeName()
	}
}

// 12.2.4.41
func (h *h5State) stateAfterAttributeValueQuotedState() bool {
	if h.pos >= h.len {
		return false
	}

	ch := h.s[h.pos]
	switch {
	case isH5White(ch):
		h.pos++
		return h.stateBeforeAttributeName()
	case ch == byteSlash:
		h.pos++
		return h.stateSelfClosingStartTag()
	case ch == byteGT:
		h.tokenStart = h.s[h.pos:]
		h.tokenLen = 1
		h.tokenType = html5TypeTagNameClose
		h.pos++
		h.state = h.stateData
		return true
	default:
		return h.stateBeforeAttributeName()
	}
}

func (h *h5State) stateAttributeValueQuote(ch byte) bool {
	// skip initial quote in normal case.
	// don't do this "if (pos == 0)" since it means we have started
	// in a non-data state.  given an input of '><foo
	// we want to make 0-length attribute name
	if h.pos > 0 {
		h.pos++
	}

	index := strings.IndexByte(h.s[h.pos:], ch)
	if index == -1 {
		h.tokenStart = h.s[h.pos:]
		h.tokenLen = h.len - h.pos
		h.tokenType = html5TypeAttrValue
		h.state = h.stateEOF
	} else {
		h.tokenStart = h.s[h.pos:]
		h.tokenLen = index
		h.tokenType = html5TypeAttrValue
		h.state = h.stateAfterAttributeValueQuotedState
		h.pos += h.tokenLen + 1
	}
	return true
}

func (h *h5State) stateAttributeValueSingleQuote() bool {
	return h.stateAttributeValueQuote(byteSingle)
}

func (h *h5State) stateAttributeValueDoubleQuote() bool {
	return h.stateAttributeValueQuote(byteDouble)
}

func (h *h5State) stateAttributeValueBackQuote() bool {
	return h.stateAttributeValueQuote(byteTick)
}

func (h *h5State) init(input string, flags int) {
	h.s = input
	h.len = len(input)

	switch flags {
	case html5FlagsDataState:
		h.state = h.stateData

	case html5FlagsValueNoQuote:
		h.state = h.stateBeforeAttributeName

	case html5FlagsValueSingleQuote:
		h.state = h.stateAttributeValueSingleQuote

	case html5FlagsValueDoubleQuote:
		h.state = h.stateAttributeValueDoubleQuote

	case html5FlagsValueBackQuote:
		h.state = h.stateAttributeValueBackQuote

	}
}

func (h *h5State) next() bool {
	return h.state()
}
