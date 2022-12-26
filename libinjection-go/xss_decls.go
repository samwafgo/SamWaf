package libinjection

const (
	attributeTypeNone = iota
	attributeTypeBlack
	attributeTypeAttrURL
	attributeTypeStyle
	attributeTypeAttrIndirect
)

type stringType struct {
	name          string
	attributeType int
}

var blackTags = []string{
	"APPLET",
	"BASE",
	"COMMENT", // IE http://html5sec.org/#38
	"EMBED",
	"FRAME",
	"FRAMESET",
	"HANDLER", // Opera SVG, effectively a script tag
	"IFRAME",
	"IMPORT",
	"ISINDEX",
	"LINK",
	"LISTENER",
	"META",
	"NOSCRIPT",
	"OBJECT",
	"SCRIPT",
	"STYLE",
	"VMLFRAME",
	"XML",
	"XSS",
}

// view-source:
// data:
// javascript:
var blacks = []stringType{
	{"ACTION", attributeTypeAttrURL},             // form
	{"ATTRIBUTENAME", attributeTypeAttrIndirect}, // SVG allow indirection of attribute names
	{"BY", attributeTypeAttrURL},                 // SVG
	{"BACKGROUND", attributeTypeAttrURL},         // IE6, O11
	{"DATAFORMATAS", attributeTypeBlack},         // IE
	{"DATASRC", attributeTypeBlack},              // IE
	{"DYNSRC", attributeTypeAttrURL},             // Obsolete img attribute
	{"FILTER", attributeTypeStyle},               // Opera, SVG inline style
	{"FORMACTION", attributeTypeAttrURL},         // HTML 5
	{"FOLDER", attributeTypeAttrURL},             // Only on A tags, IE-only
	{"FROM", attributeTypeAttrURL},               // SVG
	{"HANDLER", attributeTypeAttrURL},            // SVG Tiny, Opera
	{"HREF", attributeTypeAttrURL},
	{"LOWSRC", attributeTypeAttrURL}, // Obsolete img attribute
	{"POSTER", attributeTypeAttrURL}, // Opera 10,11
	{"SRC", attributeTypeAttrURL},
	{"STYLE", attributeTypeStyle},
	{"TO", attributeTypeAttrURL},     // SVG
	{"VALUES", attributeTypeAttrURL}, // SVG
	{"XLINK:HREF", attributeTypeAttrURL},
}

var gsHexDecodeMap = []int{
	256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
	256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
	256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
	256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 256, 256,
	256, 256, 256, 256, 256, 10, 11, 12, 13, 14, 15, 256,
	256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
	256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
	256, 10, 11, 12, 13, 14, 15, 256, 256, 256, 256, 256,
	256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
	256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
	256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
	256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
	256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
	256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
	256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
	256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
	256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
	256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
	256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
	256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
	256, 256, 256, 256,
}
