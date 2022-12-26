package libinjection

import (
	"strings"
)

type sqliState struct {
	// input, does not need to be null terminated, it is also not modified.
	input string

	// length, input length
	length int

	flags int

	// position is the index in the string during tokenization
	pos int

	// tokenVec, max tokens+1 since we use one extra token to determine the type of the previous token
	tokenVec [8]sqliToken

	// pointer to token position in tokenVec, above
	current *sqliToken

	// fingerprint pattern c-string, +1 form ending null
	fingerprint string

	// |----------------------------------------|
	// |            |/**/	|--[start]      |#  |
	// |------------|-------|---------------|---|
	// |ANSI SQL	|ok	    |ok	            |no |
	// |------------|-------|---------------|---|
	// |MYSQL       |ok     |--[whitespace] |ok |
	// |----------------------------------------|

	// Number of ddw(dash-dash-white) comments
	// These comments are in the form of
	// '--[whitespace]' or '--[EOF]'
	// All databases treat this as a comment.
	// statsCommentDDW int

	// Number of ddx(dash-dash-[not white]) comments
	//
	// ANSI SQL treats these are comments, MYSQL threats this as
	// two unary operators '-' '-'
	//
	// If you are parsing result returns FALSE and
	// stats_comment_dd > 0, you should reparse with
	// COMMENT_MYSQL
	statsCommentDDX int

	// c-style comments found /x .. x/
	// statsCommentC int

	// '#' operators or MYSQL EOL comments found
	statsCommentHash int

	// number of tokens folded away
	statsFolds int

	// total tokens processed
	statsTokens int
}

func sqliInit(s *sqliState, input string, flags int) {
	if flags == 0 {
		flags = sqliFlagQuoteNone | sqliFlagSQLAnsi
	}

	*s = sqliState{}
	s.input = input
	s.length = len(input)
	s.flags = flags
	s.current = &s.tokenVec[0]
}

// secondary api: detects SQLi in a string, GIVEN a context.
//
// A context can be:
//
//			ByteNull (\0), process as is
//			ByteSingle ('), process pretending input started with a
//			    single quote.
//	     ByteDouble ("), process pretending input started with a
//	         double quote.
func (s *sqliState) sqliFingerprint(flags int) string {
	s.reset(flags)
	length := s.fold()

	// check for magic PHP backquote comment
	// If:
	//     last token is of type "bareword"
	//     And is quoted in a backtick
	//     And isn't closed
	//     And it's empty?
	//     Then convert it to comment
	if length > 2 &&
		s.tokenVec[length-1].category == sqliTokenTypeBareWord &&
		s.tokenVec[length-1].strOpen == byteTick &&
		s.tokenVec[length-1].len == 0 &&
		s.tokenVec[length-1].strClose == byteNull {
		s.tokenVec[length-1].category = sqliTokenTypeComment
	}

	fp := strings.Builder{}

	for i := 0; i < length; i++ {
		c := s.tokenVec[i].category
		// check for 'X' in pattern, and then
		// clear out all tokens
		//
		// this means parsing could not be done
		// accurately due to pgsql's double comments
		// or other syntax that isn't consistent.
		// Should be very rare false positive
		if c == sqliTokenTypeEvil {
			s.fingerprint = string(sqliTokenTypeEvil)
			s.tokenVec[0].category = sqliTokenTypeEvil
			s.tokenVec[0].val = string(sqliTokenTypeEvil)
			return s.fingerprint
		}

		fp.WriteByte(c)
	}

	s.fingerprint = fp.String()
	return s.fingerprint
}

// See if two tokens can be merged since they are compound SQL phrases.
//
// This takes two tokens and if they are the right type,
// merges their values together. Then checks to see if the
// new value is special using the PHRASES mapping.
//
// Example: "UNION" + "ALL" = "UNION ALL"
func (s *sqliState) merge(tokenA, tokenB *sqliToken) bool {
	// first token is of right type?
	if !(tokenA.category == sqliTokenTypeKeyword ||
		tokenA.category == sqliTokenTypeBareWord ||
		tokenA.category == sqliTokenTypeOperator ||
		tokenA.category == sqliTokenTypeUnion ||
		tokenA.category == sqliTokenTypeFunction ||
		tokenA.category == sqliTokenTypeExpression ||
		tokenA.category == sqliTokenTypeTSQL ||
		tokenA.category == sqliTokenTypeSQLType) {
		return false
	}

	if !(tokenB.category == sqliTokenTypeKeyword ||
		tokenB.category == sqliTokenTypeBareWord ||
		tokenB.category == sqliTokenTypeOperator ||
		tokenB.category == sqliTokenTypeUnion ||
		tokenB.category == sqliTokenTypeFunction ||
		tokenB.category == sqliTokenTypeExpression ||
		tokenB.category == sqliTokenTypeTSQL ||
		tokenB.category == sqliTokenTypeSQLType ||
		tokenB.category == sqliTokenTypeLogicOperator) {
		return false
	}

	// +1 for space in the middle
	if tokenA.len+tokenB.len+1 > tokenSize {
		// make sure there is room for ending null
		return false
	}

	tmp := tokenA.val[:tokenA.len] + " " + tokenB.val[:tokenB.len]
	ch := s.lookupWord(sqliLookupWord, tmp)
	if ch != byteNull {
		tokenA.assign(ch, tokenA.pos, len(tmp), tmp)
		return true
	}
	return false
}

// parses and folds input, up to 5 tokens
func (s *sqliState) fold() int {
	var (
		pos         = 0 // pos is the position of where whe Next token goes
		left        = 0 // left is a count of how many tokens that are already folded or processed(i.e. part of the fingerprint)
		more        = true
		lastComment = sqliToken{}
	)

	s.current = &s.tokenVec[0]
	for more {
		more = s.tokenize()
		if !(s.current.category == sqliTokenTypeComment ||
			s.current.category == sqliTokenTypeLeftParenthesis ||
			s.current.category == sqliTokenTypeSQLType ||
			s.current.isUnaryOp()) {
			break
		}
	}

	if !more {
		// if input was only comments, unary or (, then exit
		return 0
	}
	// it's some other token
	pos++

	for {
		// do we have all the max number of tokens? if so do
		// some special cases for 5 tokens
		if pos >= maxTokens {
			if (s.tokenVec[0].category == sqliTokenTypeNumber &&
				(s.tokenVec[1].category == sqliTokenTypeOperator || s.tokenVec[1].category == sqliTokenTypeComma) &&
				s.tokenVec[2].category == sqliTokenTypeLeftParenthesis &&
				s.tokenVec[3].category == sqliTokenTypeNumber &&
				s.tokenVec[4].category == sqliTokenTypeRightParenthesis) ||
				(s.tokenVec[0].category == sqliTokenTypeBareWord &&
					s.tokenVec[1].category == sqliTokenTypeOperator &&
					s.tokenVec[2].category == sqliTokenTypeLeftParenthesis &&
					(s.tokenVec[3].category == sqliTokenTypeBareWord || s.tokenVec[3].category == sqliTokenTypeNumber) &&
					s.tokenVec[4].category == sqliTokenTypeRightParenthesis) ||
				(s.tokenVec[0].category == sqliTokenTypeNumber &&
					s.tokenVec[1].category == sqliTokenTypeRightParenthesis &&
					s.tokenVec[2].category == sqliTokenTypeComma &&
					s.tokenVec[3].category == sqliTokenTypeLeftParenthesis &&
					s.tokenVec[4].category == sqliTokenTypeNumber) ||
				(s.tokenVec[0].category == sqliTokenTypeBareWord &&
					s.tokenVec[1].category == sqliTokenTypeRightParenthesis &&
					s.tokenVec[2].category == sqliTokenTypeOperator &&
					s.tokenVec[3].category == sqliTokenTypeLeftParenthesis &&
					s.tokenVec[4].category == sqliTokenTypeBareWord) {
				if pos > maxTokens {
					s.tokenVec[1] = s.tokenVec[5]
					pos = 2
					left = 0
				} else {
					pos = 1
					left = 0
				}
			}
		}

		if !more || left >= maxTokens {
			left = pos
			break
		}

		// get up to two tokens
		for more && pos <= maxTokens && pos-left < 2 {
			s.current = &s.tokenVec[pos]
			more = s.tokenize()
			if more {
				if s.current.category == sqliTokenTypeComment {
					lastComment = *s.current
				} else {
					lastComment.category = byteNull
					pos++
				}
			}
		}

		// did we get 2 tokens? if not then we are done
		if pos-left < 2 {
			left = pos
			continue
		}

		// FOLD: "ss" -> "s"
		// "foo" "bar" is valid SQL
		// just ignore second string
		switch {
		case s.tokenVec[left].category == sqliTokenTypeString && s.tokenVec[left+1].category == sqliTokenTypeString:
			pos--
			s.statsFolds++
			continue
		case s.tokenVec[left].category == sqliTokenTypeSemiColon && s.tokenVec[left+1].category == sqliTokenTypeSemiColon:
			// not sure how various engines handle
			// 'select 1;;drop table foo' or
			// 'select 1;/x foo x/;drop table foo'
			// to prevent surprises, just fold away repeated semicolons
			pos--
			s.statsFolds++
			continue
		case (s.tokenVec[left].category == sqliTokenTypeOperator || s.tokenVec[left].category == sqliTokenTypeLogicOperator) &&
			(s.tokenVec[left+1].isUnaryOp() || s.tokenVec[left+1].category == sqliTokenTypeSQLType):
			pos--
			s.statsFolds++
			left = 0
			continue
		case s.tokenVec[left].category == sqliTokenTypeLeftParenthesis &&
			s.tokenVec[left+1].isUnaryOp():
			pos--
			s.statsFolds++
			if left > 0 {
				left--
			}
			continue
		case s.merge(&s.tokenVec[left], &s.tokenVec[left+1]):
			pos--
			s.statsFolds++
			if left > 0 {
				left--
			}
			continue
		case s.tokenVec[left].category == sqliTokenTypeSemiColon &&
			s.tokenVec[left+1].category == sqliTokenTypeFunction &&
			(s.tokenVec[left+1].val[0] == 'I' || s.tokenVec[left+1].val[0] == 'i') &&
			(s.tokenVec[left+1].val[1] == 'F' || s.tokenVec[left+1].val[1] == 'f'):
			// IF is normally a function, except in Transact-SQL where it can be used as a standalone
			// control flow operator, e.g. IF 1=1...
			// if found after a semicolon, covert from 'f' type to 'F' type
			s.tokenVec[left+1].category = sqliTokenTypeTSQL
			// left += 2
			// reparse everything, but we probably can advance left, and pos
			continue
		case (s.tokenVec[left].category == sqliTokenTypeBareWord || s.tokenVec[left].category == sqliTokenTypeVariable) &&
			s.tokenVec[left+1].category == sqliTokenTypeLeftParenthesis &&
			( // TSQL functions but common enough to be column names
			toUpperCmp("USER_ID", s.tokenVec[left].val[:s.tokenVec[left].len]) ||
				toUpperCmp("USER_NAME", s.tokenVec[left].val[:s.tokenVec[left].len]) ||

				// Function in MySQL
				toUpperCmp("DATABASE", s.tokenVec[left].val[:s.tokenVec[left].len]) ||
				toUpperCmp("PASSWORD", s.tokenVec[left].val[:s.tokenVec[left].len]) ||
				toUpperCmp("USER", s.tokenVec[left].val[:s.tokenVec[left].len]) ||

				// MySQL words that act as a variable and are a function

				// TSQL current_users is fake_variable
				// http://msdn.microsoft.com/en-us/library/ms176050.aspx
				toUpperCmp("CURRENT_USER", s.tokenVec[left].val[:s.tokenVec[left].len]) ||
				toUpperCmp("CURRENT_DATE", s.tokenVec[left].val[:s.tokenVec[left].len]) ||
				toUpperCmp("CURRENT_TIME", s.tokenVec[left].val[:s.tokenVec[left].len]) ||
				toUpperCmp("CURRENT_TIMESTAMP", s.tokenVec[left].val[:s.tokenVec[left].len]) ||
				toUpperCmp("LOCALTIME", s.tokenVec[left].val[:s.tokenVec[left].len]) ||
				toUpperCmp("LOCALTIMESTAMP", s.tokenVec[left].val[:s.tokenVec[left].len])):
			// pos is the same
			// other conversions need to go here... for instance
			// password CAN be a function, coalesce CAN be a funtion
			s.tokenVec[left].category = sqliTokenTypeFunction
			continue
		case s.tokenVec[left].category == sqliTokenTypeKeyword &&
			(toUpperCmp("IN", s.tokenVec[left].val[:s.tokenVec[left].len]) ||
				toUpperCmp("NOT IN", s.tokenVec[left].val[:s.tokenVec[left].len])):
			if s.tokenVec[left+1].category == sqliTokenTypeLeftParenthesis {
				// got ... IN ( ... (or 'NOT IN')
				// it's an operator
				s.tokenVec[left].category = sqliTokenTypeOperator
			} else {
				// it's nothing
				s.tokenVec[left].category = sqliTokenTypeBareWord
			}

			// "IN" can be used as "IN BOOLEAN MODE" for mysql
			// in which case merging of words can be done later
			// otherwise it acts as an equality operator __ IN (values..)
			//
			// here we got "IN" "(" so it's an operator.
			// also, back track to handle "NOT IN"
			// might need to do the same with like
			// two use cases   "foo" LIKE "BAR" (normal operator)
			// "foo" = LIKE(1,2)
			continue
		case s.tokenVec[left].category == sqliTokenTypeOperator &&
			(toUpperCmp("LIKE", s.tokenVec[left].val[:s.tokenVec[left].len]) ||
				toUpperCmp("NOT LIKE", s.tokenVec[left].val[:s.tokenVec[left].len])):
			if s.tokenVec[left+1].category == sqliTokenTypeLeftParenthesis {
				// SELECT LIKE(...
				// it's a function
				s.tokenVec[left].category = sqliTokenTypeFunction
			}
		case s.tokenVec[left].category == sqliTokenTypeSQLType &&
			(s.tokenVec[left+1].category == sqliTokenTypeBareWord ||
				s.tokenVec[left+1].category == sqliTokenTypeNumber ||
				s.tokenVec[left+1].category == sqliTokenTypeSQLType ||
				s.tokenVec[left+1].category == sqliTokenTypeLeftParenthesis ||
				s.tokenVec[left+1].category == sqliTokenTypeFunction ||
				s.tokenVec[left+1].category == sqliTokenTypeVariable ||
				s.tokenVec[left+1].category == sqliTokenTypeString):
			s.tokenVec[left] = s.tokenVec[left+1]
			pos--
			s.statsFolds++
			left = 0
			continue
		case s.tokenVec[left].category == sqliTokenTypeCollate && s.tokenVec[left+1].category == sqliTokenTypeBareWord:
			// there are too many collation types.. so if the bareword has a "_"
			// then it's TYPE_SQLTYPE
			if strings.IndexByte(s.tokenVec[left+1].val[:], '_') != -1 {
				s.tokenVec[left+1].category = sqliTokenTypeSQLType
				left = 0
			}
		case s.tokenVec[left].category == sqliTokenTypeBackslash:
			if s.tokenVec[left+1].isArithmeticOp() {
				// very weird case in TSQL where '\%1' is parsed as '0 % 1', etc.
				s.tokenVec[left].category = sqliTokenTypeNumber
			} else {
				// just ignore it. Again TSQL seems to parse \1 as "1"
				s.tokenVec[left] = s.tokenVec[left+1]
				pos--
				s.statsFolds++
			}

			left = 0
			continue
		case s.tokenVec[left].category == sqliTokenTypeLeftParenthesis &&
			s.tokenVec[left+1].category == sqliTokenTypeLeftParenthesis:
			pos--
			left = 0
			s.statsFolds++
			continue
		case s.tokenVec[left].category == sqliTokenTypeRightParenthesis &&
			s.tokenVec[left+1].category == sqliTokenTypeRightParenthesis:
			pos--
			left = 0
			s.statsFolds++
			continue
		case s.tokenVec[left].category == sqliTokenTypeLeftBrace &&
			s.tokenVec[left+1].category == sqliTokenTypeBareWord:
			// MySQL degenerate case
			//
			// select { ``.``.id }; -- valid!!
			// select { ``.``.``.id }; --invalid
			// select ``.``.id; --invalid     todo: this is valid
			// select { ``.id }; --invalid
			//
			// so it appears {``.``.id} is a magic case
			// I suspect this is "current database, current table, field id"
			//
			// The folding code can't look at more than 3 tokens, and
			// I don't want to make two passes.
			//
			// Since "{ ``" so rare, we are just going to blacklist it.
			//
			// Highly likely this will need revisiting!
			//
			// CREDIT @rsalgado 2013-11-25
			if s.tokenVec[left+1].len == 0 {
				s.tokenVec[left+1].category = sqliTokenTypeEvil
				return left + 2
			}

			// weird ODBC / MySQL {foo expr} --> expr
			// but for this rule we just strip away the "{ foo" part
			left = 0
			pos -= 2
			s.statsFolds += 2
			continue
		case s.tokenVec[left+1].category == sqliTokenTypeRightBrace:
			pos--
			left = 0
			s.statsFolds++
			continue
		}

		// all cases of handing 2 token is done
		// and nothing matched. Get one more token
		for more && pos <= maxTokens && pos-left < 3 {
			s.current = &s.tokenVec[pos]
			more = s.tokenize()
			if more {
				if s.current.category == sqliTokenTypeComment {
					lastComment = *s.current
				} else {
					lastComment.category = byteNull
					pos++
				}
			}
		}

		// do we have three tokens? If not then we are done
		if pos-left < 3 {
			left = pos
			continue
		}

		// now look for three token folding
		switch {

		case s.tokenVec[left].category == sqliTokenTypeNumber &&
			s.tokenVec[left+1].category == sqliTokenTypeOperator &&
			s.tokenVec[left+2].category == sqliTokenTypeNumber:
			pos -= 2
			left = 0
			continue
		case s.tokenVec[left].category == sqliTokenTypeOperator &&
			s.tokenVec[left+1].category != sqliTokenTypeLeftParenthesis &&
			s.tokenVec[left+2].category == sqliTokenTypeOperator:
			pos -= 2
			left = 0
			continue
		case s.tokenVec[left].category == sqliTokenTypeLogicOperator &&
			s.tokenVec[left+2].category == sqliTokenTypeLogicOperator:
			pos -= 2
			left = 0
			continue
		case s.tokenVec[left].category == sqliTokenTypeVariable &&
			s.tokenVec[left+1].category == sqliTokenTypeOperator &&
			(s.tokenVec[left+2].category == sqliTokenTypeVariable ||
				s.tokenVec[left+2].category == sqliTokenTypeNumber ||
				s.tokenVec[left+2].category == sqliTokenTypeBareWord):
			pos -= 2
			left = 0
			continue
		case (s.tokenVec[left].category == sqliTokenTypeBareWord ||
			s.tokenVec[left].category == sqliTokenTypeNumber) &&
			s.tokenVec[left+1].category == sqliTokenTypeOperator &&
			(s.tokenVec[left+2].category == sqliTokenTypeNumber ||
				s.tokenVec[left+2].category == sqliTokenTypeBareWord):
			pos -= 2
			left = 0
			continue
		case (s.tokenVec[left].category == sqliTokenTypeBareWord ||
			s.tokenVec[left].category == sqliTokenTypeNumber ||
			s.tokenVec[left].category == sqliTokenTypeVariable ||
			s.tokenVec[left].category == sqliTokenTypeString) &&
			s.tokenVec[left+1].category == sqliTokenTypeOperator &&
			s.tokenVec[left+1].val[:s.tokenVec[left+1].len] == "::" &&
			s.tokenVec[left+2].category == sqliTokenTypeSQLType:
			pos -= 2
			left = 0
			s.statsFolds += 2
			continue
		case (s.tokenVec[left].category == sqliTokenTypeBareWord ||
			s.tokenVec[left].category == sqliTokenTypeNumber ||
			s.tokenVec[left].category == sqliTokenTypeString ||
			s.tokenVec[left].category == sqliTokenTypeVariable) &&
			s.tokenVec[left+1].category == sqliTokenTypeComma &&
			(s.tokenVec[left+2].category == sqliTokenTypeNumber ||
				s.tokenVec[left+2].category == sqliTokenTypeBareWord ||
				s.tokenVec[left+2].category == sqliTokenTypeString ||
				s.tokenVec[left+2].category == sqliTokenTypeVariable):
			pos -= 2
			left = 0
			continue
		case (s.tokenVec[left].category == sqliTokenTypeExpression ||
			s.tokenVec[left].category == sqliTokenTypeGroup ||
			s.tokenVec[left].category == sqliTokenTypeComma) &&
			s.tokenVec[left+1].isUnaryOp() &&
			s.tokenVec[left+2].category == sqliTokenTypeLeftParenthesis:
			// got something like SELECT + (, LIMIT + (
			// remove unary operator
			s.tokenVec[left+1] = s.tokenVec[left+2]
			pos--
			left = 0
			continue
		case (s.tokenVec[left].category == sqliTokenTypeKeyword ||
			s.tokenVec[left].category == sqliTokenTypeExpression ||
			s.tokenVec[left].category == sqliTokenTypeGroup) &&
			s.tokenVec[left+1].isUnaryOp() &&
			(s.tokenVec[left+2].category == sqliTokenTypeNumber ||
				s.tokenVec[left+2].category == sqliTokenTypeBareWord ||
				s.tokenVec[left+2].category == sqliTokenTypeVariable ||
				s.tokenVec[left+2].category == sqliTokenTypeString ||
				s.tokenVec[left+2].category == sqliTokenTypeFunction):
			// remove unary operators
			// select -1
			s.tokenVec[left+1] = s.tokenVec[left+2]
			pos--
			left = 0
			continue
		case s.tokenVec[left].category == sqliTokenTypeComma &&
			s.tokenVec[left+1].isUnaryOp() &&
			(s.tokenVec[left+2].category == sqliTokenTypeNumber ||
				s.tokenVec[left+2].category == sqliTokenTypeBareWord ||
				s.tokenVec[left+2].category == sqliTokenTypeVariable ||
				s.tokenVec[left+2].category == sqliTokenTypeString):
			// interesting case turn ", -1" --> ",1" PLUS we need to back up
			// one token if possible to see if more folding can be done
			// "1, -1" --> "1"
			s.tokenVec[left+1] = s.tokenVec[left+2]
			left = 0
			pos -= 3
			continue
		case s.tokenVec[left].category == sqliTokenTypeComma &&
			s.tokenVec[left+1].isUnaryOp() &&
			s.tokenVec[left+2].category == sqliTokenTypeFunction:
			// Separate case from above since you end up with
			// 1,-sin(1) --> 1 (1)
			// Here, just do
			// 1,-sin(1) --> 1,sin(1)
			// just remove unary operator
			s.tokenVec[left+1] = s.tokenVec[left+2]
			pos--
			left = 0
			continue
		case s.tokenVec[left].category == sqliTokenTypeBareWord &&
			s.tokenVec[left+1].category == sqliTokenTypeDot &&
			s.tokenVec[left+2].category == sqliTokenTypeBareWord:
			// ignore the '.n'
			// typically is this database name .table
			pos -= 2
			left = 0
			continue
		case s.tokenVec[left].category == sqliTokenTypeExpression &&
			s.tokenVec[left+1].category == sqliTokenTypeDot &&
			s.tokenVec[left+2].category == sqliTokenTypeBareWord:
			// select . `foo` --> select `foo`
			s.tokenVec[left+1] = s.tokenVec[left+2]
			pos--
			left = 0
			continue
		case s.tokenVec[left].category == sqliTokenTypeFunction &&
			s.tokenVec[left+1].category == sqliTokenTypeLeftParenthesis &&
			s.tokenVec[left+2].category != sqliTokenTypeRightParenthesis:
			// what's going on here
			// Some SQL functions like USER() have 0 args
			// if we get User(foo), then User is not a function
			// This should be expanded since it eliminated a lot of false
			// positives.
			if toUpperCmp("USER", s.tokenVec[left].val[:s.tokenVec[left].len]) {
				s.tokenVec[left].category = sqliTokenTypeBareWord
			}
		}

		// no folding -- assume left-most token is
		// good, now use the existing 2 tokens --
		// do not get another
		left++
	}

	// if we have 4 or fewer tokens, and we had a comment token
	// at the end, add it back
	if left < maxTokens && lastComment.category == sqliTokenTypeComment {
		s.tokenVec[left] = lastComment
		left++
	}

	// sometimes we grab a 6th token to help
	// determine the type of token 5
	if left > maxTokens {
		left = maxTokens
	}

	return left
}

func (s *sqliState) tokenize() bool {
	if s.length == 0 {
		return false
	}
	*s.current = sqliToken{}

	// if we are at beginning of string and in single quote or double quote mode
	// then pretend the input starts with a quote
	if s.pos == 0 && (s.flags&(sqliFlagQuoteSingle|sqliFlagQuoteDouble)) != 0 {
		s.pos = s.current.parseStringCore(s.input, s.length, 0, 0, flag2Delimiter(s.flags))
		s.statsTokens++
		return true
	}

	for s.pos < s.length {
		// get current character
		ch := s.input[s.pos]

		// look up the parser, and cell it
		s.pos = parseByteFunctions(s, ch)

		if s.current.category != byteNull {
			s.statsTokens++
			return true
		}
	}

	return false
}

// Given a pattern determine if it's a SQLi pattern.
//
// return TRUE if SQLi, false otherwise
func (s *sqliState) blacklist() bool {

	length := len(s.fingerprint)
	if length < 1 {
		return false
	}

	fp := strings.Builder{}
	fp.Grow(length + 1)

	fp.WriteByte('0')
	for i := 0; i < length; i++ {
		ch := s.fingerprint[i]
		if ch >= 'a' && ch <= 'z' {
			ch -= 0x20
		}
		fp.WriteByte(ch)
	}

	return isKeyword(fp.String()) == sqliTokenTypeFingerprint
}

// Given a positive match for a pattern (i.e. pattern is SQLi), this function
// does additional analysis to reduce false positives.
//
// return TRUE if SQLi, false otherwise
func (s *sqliState) notWhitelist() bool {
	// We assume we got a SQLi match
	// This next part just helps reduce false positives
	length := len(s.fingerprint)

	if length > 1 && s.fingerprint[length-1] == sqliTokenTypeComment {
		// if ending comment is contains 'sp_password' then it's SQLi!
		// MS Audit log apparently ignores anything with
		// 'sp_password' in it. Unable to find primary reference to
		// this "feature" of SQL Server but seems to be known SQLi
		// technique
		if strings.Contains(s.input, "sp_password") {
			return true
		}
	}

	switch length {
	case 2:
		// case 2 are "very small SQLi" which make them
		// hard to tell from normal input...
		if s.fingerprint[1] == sqliTokenTypeUnion {
			//  not sure why but 1U comes up in SQLi attack
			//  likely part of parameter splitting/etc.
			//  lots of reasons why "1 union" might be normal
			//  input, so beep only if other SQLi things are present
			//
			//  it really is a number and 'union'
			//  otherwise it has folding or comments
			return s.statsTokens != 2
		}

		// if 'comment' is '#' ignore.. too many FP
		if s.tokenVec[1].val[0] == '#' {
			return false
		}

		// for fingerprint like 'nc', only comments of /x are treated
		// as SQL... ending comments of "--" and "#" are not SQLi
		if s.tokenVec[0].category == sqliTokenTypeBareWord &&
			s.tokenVec[1].category == sqliTokenTypeComment &&
			s.tokenVec[1].val[0] != '/' {
			return false
		}

		// if '1c' ends with '/x' then it's SQLi
		if s.tokenVec[0].category == sqliTokenTypeNumber &&
			s.tokenVec[1].category == sqliTokenTypeComment &&
			s.tokenVec[1].val[0] != '/' {
			return true
		}

		// there are some odd base64-looking query string values
		// 1234-ABCDEFEhfhihwuefi--
		// which evaluate to "1c"... these are not SQLi
		// but 1234-- probably is.
		// Make sure the "1" in "1c" is actually a true decimal number
		//
		// Need to check -original- string since the folding step
		// may have merged tokens, e.g. "1+FOO" is folded into "1"
		//
		// Note: evasion: 1*1--
		if s.tokenVec[0].category == sqliTokenTypeNumber &&
			s.tokenVec[1].category == sqliTokenTypeComment {
			if s.statsTokens > 2 {
				// we have some folding going on, highly likely SQLi
				return true
			}

			// we check that next character after the number is either whitespace,
			// or '/' or a '-' ==> SQLi
			ch := s.input[s.tokenVec[0].len]
			if ch <= 32 {
				// next char was whitespace,e.g. "1234 --"
				// this isn't exactly correct. ideally we should skip over all whitespace
				// but this seems to be ok for now
				return true
			}
			if ch == '/' && s.input[s.tokenVec[0].len+1] == '*' {
				return true
			}
			if ch == '-' && s.input[s.tokenVec[0].len+1] == '-' {
				return true
			}

			return false
		}

		// detect obvious SQLi scans.. many people put '--' in plain text
		// so only detect if input ends with '--', e.g. 1-- but not 1-- foo
		if s.tokenVec[1].len > 2 && s.tokenVec[1].val[0] == '-' {
			return false
		}

	case 3:
		// ...foo' + 'bar...
		// no opening quote, no closing quote
		// and each string has data
		// sos || s&s are string and operator || logic operator and string
		switch s.fingerprint {
		case "sos", "s&s":
			if s.tokenVec[0].strOpen == byteNull &&
				s.tokenVec[2].strClose == byteNull &&
				s.tokenVec[0].strClose == s.tokenVec[2].strOpen {
				// if ...foo" + "bar ...
				return true
			}

			if s.statsTokens == 3 {
				return false
			}

			return false
		case "s&n", "n&1", "1&1", "1&v", "1&s":
			// 'sexy and 17' not SQLi
			// 'sexy and 17<18' SQLi
			if s.statsTokens == 3 {
				return false
			}
		}
		if s.tokenVec[1].category == sqliTokenTypeKeyword && (s.tokenVec[1].len < 5 || !toUpperCmp("INTO", s.tokenVec[1].val[:4])) {
			// if it's not "INTO OUTFILE", or "INTO DUMPFILE" (MySQL)
			// then treat as safe
			return false
		}
	}

	return true
}

func (s *sqliState) checkFingerprint() bool {
	return s.blacklist() && s.notWhitelist()
}

func (s *sqliState) lookupWord(lookupType int, word string) byte {
	if lookupType == sqliLookupFingerprint {
		if s.checkFingerprint() {
			return 'X'
		}
		return byteNull
	}
	return searchKeyword(word, sqlKeywords)
}

func (s *sqliState) reset(flags int) {
	if flags == 0 {
		flags = sqliFlagQuoteNone | sqliFlagSQLAnsi
	}
	sqliInit(s, s.input, flags)
}

// Main API, detects SQLi in an input
func (s *sqliState) reparseAsMySQL() bool {
	return s.statsCommentDDX != 0 || s.statsCommentHash != 0
}

func (s *sqliState) check() bool {
	// no input? not SQLi
	if s.length == 0 {
		return false
	}

	// test input "as-is"
	s.sqliFingerprint(sqliFlagQuoteNone | sqliFlagSQLAnsi)
	if s.lookupWord(sqliLookupFingerprint, s.fingerprint) != byteNull {
		return true
	} else if s.reparseAsMySQL() {
		s.sqliFingerprint(sqliFlagQuoteNone | sqliFlagSQLMysql)
		if s.lookupWord(sqliLookupFingerprint, s.fingerprint) != byteNull {
			return true
		}
	}

	// if input has a single quote, then
	// test as if input was actually '
	// example: if input if "1' = 1", then pretend it's "'1' = 1"
	if strings.IndexByte(s.input, byteSingle) != -1 {
		s.sqliFingerprint(sqliFlagQuoteSingle | sqliFlagSQLAnsi)
		if s.lookupWord(sqliLookupFingerprint, s.fingerprint) != byteNull {
			return true
		} else if s.reparseAsMySQL() {
			s.sqliFingerprint(sqliFlagQuoteSingle | sqliFlagSQLMysql)
			if s.lookupWord(sqliLookupFingerprint, s.fingerprint) != byteNull {
				return true
			}
		}
	}

	// same as above but with a double quote
	if strings.IndexByte(s.input, byteDouble) != -1 {
		s.sqliFingerprint(sqliFlagQuoteDouble | sqliFlagSQLMysql)
		if s.lookupWord(sqliLookupFingerprint, s.fingerprint) != byteNull {
			return true
		}
	}

	// Hurry, input is not SQLi
	return false
}

// IsSQLi returns true if the input is SQLi
// It also returns the fingerprint of the SQL Injection as []byte
func IsSQLi(input string) (bool, string) {
	state := new(sqliState)
	sqliInit(state, input, 0)
	result := state.check()
	if result {
		return result, state.fingerprint
	}
	return result, ""
}
