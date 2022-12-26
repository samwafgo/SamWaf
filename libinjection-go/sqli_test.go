package libinjection

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsSQLi(t *testing.T) {
	result, fingerprint := IsSQLi("-1' and 1=1 union/* foo */select load_file('/etc/passwd')--")
	fmt.Println("=========result==========: ", result)
	fmt.Println("=======fingerprint=======: ", string(fingerprint))
}

const (
	fingerprints = "fingerprints"
	folding      = "folding"
	tokens       = "tokens"
)

func printTokenString(t *sqliToken) string {
	out := ""
	if t.strOpen != 0 {
		out += string(t.strOpen)
	}
	out += string(t.val[:t.len])
	if t.strClose != 0 {
		out += string(t.strClose)
	}
	return out
}

func printToken(t *sqliToken) string {
	out := ""
	out += string(t.category)
	out += " "
	switch t.category {
	case 's':
		out += printTokenString(t)
	case 'v':
		vc := t.count
		if vc == 1 {
			out += "@"
		} else if vc == 2 {
			out += "@@"
		}
		out += printTokenString(t)
	default:
		out += string(t.val[:t.len])
	}
	return strings.TrimSpace(out)
}

func getToken(state *sqliState, i int) *sqliToken {
	if i < 0 || i > maxTokens {
		panic("token got error!")
	}
	return &state.tokenVec[i]
}

func readTestData(filename string) map[string]string {
	f, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	var (
		data  = make(map[string]string)
		state = ""
	)

	br := bufio.NewReaderSize(f, 8192)
	for {
		line, _, err := br.ReadLine()
		if err != nil {
			if err == io.EOF {
				break
			} else {
				panic(err)
			}
		}

		str := string(bytes.TrimSpace(line))
		if str == "--TEST--" || str == "--INPUT--" || str == "--EXPECTED--" {
			state = str
		} else {
			data[state] += str + "\n"
		}
	}
	data["--TEST--"] = strings.TrimSpace(data["--TEST--"])
	data["--INPUT--"] = strings.TrimSpace(data["--INPUT--"])
	data["--EXPECTED--"] = strings.TrimSpace(data["--EXPECTED--"])
	return data
}

func runSQLiTest(t testing.TB, data map[string]string, filename string, flag string, sqliFlag int) {
	t.Helper()

	var (
		actual = ""
		state  = new(sqliState)
	)

	sqliInit(state, data["--INPUT--"], sqliFlag)

	switch flag {
	case fingerprints:
		result, fingerprints := IsSQLi(data["--INPUT--"])
		if result {
			actual = string(fingerprints[:])
		}

	case folding:
		numTokens := state.fold()
		for i := 0; i < numTokens; i++ {
			actual += printToken(getToken(state, i)) + "\n"
		}

	case tokens:
		for state.tokenize() {
			actual += printToken(state.current) + "\n"
		}
	}

	actual = strings.TrimSpace(actual)
	if actual != data["--EXPECTED--"] {
		t.Errorf("FILE: (%s)\nINPUT: (%s)\nEXPECTED: (%s)\nGOT: (%s)\n",
			filename, data["--INPUT--"], data["--EXPECTED--"], actual)
	}
}

func TestSQLiDriver(t *testing.T) {
	baseDir := "tests"
	dir, err := os.ReadDir(baseDir)
	if err != nil {
		t.Fatal(err)
	}

	for _, fi := range dir {
		p := filepath.Join(baseDir, fi.Name())
		data := readTestData(p)
		switch {
		case strings.Contains(fi.Name(), "-sqli-"):
			runSQLiTest(t, data, p, fingerprints, 0)
		case strings.Contains(fi.Name(), "-folding-"):
			runSQLiTest(t, data, p, folding, sqliFlagQuoteNone|sqliFlagSQLAnsi)
		case strings.Contains(fi.Name(), "-tokens_mysql-"):
			runSQLiTest(t, data, p, tokens, sqliFlagQuoteNone|sqliFlagSQLMysql)
		case strings.Contains(fi.Name(), "-tokens-"):
			runSQLiTest(t, data, p, tokens, sqliFlagQuoteNone|sqliFlagSQLAnsi)
		}
	}
}

type testCase struct {
	name string
	data map[string]string
}

func BenchmarkSQLiDriver(b *testing.B) {
	baseDir := "./tests/"
	dir, err := os.ReadDir(baseDir)
	if err != nil {
		b.Fatal(err)
	}

	cases := struct {
		sqli        []testCase
		folding     []testCase
		tokensMySQL []testCase
		tokens      []testCase
	}{}

	for _, fi := range dir {
		p := filepath.Join(baseDir, fi.Name())
		data := readTestData(p)
		tc := testCase{
			name: fi.Name(),
			data: data,
		}
		switch {
		case strings.Contains(fi.Name(), "-sqli-"):
			cases.sqli = append(cases.sqli, tc)
		case strings.Contains(fi.Name(), "-folding-"):
			cases.folding = append(cases.folding, tc)
		case strings.Contains(fi.Name(), "-tokens-"):
			cases.tokens = append(cases.tokens, tc)
		}
	}

	b.Run("sqli", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			for _, tc := range cases.sqli {
				tt := tc
				runSQLiTest(b, tt.data, tt.name, fingerprints, 0)
			}
		}
	})

	b.Run("folding", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			for _, tc := range cases.folding {
				tt := tc
				runSQLiTest(b, tt.data, tt.name, folding, sqliFlagQuoteNone|sqliFlagSQLAnsi)
			}
		}
	})

	b.Run("tokens", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			for _, tc := range cases.tokens {
				tt := tc
				runSQLiTest(b, tt.data, tt.name, tokens, sqliFlagQuoteNone|sqliFlagSQLAnsi)
			}
		}
	})
}
