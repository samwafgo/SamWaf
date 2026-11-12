package wafqueue

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"bytes"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

func saveRecordLimits(t *testing.T, req, resp int64) {
	t.Helper()
	oldReq, oldResp := global.GCONFIG_RECORD_MAX_BODY_LENGTH, global.GCONFIG_RECORD_MAX_RES_BODY_LENGTH
	oldMask := global.GCONFIG_RECORD_LOG_DESENSITIZE
	global.GCONFIG_RECORD_MAX_BODY_LENGTH = req
	global.GCONFIG_RECORD_MAX_RES_BODY_LENGTH = resp
	global.GCONFIG_RECORD_LOG_DESENSITIZE = 0
	t.Cleanup(func() {
		global.GCONFIG_RECORD_MAX_BODY_LENGTH = oldReq
		global.GCONFIG_RECORD_MAX_RES_BODY_LENGTH = oldResp
		global.GCONFIG_RECORD_LOG_DESENSITIZE = oldMask
	})
}

func oversizedLog(id string) *innerbean.WebLog {
	lg := &innerbean.WebLog{}
	v := reflect.ValueOf(lg).Elem()
	for i := 0; i < v.NumField(); i++ {
		if v.Field(i).Kind() == reflect.String && v.Type().Field(i).Tag.Get("gorm") != "-" {
			v.Field(i).SetString("start\x00\xff" + strings.Repeat("a", 65536) + "中文")
		}
	}
	lg.REQ_UUID, lg.TenantId, lg.USER_CODE, lg.HOST_CODE = id, "t1", "u1", "h1"
	lg.CREATE_TIME, lg.Day = "2026-11-12 10:00:00", 20261112
	lg.SrcByteBody = bytes.Repeat([]byte{'a', 0, 0xff, 0xe4, 0xb8, 0xad}, 12000)
	lg.SrcByteResBody = append([]byte(nil), lg.SrcByteBody...)
	lg.SrcURL = append([]byte(nil), lg.SrcByteBody...)
	return lg
}

func snapshotLog(lg *innerbean.WebLog) innerbean.WebLog {
	snapshot := *lg
	snapshot.SrcByteBody = bytes.Clone(lg.SrcByteBody)
	snapshot.SrcByteResBody = bytes.Clone(lg.SrcByteResBody)
	snapshot.SrcURL = bytes.Clone(lg.SrcURL)
	return snapshot
}

func assertPersistedStrings(t *testing.T, row any) {
	t.Helper()
	v := reflect.Indirect(reflect.ValueOf(row))
	for i := 0; i < v.NumField(); i++ {
		f, meta := v.Field(i), v.Type().Field(i)
		if meta.Anonymous && f.Kind() == reflect.Struct {
			assertPersistedStrings(t, f.Interface())
			continue
		}
		if f.Kind() != reflect.String {
			continue
		}
		s := f.String()
		if !utf8.ValidString(s) || strings.ContainsRune(s, 0) {
			t.Fatalf("%s must be valid database text", meta.Name)
		}
		for _, tag := range strings.Split(meta.Tag.Get("gorm"), ";") {
			max, size := 0, len(s)
			if tag == "type:text" {
				max = 65535
			} else if strings.HasPrefix(tag, "size:") {
				max, _ = strconv.Atoi(strings.TrimPrefix(tag, "size:"))
				size = utf8.RuneCountInString(s)
			}
			if max > 0 && size > max {
				t.Fatalf("%s: length %d exceeds %d", meta.Name, size, max)
			}
		}
	}
}

func TestLogFieldsPersistenceBounds(t *testing.T) {
	saveRecordLimits(t, 2048, 4096)
	lg := oversizedLog("bounds-1")
	before := snapshotLog(lg)
	ln := narrowFromLog(lg)
	p := extractPayload(lg, PayloadKindEvent)
	if p == nil {
		t.Fatal("payload missing")
	}
	assertPersistedStrings(t, ln)
	assertPersistedStrings(t, p)
	if ln.Truncated != 1 || p.Truncated != 1 {
		t.Fatal("modified persisted rows must be marked")
	}
	if len(p.BODY) != 2048 || len(p.POST_FORM) != 2048 || len(p.RES_BODY) != 4096 {
		t.Fatalf("body limits: %d/%d/%d", len(p.BODY), len(p.POST_FORM), len(p.RES_BODY))
	}
	if !bytes.Equal(p.SrcByteBody, lg.SrcByteBody[:2048]) ||
		!bytes.Equal(p.SrcByteResBody, lg.SrcByteResBody[:4096]) ||
		!bytes.Equal(p.SrcURL, lg.SrcURL[:65535]) {
		t.Fatal("binary columns must retain the original bytes within their limits")
	}
	if !reflect.DeepEqual(*lg, before) {
		t.Fatal("original log changed")
	}
}

func TestNarrowCharacterCapacity(t *testing.T) {
	lg := &innerbean.WebLog{
		HOST: strings.Repeat("中", 255), COUNTRY: strings.Repeat("中", 100),
		STATUS: strings.Repeat("中", 50), GUEST_IDENTIFICATION: strings.Repeat("中", 191),
	}
	ln := narrowFromLog(lg)
	if ln.Host != lg.HOST || ln.COUNTRY != lg.COUNTRY || ln.STATUS != lg.STATUS || ln.GUEST_IDENTIFICATION != lg.GUEST_IDENTIFICATION || ln.Truncated != 0 {
		t.Fatal("text within character capacity must remain complete")
	}
	lg.HOST += "文"
	ln = narrowFromLog(lg)
	if utf8.RuneCountInString(ln.Host) != 255 || ln.Truncated != 1 {
		t.Fatal("varchar character capacity mismatch")
	}
}

func TestPayloadBodyLimits(t *testing.T) {
	for _, configured := range []int64{-1, 0, 1, 4096, 65535, 65536, 1<<63 - 1} {
		t.Run(strconv.FormatInt(configured, 10), func(t *testing.T) {
			saveRecordLimits(t, configured, configured)
			lg := oversizedLog("limit-1")
			want := 65535
			if configured > 0 && configured < 65535 {
				want = int(configured)
			}
			for _, kind := range []string{PayloadKindEvent, PayloadKindSample, PayloadKindWatch} {
				p := extractPayload(lg, kind)
				for name, size := range map[string]int{
					"body": len(p.BODY), "post_form": len(p.POST_FORM), "res_body": len(p.RES_BODY),
					"raw request": len(p.SrcByteBody), "raw response": len(p.SrcByteResBody),
				} {
					if size != want {
						t.Fatalf("%s %s: got=%d, want=%d", kind, name, size, want)
					}
				}
				assertPersistedStrings(t, p)
			}
		})
	}
}

func TestPayloadShortTextCleanup(t *testing.T) {
	saveRecordLimits(t, 2048, 4096)
	lg := &innerbean.WebLog{
		REQ_UUID: "short-1", HEADER: "a\x00b\xffc", COOKIES: "a\x00b\xffc",
		BODY: "a\x00b\xffc", RES_BODY: "a\x00b\xffc", POST_FORM: "a\x00b\xffc", ResHeader: "a\x00b\xffc",
		SrcByteBody: []byte{'a', 0, 'b', 0xff, 'c'}, SrcByteResBody: []byte{'a', 0, 'b', 0xff, 'c'},
	}
	p := extractPayload(lg, PayloadKindEvent)
	for _, s := range []string{p.HEADER, p.COOKIES, p.BODY, p.RES_BODY, p.POST_FORM, p.ResHeader} {
		if s != "abc" {
			t.Fatalf("unexpected cleaned text: %q", s)
		}
	}
	if p.Truncated != 1 || !bytes.Equal(p.SrcByteBody, lg.SrcByteBody) || !bytes.Equal(p.SrcByteResBody, lg.SrcByteResBody) {
		t.Fatal("cleanup marker or binary preservation mismatch")
	}
}
