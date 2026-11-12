//go:build crossdb

package wafqueue

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/wafdb/dialect"
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func TestLogFieldsCrossEngine(t *testing.T) {
	zlog.InitZLog(false, "console")
	saveRecordLimits(t, 2048, 4096)
	savedDB, savedHas := global.GWAF_LOCAL_LOG_DB, ipWatchHas
	var savedDialect dialect.DBDialect
	func() {
		defer func() { _ = recover() }()
		savedDialect = dialect.Get()
	}()
	t.Cleanup(func() {
		global.GWAF_LOCAL_LOG_DB = savedDB
		ipWatchHas = savedHas
		dialect.Register(savedDialect)
	})

	for _, engine := range payloadEngines() {
		t.Run(engine.name, func(t *testing.T) {
			db, teardown := engine.setup(t)
			if db == nil {
				t.Skipf("%s 未就绪，跳过", engine.name)
			}
			defer teardown()
			defer resetTier("db")()
			if err := db.AutoMigrate(&model.AccessLog{}, &model.SecurityEvent{}, &model.EventPayload{}); err != nil {
				t.Fatal(err)
			}
			global.GWAF_LOCAL_LOG_DB = db
			ipWatchHas = func(ip string) bool { return ip == "203.0.113.10" }

			bad := oversizedLog("event-bounds")
			before := snapshotLog(bad)
			good := mkLog("event-good", "203.0.113.1")
			good.RULE = "test rule"
			storeTiered([]*innerbean.WebLog{bad, good})
			if !reflect.DeepEqual(*bad, before) {
				t.Fatal("stored original changed")
			}

			for _, id := range []string{bad.REQ_UUID, good.REQ_UUID} {
				var access model.AccessLog
				var event model.SecurityEvent
				var payload model.EventPayload
				for _, row := range []any{&access, &event, &payload} {
					if err := db.Where("req_uuid = ?", id).First(row).Error; err != nil {
						t.Fatalf("%s %T: %v", id, row, err)
					}
					assertPersistedStrings(t, row)
				}
				if id == bad.REQ_UUID {
					if access.Truncated != 1 || event.Truncated != 1 || payload.Truncated != 1 {
						t.Fatal("truncation flags missing")
					}
					if payload.HEADER != cutUTF8(bad.HEADER) || len(payload.BODY) != 2048 || len(payload.RES_BODY) != 4096 {
						t.Fatal("persisted payload mismatch")
					}
					if !bytes.Equal(payload.SrcByteBody, bad.SrcByteBody[:2048]) || !bytes.Equal(payload.SrcByteResBody, bad.SrcByteResBody[:4096]) {
						t.Fatal("binary bytes changed")
					}
				} else if payload.BODY != good.BODY || payload.RES_BODY != good.RES_BODY {
					t.Fatal("adjacent short payload changed")
				}
			}

			for _, kind := range []string{PayloadKindSample, PayloadKindWatch} {
				lg := oversizedLog(kind + "-bounds")
				lg.ACTION, lg.RULE, lg.SRC_IP = "放行", "", "203.0.113.9"
				if kind == PayloadKindWatch {
					lg.SRC_IP = "203.0.113.10"
				}
				storeTiered([]*innerbean.WebLog{lg})
				if kind == PayloadKindSample {
					negSampler.FlushIfDue()
				}
				var got model.EventPayload
				if err := db.Where("req_uuid = ?", lg.REQ_UUID).First(&got).Error; err != nil {
					t.Fatalf("%s: %v", kind, err)
				}
				assertPersistedStrings(t, got)
				if got.Kind != kind || got.Truncated != 1 || len(got.RES_BODY) != 4096 || len(got.BODY) != 2048 {
					t.Fatalf("%s payload limits mismatch", kind)
				}
			}

			for _, tc := range []struct{ name, text string }{
				{"nul", "a\x00bc"}, {"invalid_utf8", "ab\xffc"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					lg := mkLog(tc.name+"-text", "203.0.113.1")
					lg.RULE = "text test"
					lg.HEADER, lg.COOKIES, lg.BODY, lg.RES_BODY, lg.POST_FORM, lg.ResHeader = tc.text, tc.text, tc.text, tc.text, tc.text, tc.text
					lg.SrcByteBody, lg.SrcByteResBody = []byte(tc.text), []byte(tc.text)
					adjacent := mkLog(tc.name+"-good", "203.0.113.2")
					adjacent.RULE = "text test"
					storeTiered([]*innerbean.WebLog{lg, adjacent})
					var rows []model.EventPayload
					if err := db.Where("req_uuid IN ?", []string{lg.REQ_UUID, adjacent.REQ_UUID}).Find(&rows).Error; err != nil {
						t.Fatal(err)
					}
					if len(rows) != 2 {
						t.Fatalf("mixed text batch: got=%d rows, want=2", len(rows))
					}
					for _, row := range rows {
						if row.ReqUUID == adjacent.REQ_UUID {
							if row.BODY != adjacent.BODY || row.RES_BODY != adjacent.RES_BODY {
								t.Fatal("adjacent text row changed")
							}
							continue
						}
						for _, s := range []string{row.HEADER, row.COOKIES, row.BODY, row.RES_BODY, row.POST_FORM, row.ResHeader} {
							if s != "abc" {
								t.Fatalf("unexpected persisted text: %q", s)
							}
						}
						if row.Truncated != 1 || !bytes.Equal(row.SrcByteBody, []byte(tc.text)) || !bytes.Equal(row.SrcByteResBody, []byte(tc.text)) {
							t.Fatal("text marker or binary preservation mismatch")
						}
					}
				})
			}

			global.GCONFIG_RECORD_MAX_BODY_LENGTH = 70000
			global.GCONFIG_RECORD_MAX_RES_BODY_LENGTH = 70000
			t.Cleanup(func() {
				global.GCONFIG_RECORD_MAX_BODY_LENGTH = 2048
				global.GCONFIG_RECORD_MAX_RES_BODY_LENGTH = 4096
			})
			capLog := oversizedLog("database-cap")
			storeTiered([]*innerbean.WebLog{capLog})
			var capped model.EventPayload
			if err := db.Where("req_uuid = ?", capLog.REQ_UUID).First(&capped).Error; err != nil {
				t.Fatal(err)
			}
			assertPersistedStrings(t, capped)
			if len(capped.BODY) != 65535 || len(capped.RES_BODY) != 65535 || len(capped.POST_FORM) != 65535 {
				t.Fatal("database text cap mismatch")
			}

			unicodeLog := mkLog("unicode-cap", "203.0.113.1")
			unicodeLog.RULE = "unicode test"
			unicodeLog.HOST, unicodeLog.COUNTRY = strings.Repeat("中", 255), strings.Repeat("国", 100)
			unicodeLog.BODY, unicodeLog.RES_BODY = strings.Repeat("中", 21846), strings.Repeat("🙂", 16384)
			storeTiered([]*innerbean.WebLog{unicodeLog})
			var unicodePayload model.EventPayload
			var unicodeAccess model.AccessLog
			if err := db.Where("req_uuid = ?", unicodeLog.REQ_UUID).First(&unicodePayload).Error; err != nil {
				t.Fatal(err)
			}
			if err := db.Where("req_uuid = ?", unicodeLog.REQ_UUID).First(&unicodeAccess).Error; err != nil {
				t.Fatal(err)
			}
			assertPersistedStrings(t, unicodePayload)
			assertPersistedStrings(t, unicodeAccess)
			if len(unicodePayload.BODY) != 65535 || len(unicodePayload.RES_BODY) != 65532 || unicodePayload.Truncated != 1 ||
				unicodeAccess.Host != unicodeLog.HOST || unicodeAccess.COUNTRY != unicodeLog.COUNTRY || unicodeAccess.Truncated != 0 {
				t.Fatal("multibyte text boundary mismatch")
			}
		})
	}
}
