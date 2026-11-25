package iplocation

import (
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/ipipdotnet/ipdb-go"
	"github.com/lionsoul2014/ip2region/binding/golang/xdb"
)

func TestCountryCodes(t *testing.T) {
	codes := CountryCodes()
	if !slices.IsSorted(codes) || len(slices.Compact(slices.Clone(codes))) != 249 || len(codes) != 249 {
		t.Fatalf("expected 249 sorted, unique codes, got %v", codes)
	}
	for _, code := range []string{"CN", "GB", "HK", "MO", "TW", "US"} {
		if !slices.Contains(codes, code) {
			t.Errorf("missing %s", code)
		}
	}
	for _, code := range []string{"", "AP", "EU", "UK", "XK", "ZZ"} {
		if slices.Contains(codes, code) {
			t.Errorf("unexpected %q", code)
		}
	}
	codes[0] = "ZZ"
	if CountryCodes()[0] != "AD" {
		t.Fatal("returned slice must not modify the enum")
	}
}

func TestCountryNames(t *testing.T) {
	for _, tc := range []struct{ name, want string }{
		{"  中国  ", "CN"}, {"中國", "CN"}, {"China", "CN"}, {"中国香港", "HK"}, {"澳門", "MO"},
		{"UNITED STATES", "US"}, {"美国", "US"}, {"美國", "US"}, {" cn ", "CN"},
		{"刚果金", "CD"}, {"刚果布", "CG"}, {"Congo", "CG"}, {"DR Congo", "CD"},
		{"Côte d'Ivoire", "CI"}, {"Türkiye", "TR"}, {"Viet Nam", "VN"},
		{"Bosnia and Herzegovina", "BA"}, {"Cabo Verde", "CV"}, {"Eswatini", "SZ"}, {"North Macedonia", "MK"},
		{"未知", ""}, {"内网IP", ""}, {"保留地址", ""}, {"Reserved", ""},
		{"亚太地区", ""}, {"United", ""}, {"CN-53", ""}, {"0", ""}, {"ZZ", ""}, {"XK", ""},
	} {
		if got := countryCodeFromName(tc.name); got != tc.want {
			t.Errorf("name %q: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestCountryXDB(t *testing.T) {
	m := NewManager()
	t.Cleanup(m.Close)
	if err := m.ReloadFromConfig(t.TempDir(), "ip2region", "ip2region", "legacy", "legacy"); err != nil {
		t.Fatal(err)
	}
	if err := m.LoadV4Ip2Region(loadBuiltinV4(t), FormatLegacy); err != nil {
		t.Fatal(err)
	}
	assertCountryAvailability(t, m, true, false)
	assertCountry(t, m, "8.8.8.8", "US")
	assertCountry(t, m, "223.5.5.5", "CN")
	assertCountry(t, m, "::ffff:8.8.8.8", "US")
	assertCountry(t, m, "2001:4860:4860::8888", "")

	const v6 = "2400:3200::1"
	for _, tc := range []struct {
		format       DBFormat
		region, want string
	}{
		{FormatLegacy, "中国|0|浙江|杭州|电信", "CN"},
		{FormatOpenSource, "日本|东京都|东京|运营商", "JP"},
		{FormatFull, "亚洲|韩国|首尔|首尔|0|运营商|0", "KR"},
		{FormatStandard, "美国|California|Los Angeles|0|运营商|0", "US"},
		{FormatCompact, "日本|Tokyo|Tokyo|运营商|US", "JP"},
		{FormatCompact, "Reserved|0|0|0|US", ""},
		{FormatCompact, "美国|0|0|0|内网IP", ""},
		{"", "中国|0|0|0|0", "CN"},
		{"unsupported", "中国|0|0|0|0", ""},
	} {
		if err := m.LoadV6Ip2Region(xdbCountryFixture(v6, tc.region), tc.format); err != nil {
			t.Fatal(err)
		}
		assertCountryAvailability(t, m, true, tc.format != "unsupported")
		assertCountry(t, m, v6, tc.want)
	}
	m.SetV4Source(SourceGeoLite2)
	assertCountryAvailability(t, m, false, false)
	assertCountry(t, m, "8.8.8.8", "")
}

func TestBuiltinXDBCountryNameCoverage(t *testing.T) {
	data := loadBuiltinV4(t)
	version := xdb.IPv4
	header, err := xdb.NewHeader(data[:xdb.HeaderInfoLength])
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{
		"0": true, "亚太地区": true, "北美地区": true, "欧洲": true,
		"非洲地区": true, "安的列斯": true, "科索沃": true, "Kosovo": true, "Reserved": true,
	}
	for offset := int(header.StartIndexPtr); offset <= int(header.EndIndexPtr); offset += version.SegmentIndexSize {
		record := data[offset+2*version.Bytes:]
		size := int(binary.LittleEndian.Uint16(record))
		pos := int(binary.LittleEndian.Uint32(record[2:]))
		name, _, _ := strings.Cut(string(data[pos:pos+size]), "|")
		if !seen[name] && countryCodeFromName(name) == "" {
			t.Errorf("unmapped built-in XDB country %q", name)
		}
		seen[name] = true
	}
}

func TestCountryGeoLite(t *testing.T) {
	m := NewManager()
	t.Cleanup(m.Close)
	v4 := mmdbCountryFixture(4, "GeoLite2-Country")
	if err := m.LoadV4GeoLite2(v4); err != nil {
		t.Fatal(err)
	}
	if err := m.LoadV6GeoLite2(v4); err != nil {
		t.Fatal(err)
	}
	assertCountryAvailability(t, m, true, false)
	assertCountry(t, m, "8.8.8.8", "DE")
	assertCountry(t, m, "::ffff:8.8.8.8", "DE")
	assertCountry(t, m, "200.1.1.1", "") // registered_country is not location
	assertCountry(t, m, "2001:4860:4860::8888", "")
	for _, ip := range []string{
		"", "not-a-literal", "8.8.8.8:80", "0.0.0.0", "0.1.2.3", "10.0.0.1", "127.0.0.1", "::ffff:10.0.0.1",
		"100.64.0.1", "169.254.169.254", "172.16.1.1", "192.168.0.1", "192.0.2.1", "198.18.0.1", "224.0.0.1",
	} {
		assertCountry(t, m, ip, "")
	}
	if err := m.LoadV6GeoLite2(mmdbCountryFixture(6, "GeoLite2-Country")); err != nil {
		t.Fatal(err)
	}
	assertCountryAvailability(t, m, true, true)
	assertCountry(t, m, "2001:4860:4860::8888", "DE")
	for _, ip := range []string{"::", "::1", "::10.0.0.1", "64:ff9b::10.0.0.1", "fc00::1", "fe80::1", "fec0::1", "ff02::1", "2001:db8::1", "2600::1%zone"} {
		assertCountry(t, m, ip, "")
	}
	if err := m.LoadV6GeoLite2(mmdbCountryFixture(6, "GeoLite2-ASN")); err != nil {
		t.Fatal(err)
	}
	assertCountryAvailability(t, m, true, false)
	assertCountry(t, m, "2001:4860:4860::8888", "")
}

func TestCountryIPDB(t *testing.T) {
	for _, tc := range []struct {
		name, language string
		version        uint16
		fields         []string
		payload, want  string
		ipv4, ipv6     bool
	}{
		{"prefer native", "CN", 3, []string{"country_name", "country_code"}, "日本\tUS", "US", true, true},
		{"name fallback", "CN", 1, []string{"country_name"}, "中国", "CN", true, false},
		{"English", "EN", 2, []string{"country_name", "country_code"}, "Canada\t", "CA", false, true},
		{"unknown", "CN", 1, []string{"country_name", "country_code"}, "未知\tZZ", "", true, false},
		{"missing field", "CN", 3, []string{"city_name"}, "上海", "", false, false},
		{"unsupported language", "RU", 3, []string{"country_name"}, "Canada", "", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewManager()
			t.Cleanup(m.Close)
			path := filepath.Join(t.TempDir(), "fixture.ipdb")
			if err := os.WriteFile(path, ipdbCountryFixture(t, tc.language, tc.version, tc.fields, tc.payload), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := m.LoadIpdb(path); err != nil {
				t.Fatal(err)
			}
			assertCountryAvailability(t, m, false, false) // inactive until selected
			m.SetBothSourceIpdb()
			assertCountryAvailability(t, m, tc.ipv4, tc.ipv6)
			for ip, available := range map[string]bool{"8.8.8.8": tc.ipv4, "2600::1": tc.ipv6} {
				want := ""
				if available {
					want = tc.want
				}
				assertCountry(t, m, ip, want)
			}
		})
	}
}

func TestCountryUnavailable(t *testing.T) {
	var m *Manager
	assertCountryAvailability(t, m, false, false)
	assertCountry(t, m, "8.8.8.8", "")
	m = NewManager()
	assertCountryAvailability(t, m, false, false)
	assertCountry(t, m, "8.8.8.8", "")
	if err := m.LoadV4Ip2Region([]byte{1}, FormatLegacy); err == nil {
		t.Fatal("truncated XDB accepted")
	}
	if err := m.LoadV4Ip2Region(xdbCountryFixture("2600::1", "美国|0|0|0|0"), FormatLegacy); err == nil {
		t.Fatal("IPv6 XDB accepted by the IPv4 slot")
	}
	assertCountryAvailability(t, m, false, false)
	data := xdbCountryFixture("8.8.8.8", "美国|0|0|0|0")
	binary.LittleEndian.PutUint32(data[xdbIndexStart+10:], uint32(len(data)+1))
	if err := m.LoadV4Ip2Region(data, FormatLegacy); err != nil {
		t.Fatal(err)
	}
	assertCountry(t, m, "8.8.8.8", "") // unreadable record is unknown
	m.Close()
	assertCountryAvailability(t, m, false, false)
}

func TestCountryConcurrentLookup(t *testing.T) {
	m := NewManager()
	t.Cleanup(m.Close)
	if err := m.LoadV4Ip2Region(xdbCountryFixture("8.8.8.8", "美国|0|0|0|0"), FormatLegacy); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 40; j++ {
				if m.LookupCountryCode("8.8.8.8") != "US" || m.Lookup("8.8.8.8").Country != "美国" {
					t.Error("country lookup failed during concurrent use")
					return
				}
			}
		}()
	}
	wg.Wait()
}

func assertCountry(t *testing.T, m *Manager, ip, want string) {
	t.Helper()
	if got := m.LookupCountryCode(ip); got != want {
		t.Errorf("IP %q: got %q, want %q", ip, got, want)
	}
}

func assertCountryAvailability(t *testing.T, m *Manager, wantV4, wantV6 bool) {
	t.Helper()
	if v4, v6 := m.CountryAvailability(); v4 != wantV4 || v6 != wantV6 {
		t.Errorf("country availability: got (%t, %t), want (%t, %t)", v4, v6, wantV4, wantV6)
	}
}

// A single XDB segment covers exactly the requested fixture address.
func xdbCountryFixture(addr, region string) []byte {
	ip := netip.MustParseAddr(addr).AsSlice()
	const segment = xdbIndexStart
	width := len(ip)
	pos := segment + 2*width + 6
	data := make([]byte, pos+len(region))
	binary.LittleEndian.PutUint16(data, xdb.Structure30)
	binary.LittleEndian.PutUint32(data[8:], segment)
	binary.LittleEndian.PutUint32(data[12:], segment)
	version := xdb.IPv6VersionNo
	if width == 4 {
		version = xdb.IPv4VersionNo
	}
	binary.LittleEndian.PutUint16(data[16:], uint16(version))
	vec := xdb.HeaderInfoLength + (int(ip[0])*xdb.VectorIndexCols+int(ip[1]))*xdb.VectorIndexSize
	binary.LittleEndian.PutUint32(data[vec:], segment)
	binary.LittleEndian.PutUint32(data[vec+4:], segment)
	if width == 4 {
		slices.Reverse(ip)
	}
	copy(data[segment:], ip)
	copy(data[segment+width:], ip)
	binary.LittleEndian.PutUint16(data[segment+2*width:], uint16(len(region)))
	binary.LittleEndian.PutUint32(data[segment+2*width+2:], uint32(pos))
	copy(data[pos:], region)
	return data
}

// One MaxMind node points to deliberately different location and registered countries.
func mmdbCountryFixture(version byte, databaseType string) []byte {
	text := func(s string) []byte { return append([]byte{0x40 | byte(len(s))}, s...) }
	country := func(field, iso string) []byte {
		data := append([]byte{0xe1}, text(field)...)
		data = append(data, 0xe1)
		data = append(data, text("iso_code")...)
		return append(data, text(iso)...)
	}
	left, right := country("country", "DE"), country("registered_country", "FR")
	data := append([]byte{0, 0, 17, 0, 0, 17 + byte(len(left))}, make([]byte, 16)...)
	data = append(data, left...)
	data = append(data, right...)
	data = append(data, "\xab\xcd\xefMaxMind.com"...)
	data = append(data, 0xe4)
	data = append(append(data, text("node_count")...), 0xc1, 1)
	data = append(append(data, text("record_size")...), 0xa1, 24)
	data = append(append(data, text("ip_version")...), 0xa1, version)
	return append(append(data, text("database_type")...), text(databaseType)...)
}

func ipdbCountryFixture(t *testing.T, language string, version uint16, fields []string, payload string) []byte {
	t.Helper()
	body := make([]byte, 11)
	binary.BigEndian.PutUint32(body, 2)
	binary.BigEndian.PutUint32(body[4:], 2)
	binary.BigEndian.PutUint16(body[9:], uint16(len(payload)))
	body = append(body, payload...)
	meta, err := json.Marshal(ipdb.MetaData{
		IPVersion: version, Fields: fields, Languages: map[string]int{language: 0}, NodeCount: 1, TotalSize: len(body),
	})
	if err != nil {
		t.Fatal(err)
	}
	data := binary.BigEndian.AppendUint32(nil, uint32(len(meta)))
	return append(append(data, meta...), body...)
}
