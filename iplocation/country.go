package iplocation

import (
	"net"
	"net/netip"
	"slices"
	"strings"

	"github.com/ipipdotnet/ipdb-go"
	"github.com/lionsoul2014/ip2region/binding/golang/xdb"
	"github.com/oschwald/geoip2-golang"
	"golang.org/x/text/language"
	"golang.org/x/text/language/display"
	"golang.org/x/text/unicode/norm"
)

// ISO 3166-1 assigned alpha-2 codes. CLDR also names unassigned codes and
// aggregates, so it supplies names but does not determine the policy enum.
const isoAlpha2 = `AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ
BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ
CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ
DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR
GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY
HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP
KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY
MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ
NA NC NE NF NG NI NL NO NP NR NU NZ OM
PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW
SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ
TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ
VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW`

var (
	countryCodes = strings.Fields(isoAlpha2)
	countryNames = buildCountryNames()
)

// CountryCodes returns the sorted ISO 3166-1 alpha-2 enum, without an unknown value.
func CountryCodes() []string {
	return slices.Clone(countryCodes)
}

func assignedCountryCode(value string) string {
	value = strings.TrimSpace(value)
	if len(value) == 2 {
		value = strings.ToUpper(value)
		if _, ok := slices.BinarySearch(countryCodes, value); ok {
			return value
		}
	}
	return ""
}

func countryNameKey(name string) string {
	return norm.NFC.String(strings.ReplaceAll(strings.ToLower(strings.TrimSpace(name)), "’", "'"))
}

func buildCountryNames() map[string]string {
	names := make(map[string]string)
	for _, tag := range []language.Tag{language.English, language.SimplifiedChinese, language.TraditionalChinese} {
		namer := display.Regions(tag)
		for _, code := range countryCodes {
			region, err := language.ParseRegion(code)
			if err != nil {
				continue
			}
			if name := countryNameKey(namer.Name(region)); name != "" {
				if previous, exists := names[name]; !exists {
					names[name] = code
				} else if previous != code {
					names[name] = ""
				}
			}
		}
	}

	// Exact provider spellings and legacy names with an unambiguous ISO equivalent.
	aliases := map[string]string{
		"AE": "阿联酋|阿聯酋",
		"AG": "Antigua and Barbuda",
		"AX": "奥兰群岛|奧蘭群島|Åland",
		"BA": "波黑|Bosnia and Herzegovina",
		"BL": "圣巴泰勒米|聖巴泰勒米|Saint Barthélemy",
		"BN": "Brunei Darussalam",
		"CC": "Cocos Islands",
		"CD": "刚果金|剛果金|刚果（金）|剛果（金）|刚果(金)|剛果(金)|刚果民主共和国|剛果民主共和國|DR Congo|Democratic Republic of the Congo",
		"CF": "中非",
		"CG": "刚果布|剛果布|刚果（布）|剛果（布）|刚果(布)|剛果(布)|刚果共和国|剛果共和國|Congo|Republic of the Congo",
		"CV": "Cabo Verde|Cape Verde",
		"DO": "多米尼加",
		"FK": "福克兰群岛|福克蘭群島",
		"FM": "密克罗尼西亚|密克羅尼西亞",
		"GB": "大不列颠及北爱尔兰联合王国|Great Britain|UK",
		"GS": "南乔治亚岛和南桑威奇群岛|South Georgia and the South Sandwich Islands",
		"HK": "香港|中国香港|中國香港|香港特别行政区|香港特別行政區",
		"KN": "圣基茨和尼维斯|聖基茨和尼維斯|Saint Kitts and Nevis",
		"LC": "Saint Lucia",
		"MK": "马其顿|馬其頓|North Macedonia|Macedonia",
		"MM": "Myanmar|Burma",
		"MF": "圣马丁|聖馬丁|Saint Martin",
		"MO": "澳门|澳門|中国澳门|中國澳門|澳门特别行政区|澳門特別行政區|Macao|Macau",
		"MS": "蒙塞拉特岛|蒙塞拉特島",
		"PM": "圣皮埃尔和密克隆群岛|Saint Pierre and Miquelon",
		"PN": "Pitcairn",
		"PS": "巴勒斯坦|Palestine",
		"SH": "阿森松岛|阿森松島|Saint Helena|Ascension Island",
		"SJ": "Svalbard and Jan Mayen",
		"ST": "圣多美和普林西比|Sao Tome and Principe",
		"SX": "荷属圣马丁|荷屬聖馬丁",
		"SZ": "斯威士兰|史瓦濟蘭|Eswatini|Swaziland",
		"TC": "Turks and Caicos Islands",
		"TF": "法国南部领地|French Southern Territories",
		"TK": "托克劳群岛|托克勞群島",
		"TR": "Turkey|Türkiye",
		"TT": "Trinidad and Tobago",
		"TW": "台湾|台灣|臺灣|中国台湾|中國台灣|中國臺灣",
		"UM": "US Minor Outlying Islands",
		"US": "美利坚合众国|United States of America|USA",
		"VA": "梵蒂冈|梵蒂岡|Holy See",
		"VC": "Saint Vincent and the Grenadines",
		"VI": "United States Virgin Islands",
		"VN": "Viet Nam",
		"WF": "瓦利斯和富图纳群岛|Wallis and Futuna",
	}
	for code, spellings := range aliases {
		for _, spelling := range strings.Split(spellings, "|") {
			names[countryNameKey(spelling)] = code
		}
	}
	return names
}

func countryCodeFromName(name string) string {
	if code := assignedCountryCode(name); code != "" {
		return code
	}
	return countryNames[countryNameKey(name)]
}

var nonGeographicPrefixes = [...]netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), // Carrier-grade NAT
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/96"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("fec0::/10"), // Deprecated site-local addresses
}

// LookupCountryCode queries the active local database. It returns empty for
// invalid, internal or unmapped IPs, and when the configured reader is unavailable.
func (m *Manager) LookupCountryCode(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if m == nil || err != nil || addr.Zone() != "" {
		return ""
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() {
		return ""
	}
	for _, prefix := range nonGeographicPrefixes {
		if prefix.Contains(addr) {
			return ""
		}
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.countryBackend(addr.Is4()).lookup(addr)
}

// CountryAvailability reports whether the active local provider can process
// each family. It does not guarantee any particular address has a country.
func (m *Manager) CountryAvailability() (ipv4, ipv6 bool) {
	if m == nil {
		return false, false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.countryBackend(true).available(true), m.countryBackend(false).available(false)
}

type countryBackend struct {
	source   DBSource
	format   DBFormat
	searcher *xdb.Searcher
	geo      *geoip2.Reader
	ipdb     *ipdb.City
}

// countryBackend is called under the manager read lock.
func (m *Manager) countryBackend(ipv4 bool) countryBackend {
	if ipv4 {
		return countryBackend{m.v4Source, m.v4Format, m.v4Searcher, m.v4GeoReader, m.ipdbReader}
	}
	return countryBackend{m.v6Source, m.v6Format, m.v6Searcher, m.v6GeoReader, m.ipdbReader}
}

func supportsXDBCountry(format DBFormat) bool {
	switch format {
	case "", FormatLegacy, FormatOpenSource, FormatFull, FormatStandard, FormatCompact:
		return true
	}
	return false
}

func (b countryBackend) available(ipv4 bool) bool {
	switch b.source {
	case SourceIp2Region:
		return b.searcher != nil && supportsXDBCountry(b.format)
	case SourceGeoLite2:
		if b.geo == nil {
			return false
		}
		meta := b.geo.Metadata()
		if meta.IPVersion != 6 && (!ipv4 || meta.IPVersion != 4) {
			return false
		}
		// Country rejects unsupported database types before checking the IP.
		// A nil IP does not perform a tree lookup.
		record, _ := b.geo.Country(nil)
		return record != nil
	case SourceIpdb:
		if b.ipdb == nil || (ipv4 && !b.ipdb.IsIPv4()) || (!ipv4 && !b.ipdb.IsIPv6()) {
			return false
		}
		langs, fields := b.ipdb.Languages(), b.ipdb.Fields()
		return (slices.Contains(langs, "CN") || slices.Contains(langs, "EN")) &&
			(slices.Contains(fields, "country_name") || slices.Contains(fields, "country_code"))
	}
	return false
}

func (b countryBackend) lookup(ip netip.Addr) (code string) {
	// Provider readers index uploaded binary data; an unreadable record is unknown.
	defer func() {
		if recover() != nil {
			code = ""
		}
	}()

	switch b.source {
	case SourceIp2Region:
		if b.searcher != nil && supportsXDBCountry(b.format) {
			region, err := searchXDB(b.searcher, ip.AsSlice())
			if err == nil {
				return countryCodeFromName(ParseRegion(region, b.format).Country)
			}
		}
	case SourceGeoLite2:
		if b.geo != nil {
			record, err := b.geo.Country(net.IP(ip.AsSlice()))
			if err == nil {
				return assignedCountryCode(record.Country.IsoCode)
			}
		}
	case SourceIpdb:
		if b.ipdb != nil {
			addr := ip.String()
			info, err := b.ipdb.FindMap(addr, "CN")
			if err == ipdb.ErrNoSupportLanguage {
				info, err = b.ipdb.FindMap(addr, "EN")
			}
			if err == nil {
				if code := assignedCountryCode(info["country_code"]); code != "" {
					return code
				}
				return countryCodeFromName(info["country_name"])
			}
		}
	}
	return ""
}
