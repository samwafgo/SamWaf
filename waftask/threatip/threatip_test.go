package threatip

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestCIDROnlyParser(t *testing.T) {
	in := "1.2.3.4\n2001:db8::/48\n\n# comment\nbadline\n5.6.7.0/24\n"
	res, err := ParseByType("cidr_only", strings.NewReader(in), 0)
	if err != nil {
		t.Fatal(err)
	}
	got := sortedUnique(res.IPs)
	want := sortedUnique([]string{"1.2.3.4", "2001:db8::/48", "5.6.7.0/24"})
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ips = %v, want %v", got, want)
	}
	if res.Dropped != 1 { // "badline"
		t.Errorf("dropped = %d, want 1", res.Dropped)
	}
}

func TestIpsumParserThreshold(t *testing.T) {
	in := "# IPsum\n# comment\n77.90.185.20\t11\n2.57.121.25\t9\n1.1.1.1\t3\n"
	// threshold=9 → 只保留 >=9 的两个
	res, err := ParseByType("ipsum", strings.NewReader(in), 9)
	if err != nil {
		t.Fatal(err)
	}
	got := sortedUnique(res.IPs)
	want := sortedUnique([]string{"77.90.185.20", "2.57.121.25"})
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ips = %v, want %v", got, want)
	}
}

func TestSnapshotRoundTrip(t *testing.T) {
	ips := []string{"1.2.3.4", "10.0.0.0/8", "1.2.3.4", "  ", "2001:db8::1"}
	payload, sha, count, err := EncodeSnapshot(ips)
	if err != nil {
		t.Fatal(err)
	}
	if count != 3 { // 去重去空后 3 条
		t.Errorf("count = %d, want 3", count)
	}
	if sha == "" {
		t.Error("sha empty")
	}
	out, err := DecodeSnapshot(payload)
	if err != nil {
		t.Fatal(err)
	}
	got := sortedUnique(out)
	want := sortedUnique([]string{"1.2.3.4", "10.0.0.0/8", "2001:db8::1"})
	if !reflect.DeepEqual(got, want) {
		t.Errorf("decoded = %v, want %v", got, want)
	}
}

func TestDiff(t *testing.T) {
	old := []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"}
	next := []string{"2.2.2.2", "3.3.3.3", "4.4.4.4"}
	added, removed := Diff(old, next)
	sort.Strings(added)
	sort.Strings(removed)
	if !reflect.DeepEqual(added, []string{"4.4.4.4"}) {
		t.Errorf("added = %v, want [4.4.4.4]", added)
	}
	if !reflect.DeepEqual(removed, []string{"1.1.1.1"}) {
		t.Errorf("removed = %v, want [1.1.1.1]", removed)
	}
}
