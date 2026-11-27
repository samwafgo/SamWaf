package wafconfig

import (
	"SamWaf/global"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

func TestLoadACMETrustedCAs(t *testing.T) {
	const endpoint = "https://127.0.0.1:14000/dir"
	previous := global.GACME_CONFIG
	t.Cleanup(func() { global.GACME_CONFIG = previous })
	for _, tt := range []struct {
		name, list, file, wantError string
	}{
		{"empty", "[]", "", ""},
		{"wrong shape", "{directory_url: " + endpoint + "}", "", ""},
		{"valid", "[{directory_url: ' " + endpoint + " ', ca_file: root.pem}]", "root.pem", ""},
		{"traversal", "[{directory_url: " + endpoint + ", ca_file: ../root.pem}]", "", "ca_file"},
		{"absolute", "[{directory_url: " + endpoint + ", ca_file: '/tmp/root.pem'}]", "", "ca_file"},
		{"drive", "[{directory_url: " + endpoint + ", ca_file: 'C:root.pem'}]", "", "ca_file"},
		{"file type", "[{directory_url: " + endpoint + ", ca_file: true}]", "", "ca_file"},
		{"invalid URL alongside valid", "[{directory_url: 'http://127.0.0.1:14000/dir', ca_file: other.pem}, {directory_url: " + endpoint + ", ca_file: root.pem}]", "root.pem", ""},
		{"duplicate", "[{directory_url: " + endpoint + ", ca_file: root.pem}, {directory_url: " + endpoint + ", ca_file: other.pem}]", "", "重复"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			v := viper.New()
			v.SetConfigType("yaml")
			if err := v.ReadConfig(strings.NewReader("acme:\n  directory_max_retries: 0\n  trusted_cas: " + tt.list)); err != nil {
				t.Fatal(err)
			}
			loadACMEConfig(v)
			got := global.GACME_CONFIG
			entry, exists := got.TrustedCAs[endpoint]
			if exists != (tt.file != "" || tt.wantError != "") || entry.CAFile != tt.file ||
				(tt.wantError == "") != (entry.ConfigError == "") || !strings.Contains(entry.ConfigError, tt.wantError) ||
				got.DirectoryMaxRetries != 0 || got.DirectoryTimeoutSeconds != global.DefaultACMEConfig().DirectoryTimeoutSeconds {
				t.Fatalf("unexpected ACME config: %+v", got)
			}
			if len(got.TrustedCAs) > 1 {
				t.Fatalf("unexpected extra CA entries: %+v", got.TrustedCAs)
			}
		})
	}
}

func TestLoadACMEConfig(t *testing.T) {
	previous := global.GACME_CONFIG
	t.Cleanup(func() { global.GACME_CONFIG = previous })
	for _, tt := range []struct {
		name string
		yaml string
		want global.ACMEConfig
	}{
		{"absent", "", global.DefaultACMEConfig()},
		{"lower bounds", "acme: {directory_timeout_seconds: 5, directory_max_retries: 0}", global.ACMEConfig{DirectoryTimeoutSeconds: 5, DirectoryMaxRetries: 0}},
		{"upper bounds", "acme: {directory_timeout_seconds: 120, directory_max_retries: 5}", global.ACMEConfig{DirectoryTimeoutSeconds: 120, DirectoryMaxRetries: 5}},
		{"invalid types", "acme: {directory_timeout_seconds: false, directory_max_retries: 0.0}", global.DefaultACMEConfig()},
		{"out of range", "acme: {directory_timeout_seconds: 121, directory_max_retries: 6}", global.DefaultACMEConfig()},
		{"independent defaults", "acme: {directory_timeout_seconds: bogus, directory_max_retries: 2}", global.ACMEConfig{DirectoryTimeoutSeconds: 30, DirectoryMaxRetries: 2}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			config := viper.New()
			config.SetConfigType("yml")
			if err := config.ReadConfig(strings.NewReader(tt.yaml)); err != nil {
				t.Fatal(err)
			}
			loadACMEConfig(config)
			if got := global.GACME_CONFIG; !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}
