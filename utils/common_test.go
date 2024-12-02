package utils

import (
	"fmt"
	"github.com/oschwald/geoip2-golang"
	"log"
	"net"
	"testing"
)

func TestIPv6(t *testing.T) {
	db, err := geoip2.Open("../data/ipv6/GeoLite2-Country.mmdb")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	// If you are using strings that may be invalid, check that ip is not nil
	ip := net.ParseIP("2409:8087:3c02:21:0:1:0:100a")
	record, err := db.City(ip)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("国家: %v\n", record.Country.Names["zh-CN"])
	fmt.Sprintf("%v", record)
	fmt.Printf("Portuguese (BR) city name: %v\n", record.City.Names["pt-BR"])
	if len(record.Subdivisions) > 0 {
		fmt.Printf("English subdivision name: %v\n", record.Subdivisions[0].Names["en"])
	}
	fmt.Printf("Russian country name: %v\n", record.Country.Names["ru"])
	fmt.Printf("ISO country code: %v\n", record.Country.IsoCode)
	fmt.Printf("Time zone: %v\n", record.Location.TimeZone)
	fmt.Printf("Coordinates: %v, %v\n", record.Location.Latitude, record.Location.Longitude)
}
