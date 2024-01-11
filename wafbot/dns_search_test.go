package wafbot

import (
	"fmt"
	"testing"
)

func TestReverseDNSLookup(t *testing.T) {
	lookup, err := ReverseDNSLookup("114.119.151.1")
	if err == nil {
		for _, s := range lookup {
			fmt.Println(s)
		}
	}
}
