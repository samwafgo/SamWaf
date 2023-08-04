package firewall

import (
	"fmt"
	"os"
	"testing"
)

func TestFireWallEngine_AddRule(t *testing.T) {
	fw := FireWallEngine{}
	// Add a new firewall rule
	//ruleToAdd := "-p tcp --dport 8080 -j ACCEPT"
	ruleName := "testwaf1"
	ipToAdd := "192.168.1.12"
	action := ACTION_BLOCK
	proc := "TCP"
	localport := "8989"
	if err := fw.AddRule(ruleName, ipToAdd, action, proc, localport); err != nil {
		fmt.Println("Failed to add firewall rule:", err)
	} else {
		fmt.Println("Firewall rule added successfully.")
	}
}
func TestFireWallEngine_DeleteRule(t *testing.T) {
	fw := FireWallEngine{}
	ruleName := "testwaf1"

	exists, err := fw.IsRuleExists(ruleName)
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}

	if exists {
		if excuteResult, err := fw.DeleteRule(ruleName); err != nil {
			fmt.Println("Failed to delete firewall rule:", err)
		} else {
			if excuteResult {
				fmt.Println("Firewall rule deleted successfully.")
			} else {
				fmt.Println("Firewall rule deleted failed.", err)
			}
		}

	} else {
		fmt.Println("Rule does not exist.")
	}

}

func TestFireWallEngine_EditRule(t *testing.T) {
	fw := FireWallEngine{}
	// Edit an existing firewall rule (not supported on Windows)
	ruleNum := 1
	newRule := "-p tcp --dport 8080 -j DROP"
	if err := fw.EditRule(ruleNum, newRule); err != nil {
		fmt.Println("Failed to edit firewall rule:", err)
	} else {
		fmt.Println("Firewall rule edited successfully.")
	}
}

func TestFireWallEngine_IsFirewallEnabled(t *testing.T) {
	fw := FireWallEngine{}

	// Check if the firewall is enabled
	if fw.IsFirewallEnabled() {
		fmt.Println("Firewall is enabled.")
	} else {
		fmt.Println("Firewall is not enabled.")
	}
}

func TestFireWallEngine_IsRuleExists(t *testing.T) {
	fw := FireWallEngine{}

	// Check if the rule exists
	ruleName := "testwaf"
	exists, err := fw.IsRuleExists(ruleName)
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}

	if exists {
		fmt.Println("Rule exists.")
	} else {
		fmt.Println("Rule does not exist.")
	}
}
