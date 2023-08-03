package firewall

import (
	"fmt"
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
	// Delete a firewall rule
	ruleNumToDelete := 1
	if err := fw.DeleteRule(ruleNumToDelete); err != nil {
		fmt.Println("Failed to delete firewall rule:", err)
	} else {
		fmt.Println("Firewall rule deleted successfully.")
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
