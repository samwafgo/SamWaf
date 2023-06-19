//go:build windows
// +build windows

package wafsystem

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
)

// WafServiceManager 封装了 Windows 平台的服务管理方法
type WafServiceManager struct {
	serviceName string
	runAsAdmin  bool
}

// NewWafServiceManager 创建一个新的 WafServiceManager 实例
func NewWafServiceManager(serviceName string) *WafServiceManager {
	return &WafServiceManager{
		serviceName: serviceName,
	}
}

// Install 安装服务
func (sm *WafServiceManager) Install() {
	if sm.serviceExists() {
		fmt.Println("Service", sm.serviceName, "already exists.")
	} else {
		fmt.Println("Service", sm.serviceName, "does not exist.")
		sm.installServiceWindows()
	}
}

// Uninstall 卸载服务
func (sm *WafServiceManager) Uninstall() {
	sm.uninstallServiceWindows()
}

// Pause 暂停服务
func (sm *WafServiceManager) Stop() {
	sm.stopServiceWindows()
}

// serviceExists 检查服务是否存在
func (sm *WafServiceManager) serviceExists() bool {
	cmd := exec.Command("sc", "query", sm.serviceName)
	output, err := cmd.Output()
	if err == nil && strings.Contains(string(output), "SERVICE_NAME: "+sm.serviceName) {
		return true
	}
	return false
}

// installServiceWindows 安装服务（Windows）
func (sm *WafServiceManager) installServiceWindows() {
	executablePath, err := os.Executable()
	if err != nil {
		fmt.Println("Failed to get executable path:", err)
		return
	}

	serviceContent := fmt.Sprintf(`[Unit]
Description=SamWaf is a Web Application Firewall (WAF)

[Service]
ExecStart=%s

[Install]
WantedBy=multi-user.target`, executablePath)

	// 创建服务配置文件
	err = ioutil.WriteFile(fmt.Sprintf("%s.service", sm.serviceName), []byte(serviceContent), 0644)
	if err != nil {
		fmt.Println("Failed to create service configuration file:", err)
		return
	}

	// 创建服务
	cmd := exec.Command("sc", "create", sm.serviceName, "binPath= \""+executablePath+" -d\"")
	err = cmd.Run()
	if err != nil {
		fmt.Println("Failed to create service:", err)
		return
	}
	isRunning, err := sm.IsServiceRunning()
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}

	if !isRunning {
		fmt.Println("Service is not running.")
		sm.StartService()
	}

	// 设置服务自动启动
	cmd = exec.Command("sc", "config", sm.serviceName, "start=auto")
	err = cmd.Run()
	if err != nil {
		fmt.Println("Failed to set service auto-start:", err)
		return
	}

	fmt.Println("Successfully installed and started the service", sm.serviceName)
}

// uninstallServiceWindows 卸载服务（Windows）
func (sm *WafServiceManager) uninstallServiceWindows() {
	isRunning, err := sm.IsServiceRunning()
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}

	if isRunning {
		fmt.Println("Service is already running.")
		sm.stopServiceWindows()
	}

	cmd := exec.Command("sc", "delete", sm.serviceName)
	err = cmd.Run()
	if err != nil {
		fmt.Println("Failed to delete service:", err)
		return
	}

	fmt.Println("Successfully uninstalled the service", sm.serviceName)
}

// stopServiceWindows 暂停服务（Windows）
func (sm *WafServiceManager) stopServiceWindows() {
	cmd := exec.Command("sc", "stop", sm.serviceName)
	err := cmd.Run()
	if err != nil {
		fmt.Println("Failed to stop service:", err)
		return
	}

	fmt.Println("Successfully paused the service", sm.serviceName)
}
func (sm *WafServiceManager) IsServiceRunning() (bool, error) {
	cmd := exec.Command("sc", "query", sm.serviceName)

	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() == 1 {
				// Service is not running
				return false, nil
			}
		}
		return false, fmt.Errorf("failed to query service status: %w", err)
	}

	status := string(output)
	status = strings.ToLower(strings.TrimSpace(status))

	return status == "running", nil
}
func (sm *WafServiceManager) StartService() error {
	cmd := exec.Command("sc", "start", sm.serviceName)
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}

	return nil
}
