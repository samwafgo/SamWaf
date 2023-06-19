//go:build linux
// +build linux

package wafsystem

import (
	"fmt"
	"os"
	"os/exec"
)

// WafServiceManager 封装了 Linux 平台的服务管理方法
type WafServiceManager struct {
	serviceName string
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
		sm.installServiceLinux()
	}
}

// Uninstall 卸载服务
func (sm *WafServiceManager) Uninstall() {
	sm.uninstallServiceLinux()
}

// Pause 暂停服务
func (sm *WafServiceManager) Pause() {
	fmt.Println("Pause service functionality is not available on Linux.")
}

// serviceExists 检查服务是否存在
func (sm *WafServiceManager) serviceExists() bool {
	cmd := exec.Command("systemctl", "is-active", sm.serviceName)
	err := cmd.Run()
	if err == nil {
		return true
	}
	return false
}

// installServiceLinux 安装服务（Linux）
func (sm *WafServiceManager) installServiceLinux() {
	executablePath, err := os.Executable()
	if err != nil {
		fmt.Println("Failed to get executable path:", err)
		return
	}

	serviceContent := fmt.Sprintf(`[Unit]
Description=SamWaf is a Web Application Firewall (WAF). 
After=network.target

[Service]
ExecStart=%s
WorkingDirectory=%s
Restart=always
User=%s

[Install]
WantedBy=default.target`, executablePath, executablePath, os.Getenv("USER"))

	// 创建服务文件
	err = ioutil.WriteFile(fmt.Sprintf("/etc/systemd/system/%s.service", sm.serviceName), []byte(serviceContent), 0644)
	if err != nil {
		fmt.Println("Failed to create service file:", err)
		return
	}

	// 重新加载 systemd 配置
	cmd := exec.Command("systemctl", "daemon-reload")
	err = cmd.Run()
	if err != nil {
		fmt.Println("Failed to reload systemd configuration:", err)
		return
	}

	// 启动服务
	cmd = exec.Command("systemctl", "start", sm.serviceName)
	err = cmd.Run()
	if err != nil {
		fmt.Println("Failed to start service:", err)
		return
	}

	// 设置服务自动启动
	cmd = exec.Command("systemctl", "enable", sm.serviceName)
	err = cmd.Run()
	if err != nil {
		fmt.Println("Failed to enable service auto-start:", err)
		return
	}

	fmt.Println("Successfully installed and started the service", sm.serviceName)
}

// uninstallServiceLinux 卸载服务（Linux）
func (sm *WafServiceManager) uninstallServiceLinux() {
	cmd := exec.Command("systemctl", "stop", sm.serviceName)
	err := cmd.Run()
	if err != nil {
		fmt.Println("Failed to stop service:", err)
		return
	}

	cmd = exec.Command("systemctl", "disable", sm.serviceName)
	err = cmd.Run()
	if err != nil {
		fmt.Println("Failed to disable service auto-start:", err)
		return
	}

	serviceFile := fmt.Sprintf("/etc/systemd/system/%s.service", sm.serviceName)
	err = os.Remove(serviceFile)
	if err != nil {
		fmt.Println("Failed to delete service file:", err)
		return
	}

	cmd = exec.Command("systemctl", "daemon-reload")
	err = cmd.Run()
	if err != nil {
		fmt.Println("Failed to reload systemd configuration:", err)
		return
	}

	fmt.Println("Successfully uninstalled the service", sm.serviceName)
}
func (sm *WafServiceManager) IsServiceRunning() (bool, error) {
	cmd := exec.Command("systemctl", "is-active", sm.serviceName)

	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() == 3 {
				// Service is not running
				return false, nil
			}
		}
		return false, fmt.Errorf("failed to query service status: %w", err)
	}

	status := string(output)
	status = strings.ToLower(strings.TrimSpace(status))

	return status == "active", nil
}

func (sm *WafServiceManager) StartService() error {
	cmd := exec.Command("systemctl", "start", sm.serviceName)

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}

	return nil
}

func (sm *WafServiceManager) StopService() error {
	cmd := exec.Command("systemctl", "stop", sm.serviceName)

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to stop service: %w", err)
	}

	return nil
}
