package wafnotify

import (
	"SamWaf/wafnotify/kafka"
	"fmt"
	"strings"
)

func InitNotifyKafkaEngine(enable int64, url string, topic string) *WafNotifyService {

	brokers := strings.Split(url, ",") // Kafka brokers
	notifier, err := kafka.NewKafkaNotifier(brokers, topic, enable)
	if err != nil {
		fmt.Printf("Failed to create notifier: %v\n", err)
		return NewWafNotifyService(notifier, enable)
	}
	// 创建日志服务并注入 notifier
	return NewWafNotifyService(notifier, enable)
}
