package kafka

import (
	"SamWaf/innerbean"
	"fmt"
	"testing"
	"time"
)

func TestKafka(t *testing.T) {
	// 初始化 Kafka
	brokers := []string{"localhost:9092"}
	topic := "samwaf_logs_topic"
	kafkaNotifier, err := NewKafkaNotifier(brokers, topic)
	if err != nil {
		fmt.Println("Failed to initialize Kafka:", err)
		return
	}
	defer kafkaNotifier.Close()
	done := make(chan error)

	log := innerbean.WebLog{ /* 初始化日志 */ }
	log.ACTION = "通过"
	log.BODY = "测试"
	log.SRC_IP = "127.0.0.3"
	//logs := []innerbean.WebLog{log, /* 其他日志 */ }
	kafkaNotifier.NotifySingle(log)
	go func() {
		err := <-done
		if err != nil {
			fmt.Println("Failed to send single log to Kafka:", err)
		} else {
			fmt.Println("Single log sent to Kafka successfully.")
		}
	}()

	// 保持主进程继续运行，直到所有异步任务完成
	time.Sleep(10 * time.Second)
}

func BenchmarkKafka(b *testing.B) {
	b.ReportAllocs()
	// 初始化 Kafka
	brokers := []string{"localhost:9092"}
	topic := "samwaf_logs_topic"
	kafkaNotifier, err := NewKafkaNotifier(brokers, topic)
	if err != nil {
		fmt.Println("Failed to initialize Kafka:", err)
		return
	}
	defer kafkaNotifier.Close()

	total := b.N
	fmt.Println(total)
	for i := 0; i < b.N; i++ {
		datetimeNow := time.Now()
		log := innerbean.WebLog{ /* 初始化日志 */ }
		log.ACTION = "通过"
		log.BODY = "测试"
		log.SRC_IP = "127.0.0.3"
		log.CREATE_TIME = datetimeNow.Format("2006-01-02 15:04:05")
		log.UNIX_ADD_TIME = datetimeNow.UnixNano() / 1e6
		//logs := []innerbean.WebLog{log, /* 其他日志 */ }
		kafkaNotifier.NotifySingle(log)
	}

	// 保持主进程继续运行，直到所有异步任务完成

}
