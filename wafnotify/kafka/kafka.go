package kafka

import (
	"SamWaf/common/zlog"
	"SamWaf/innerbean"
	"context"
	"encoding/json"
	"fmt"
	"github.com/twmb/franz-go/pkg/kgo"
	"sync"
	"time"
)

// KafkaNotifier 实现 WafNotify 接口
type KafkaNotifier struct {
	client      *kgo.Client
	topic       string
	brokers     []string
	lastErrTime int64 //上次错误时间
}

// 初始化 Kafka 客户端
func NewKafkaNotifier(brokers []string, topic string, enable int64) (*KafkaNotifier, error) {

	if enable == 0 {
		return &KafkaNotifier{
			client:  nil,
			topic:   topic,
			brokers: brokers,
		}, nil
	}
	client, err := connect(brokers)
	return &KafkaNotifier{
		client:  client,
		topic:   topic,
		brokers: brokers,
	}, err
}
func connect(brokers []string) (*kgo.Client, error) {
	opts := []kgo.Opt{
		kgo.SeedBrokers(brokers...),
		kgo.RecordPartitioner(kgo.StickyKeyPartitioner(nil)),
	}
	client, err := kgo.NewClient(opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kafka client: %v", err)
	}

	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	err = client.Ping(ctx)
	if err != nil {
		zlog.Error("failed to ping Kafka server: %v", err)
		return nil, err
	}
	return client, nil
}

// 关闭 Kafka 客户端
func (kn *KafkaNotifier) Close() {
	if kn.client != nil {
		kn.client.Close()
	}
}

// 关闭 Kafka 客户端
func (kn *KafkaNotifier) ReConnect() error {
	//TODO 如果错误时间间隔在1，分钟之内，不进行重连操作
	if kn.client != nil {
		kn.client.Close()
	}
	client, err := connect(kn.brokers)
	if err != nil {
		zlog.Error("failed to reconnect create Kafka notifier: %v", err)
		return err
	}
	kn.client = client
	kn.lastErrTime = 0
	return nil
}

// 实现 WafNotify 接口中的 NotifySingle 方法
func (kn *KafkaNotifier) NotifySingle(log *innerbean.WebLog) error {
	err := kn.sendMessage(log)
	if err != nil {
		return err
	}
	zlog.Debug("已发送")
	return nil
}

// 实现 WafNotify 接口中的 NotifyBatch 方法
func (kn *KafkaNotifier) NotifyBatch(logs []*innerbean.WebLog) error {
	go func() {
		for _, log := range logs {
			if err := kn.sendMessage(log); err != nil {
				zlog.Debug("发送批量日志时出错:", err.Error())
				return
			}
		}
	}()
	return nil
}

// 发送消息到 Kafka
func (kn *KafkaNotifier) sendMessage(log *innerbean.WebLog) error {
	if kn.client == nil {
		err := kn.ReConnect()
		if err != nil {
			return err
		}
	}
	// 将日志对象转换为 JSON
	jsonData, err := json.Marshal(log)
	if err != nil {
		zlog.Error("failed to marshal log: %v", err)
		//精简重新继续发
		logSimple := innerbean.WebLog{ /* 初始化日志 */ }
		logSimple.REQ_UUID = log.REQ_UUID
		logSimple.CREATE_TIME = log.CREATE_TIME
		logSimple.ACTION = log.ACTION
		logSimple.SRC_IP = log.SRC_IP
		logSimple.SRC_PORT = log.SRC_PORT
		logSimple.HOST_CODE = log.HOST_CODE
		logSimple.GUEST_IDENTIFICATION = log.GUEST_IDENTIFICATION
		logSimple.RISK_LEVEL = log.RISK_LEVEL
		jsonData, err = json.Marshal(logSimple)
		if err != nil {
			zlog.Error("failed to marshal simple log: %v", err)
			return err
		}
	}
	record := &kgo.Record{
		Topic: kn.topic,
		Value: jsonData,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second) // 为每次操作创建子 context
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(1)

	kn.client.Produce(ctx, record, func(r *kgo.Record, err error) {
		defer wg.Done()

		if err != nil {
			zlog.Error("failed to produce message: %v\n", err.Error())
		} else {
			zlog.Debug("message produced successfully")
		}
	})
	wg.Wait()
	return nil
}
