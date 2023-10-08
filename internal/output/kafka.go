package output

import (
	"fmt"
	"log"
	"time"

	"github.com/IBM/sarama"
	"github.com/LinkTsang/go-observer/internal/record"
)

type KafkaOutput struct {
	producer sarama.SyncProducer
	topic    string
}

func NewKafkaOutput(brokers []string, topic string) KafkaOutput {
	config := sarama.NewConfig()
	config.Producer.RequiredAcks = sarama.WaitForAll
	config.Producer.Retry.Max = 5
	config.Producer.Return.Successes = true
	producer, err := sarama.NewSyncProducer(brokers, config)
	if err != nil {
		panic(err)
	}

	return KafkaOutput{
		producer: producer,
		topic:    topic,
	}
}

func (k *KafkaOutput) Consume(r *record.Record) {
	if r == nil {
		log.Fatal("emptry record!")
		return
	}
	location, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		log.Fatal(err)
	}
	value := fmt.Sprintf("[%s] %s:%d -> %s:%d \n```payload length:%v\n%v\n```\n", r.Timestamp.In(location).Format("2006-01-02 15:04:05.000000 MST"), r.SrcIP, r.SrcPort, r.DstIP, r.DstPort, len(r.Payload), string(r.Payload))

	message := &sarama.ProducerMessage{
		Topic: k.topic,
		Key:   sarama.StringEncoder("key"),
		Value: sarama.StringEncoder(value),
	}

	_, _, err = k.producer.SendMessage(message)
	if err != nil {
		panic(err)
	}
}

func (k *KafkaOutput) Close() {
	if err := k.producer.Close(); err != nil {
		panic(err)
	}
}
