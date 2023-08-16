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
}

func NewKafkaOutput() KafkaOutput {
	config := sarama.NewConfig()
	config.Producer.RequiredAcks = sarama.WaitForAll
	config.Producer.Retry.Max = 5
	config.Producer.Return.Successes = true
	producer, err := sarama.NewSyncProducer([]string{"172.30.253.207:9092"}, config)
	if err != nil {
		panic(err)
	}

	return KafkaOutput{
		producer: producer,
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
	value := fmt.Sprintf("[%s] %s:%d -> %s:%d\n", r.Timestamp.In(location).Format("2006-01-02 15:04:05.000000 MST"), r.SrcIP, r.SrcPort, r.DstIP, r.DstPort)

	message := &sarama.ProducerMessage{
		Topic: "demo",
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
