package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/IBM/sarama"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type Record struct {
	Timestamp time.Time
	SrcIP     net.IP
	SrcPort   layers.TCPPort
	DstIP     net.IP
	DstPort   layers.TCPPort
	Payload   []byte
}

type RecordConsumer interface {
	consumer(*Record)
	close()
}

type StdoutRecordConsumer struct {
}

func (c *StdoutRecordConsumer) consumer(r *Record) {
	if r == nil {
		log.Fatal("emptry record!")
		return
	}
	location, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("[%s] %s:%d -> %s:%d\n", r.Timestamp.In(location).Format("2006-01-02 15:04:05.000000 MST"), r.SrcIP, r.SrcPort, r.DstIP, r.DstPort)
}

func (c *StdoutRecordConsumer) close() {
}

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
	defer func() {

	}()

	return KafkaOutput{
		producer: producer,
	}
}

func (k *KafkaOutput) consumer(r *Record) {
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

func (k *KafkaOutput) close() {
	if err := k.producer.Close(); err != nil {
		panic(err)
	}
}

func main() {
	handle, err := pcap.OpenLive("lo", 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	filter := "tcp port 8080"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	serverPort := 8080

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	kafkaOutput := NewKafkaOutput()
	defer kafkaOutput.close()

	ch := make(chan Record, 1024)
	go func() {
		for r := range ch {
			kafkaOutput.consumer(&r)
		}
	}()

	for packet := range packetSource.Packets() {
		ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		tcpLayer := packet.Layer(layers.LayerTypeTCP)

		if ethernetLayer != nil && ipLayer != nil && tcpLayer != nil {
			ipPacket, _ := ipLayer.(*layers.IPv4)
			tcpPacket, _ := tcpLayer.(*layers.TCP)

			timestamp := packet.Metadata().Timestamp
			srcIP := ipPacket.SrcIP
			srcPort := tcpPacket.SrcPort
			dstIP := ipPacket.DstIP
			dstPort := tcpPacket.DstPort

			r := Record{
				Timestamp: timestamp,
				SrcIP:     srcIP,
				SrcPort:   srcPort,
				DstIP:     dstIP,
				DstPort:   dstPort,
			}

			if tcpPacket.DstPort == layers.TCPPort(serverPort) && tcpPacket.Payload != nil {
				r.Payload = tcpPacket.Payload
			}

			if tcpPacket.SrcPort == layers.TCPPort(serverPort) && tcpPacket.Payload != nil {
				r.Payload = tcpPacket.Payload
			}

			ch <- r
		}
	}
}
