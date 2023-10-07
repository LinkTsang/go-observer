package main

import (
	"log"
	"os"
	"strings"

	"github.com/LinkTsang/go-observer/internal/output"
	"github.com/LinkTsang/go-observer/internal/record"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/urfave/cli/v2"
)

func handle(cCtx *cli.Context) error {

	pcapDevice := cCtx.String("pcap-device")
	pcapSnaplen := cCtx.Int("pcap-snaplen")
	pcapFilter := cCtx.String("pcap-filter")
	log.Printf("pcap device: %v\n", pcapDevice)
	log.Printf("pcap snaplen: %v\n", pcapSnaplen)
	log.Printf("pcap bpf filter: %v\n", pcapFilter)

	brokers := strings.Split(cCtx.String("kafka-brokers"), ";")
	topic := cCtx.String("kafka-topic")
	log.Printf("kafka brokers: %v\n", brokers)
	log.Printf("kafka topic: %v\n", topic)

	handle, err := pcap.OpenLive(pcapDevice, int32(pcapSnaplen), true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	err = handle.SetBPFFilter(pcapFilter)
	if err != nil {
		log.Fatal(err)
	}

	serverPort := 8080

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	kafkaOutput := output.NewKafkaOutput(brokers, topic)
	defer kafkaOutput.Close()

	ch := make(chan record.Record, 1024)
	go func() {
		for r := range ch {
			kafkaOutput.Consume(&r)
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

			r := record.Record{
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

	return nil
}

func main() {

	app := &cli.App{
		Name:  "go-observer",
		Usage: "observer anything!",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "pcap-device",
				Value: "lo",
				Usage: "device for pcap",
			},
			&cli.IntFlag{
				Name:  "pcap-snaplen",
				Value: 65535,
				Usage: "snaplen for pcap",
			},
			&cli.StringFlag{
				Name:  "pcap-filter",
				Value: "tcp port 8080",
				Usage: "bpf filter for pcap",
			},
			&cli.StringFlag{
				Name:  "kafka-brokers",
				Value: "127.0.0.1:9092",
				Usage: "kafka brokers",
			},
			&cli.StringFlag{
				Name:  "kafka-topic",
				Value: "demo",
				Usage: "kafka brokers",
			},
		},
		Action: handle,
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
