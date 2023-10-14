package main

import (
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/LinkTsang/go-observer/internal/output"
	"github.com/LinkTsang/go-observer/internal/protocol"
	"github.com/LinkTsang/go-observer/internal/record"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/urfave/cli/v2"

	"net/http"
	_ "net/http/pprof"
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

	tcpHandler := protocol.NewTcpHandler()

	ticker := time.Tick(time.Minute)

	var eth layers.Ethernet
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var tcp layers.TCP
	var udp layers.UDP
	var payload gopacket.Payload
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp, &udp, &payload)
	decodedLayers := make([]gopacket.LayerType, 0, 10)

	for {
		select {
		case packet := <-packetSource.Packets():
			{
				if err := parser.DecodeLayers(packet.Data(), &decodedLayers); err != nil {
					log.Printf("Could not decode layers: %v\n", err)
					continue
				}

				timestamp := packet.Metadata().Timestamp

				var srcIP net.IP
				var srcPort layers.TCPPort
				var dstIP net.IP
				var dstPort layers.TCPPort
				var payload []byte

				for _, layerType := range decodedLayers {
					switch layerType {
					case layers.LayerTypeIPv4:
						{
							srcIP = ip4.SrcIP
							dstIP = ip4.DstIP
						}
					case layers.LayerTypeTCP:
						{
							srcPort = tcp.SrcPort
							dstPort = tcp.DstPort
							if tcp.DstPort == layers.TCPPort(serverPort) && tcp.Payload != nil {
								payload = tcp.Payload
							}

							if tcp.SrcPort == layers.TCPPort(serverPort) && tcp.Payload != nil {
								payload = tcp.Payload
							}

							tcpHandler.HandlePacket(&tcp, packet)
						}
					}
				}

				r := record.Record{
					Timestamp: timestamp,
					SrcIP:     srcIP,
					SrcPort:   srcPort,
					DstIP:     dstIP,
					DstPort:   dstPort,
					Payload:   payload,
				}

				ch <- r
			}
		case <-ticker:
			tcpHandler.HandleTicket()
		}
	}

}

func main() {

	go func() {
		log.Fatalln(http.ListenAndServe(":19999", nil))
	}()

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
