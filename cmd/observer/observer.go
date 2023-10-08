package main

import (
	"bufio"
	"bytes"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/LinkTsang/go-observer/internal/output"
	"github.com/LinkTsang/go-observer/internal/record"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"github.com/urfave/cli/v2"
)

// Build a simple HTTP request parser using tcpassembly.StreamFactory and tcpassembly.Stream interfaces

// httpStreamFactory implements tcpassembly.StreamFactory
type httpStreamFactory struct{}

// httpStream will handle the actual decoding of http requests.
type httpStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
}

func (h *httpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	hstream := &httpStream{
		net:       net,
		transport: transport,
		r:         tcpreader.NewReaderStream(),
	}
	go hstream.run() // Important... we must guarantee that data from the reader stream is read.

	// ReaderStream implements tcpassembly.Stream, so we can return a pointer to it.
	return &hstream.r
}

func (h *httpStream) run() {
	buf := bufio.NewReader(&h.r)
	for {
		magicNumber, err := buf.Peek(4)
		if err == io.EOF {
			// We must read until we see an EOF... very important!
			return
		} else if err != nil {
			log.Println("Error reading stream", h.net, h.transport, ":", err)
		} else {
			if bytes.Equal([]byte("HTTP"), magicNumber) {
				resp, err := http.ReadResponse(buf, nil)
				if err == io.EOF {
					// We must read until we see an EOF... very important!
					return
				} else if err != nil {
					log.Println("Error reading stream", h.net, h.transport, ":", err)
				} else {
					bodyBytes := tcpreader.DiscardBytesToEOF(resp.Body)
					resp.Body.Close()
					log.Printf("Received response from stream %v %v : %+v with %v bytes in response body\n", h.net, h.transport, resp, bodyBytes)
				}
			} else {
				req, err := http.ReadRequest(buf)
				if err == io.EOF {
					// We must read until we see an EOF... very important!
					return
				} else if err != nil {
					log.Println("Error reading stream", h.net, h.transport, ":", err)
				} else {
					bodyBytes := tcpreader.DiscardBytesToEOF(req.Body)
					req.Body.Close()
					log.Printf("Received request from stream %v %v : %+v with %v bytes in request body", h.net, h.transport, req, bodyBytes)
				}
			}
		}
	}
}

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

	streamFactory := &httpStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

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

							assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), &tcp, packet.Metadata().Timestamp)
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
			assembler.FlushOlderThan(time.Now().Add(time.Minute * -2))
		}
	}

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
