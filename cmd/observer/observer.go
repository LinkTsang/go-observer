package main

import (
	"fmt"
	"log"
	"net"
	"time"

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

	recordConsumerStdout := &StdoutRecordConsumer{}
	ch := make(chan Record, 1024)
	go func() {
		for r := range ch {
			recordConsumerStdout.consumer(&r)
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
