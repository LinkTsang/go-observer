package main

import (
	"fmt"
	"log"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

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

	for packet := range packetSource.Packets() {
		ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		tcpLayer := packet.Layer(layers.LayerTypeTCP)

		if ethernetLayer != nil && ipLayer != nil && tcpLayer != nil {
			ipPacket, _ := ipLayer.(*layers.IPv4)
			tcpPacket, _ := tcpLayer.(*layers.TCP)

			fmt.Printf("%s:%s -> %s:%s\n", ipPacket.SrcIP, tcpPacket.SrcPort, ipPacket.DstIP, tcpPacket.DstPort)

			if tcpPacket.DstPort == layers.TCPPort(serverPort) && tcpPacket.Payload != nil {
				payload := string(tcpPacket.Payload)

				reqHeaders := strings.Split(payload, "\r\n")
				for _, header := range reqHeaders {
					if strings.HasPrefix(header, "Host:") {
						host := strings.TrimSpace(strings.TrimPrefix(header, "Host:"))
						fmt.Printf("Request to: %s\n", host)
					}
				}
			}

			if tcpPacket.SrcPort == layers.TCPPort(serverPort) && tcpPacket.Payload != nil {
				payload := string(tcpPacket.Payload)

				bodyStart := strings.Index(payload, "\r\n\r\n") + 4
				if bodyStart > 0 && len(payload) >= bodyStart {
					body := payload[bodyStart:]
					fmt.Printf("Response body:\n%s\n", body)
				}
			}

			fmt.Printf("====\n\n")
		}
	}
}
