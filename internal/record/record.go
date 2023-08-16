package record

import (
	"net"
	"time"

	"github.com/google/gopacket/layers"
)

type Record struct {
	Timestamp time.Time
	SrcIP     net.IP
	SrcPort   layers.TCPPort
	DstIP     net.IP
	DstPort   layers.TCPPort
	Payload   []byte
}
