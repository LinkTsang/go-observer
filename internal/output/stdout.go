package output

import (
	"fmt"
	"log"
	"time"

	"github.com/LinkTsang/go-observer/internal/record"
)

type StdoutRecordConsumer struct {
}

func (c *StdoutRecordConsumer) Consume(r *record.Record) {
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

func (c *StdoutRecordConsumer) Close() {
}
