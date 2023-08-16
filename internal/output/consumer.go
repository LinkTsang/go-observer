package output

import (
	"github.com/LinkTsang/go-observer/internal/record"
)

type RecordConsumer interface {
	Consume(*record.Record)
	Close()
}
