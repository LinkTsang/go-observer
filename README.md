# Observer

[![Go](https://github.com/LinkTsang/go-observer/actions/workflows/go.yml/badge.svg)](https://github.com/LinkTsang/go-observer/actions/workflows/go.yml)


## Build && Run

```bash
make build && sudo ./bin/go-observer --pcap-device lo --pcap-snaplen 65535 --pcap-filter 'tcp port 8080' --kafka-brokers 127.0.0.1:9092 --kafka-topic demo
```
