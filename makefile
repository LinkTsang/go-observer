.PHONY: all build clean run
BIN_FILE=go-observer
all: build
clean:
	@go clean
	@rm -vf ./bin/*
build:
	@go build -o ./bin/"${BIN_FILE}" cmd/observer/observer.go
run:
	./bin/"${BIN_FILE}"
