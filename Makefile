CLANG ?= clang
CFLAGS ?= -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86
BPFTOOL ?= bpftool
GO ?= go

.PHONY: all vmlinux build-ebpf build-daemon build-ui test vet fmt clean

all: build-daemon build-ui

vmlinux:
	@echo "Generating bpf/vmlinux.h from running kernel BTF..."
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h

build-ebpf:
	@echo "Compiling eBPF programs and generating Go bindings..."
	cd internal/bpf && $(GO) run github.com/cilium/ebpf/cmd/bpf2go -target bpfel,bpfeb -cc $(CLANG) -cflags "-O2 -g -Wall -I../../bpf" sentinel ../../bpf/sentinel.bpf.c

build-daemon:
	@echo "Building SentinelBPF daemon..."
	@mkdir -p bin
	$(GO) build -v -o bin/sentinel-daemon ./cmd/sentinel-daemon

build-ui:
	@echo "Building Web UI..."
	cd web-ui && npm install && npm run build

test:
	@echo "Running Go tests..."
	$(GO) test -v -race ./cmd/... ./internal/...

vet:
	@echo "Running static analysis..."
	$(GO) vet ./cmd/... ./internal/...
	test -z "$$(gofmt -l .)"

fmt:
	@echo "Formatting Go files..."
	gofmt -w -s .

clean:
	rm -rf bin/
	rm -f bpf/vmlinux.h
	rm -f internal/bpf/sentinel_bpf*.go internal/bpf/sentinel_bpf*.o
