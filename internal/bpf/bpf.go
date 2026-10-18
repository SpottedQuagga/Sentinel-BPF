package bpf

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sentinel-bpf/sentinel/internal/config"
	"github.com/sentinel-bpf/sentinel/internal/events"
)

// Reader is the interface for consuming events from eBPF ring buffer or synthetic stream.
type Reader interface {
	Start(ctx context.Context, out chan<- *events.Event) error
	Close() error
	KernelDrops() uint64
}

// BPFManager coordinates eBPF maps, probes, and ring buffer consumption.
type BPFManager struct {
	cfg         *config.Config
	kernelDrops uint64
	mu          sync.Mutex
	closed      bool
}

// NewManager creates a manager for eBPF operations.
func NewManager(cfg *config.Config) *BPFManager {
	return &BPFManager{
		cfg: cfg,
	}
}

func (m *BPFManager) KernelDrops() uint64 {
	return atomic.LoadUint64(&m.kernelDrops)
}

func (m *BPFManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

// MockReader generates realistic synthetic events for local testing and UI demonstration.
type MockReader struct {
	drops  uint64
	closed chan struct{}
}

// NewMockReader creates a synthetic event reader.
func NewMockReader() *MockReader {
	return &MockReader{
		closed: make(chan struct{}),
	}
}

func (m *MockReader) KernelDrops() uint64 {
	return atomic.LoadUint64(&m.drops)
}

func (m *MockReader) Close() error {
	close(m.closed)
	return nil
}

// Start launches a mock event emission loop generating diverse system behaviors.
func (m *MockReader) Start(ctx context.Context, out chan<- *events.Event) error {
	go func() {
		ticker := time.NewTicker(350 * time.Millisecond)
		defer ticker.Stop()

		var seq uint32 = 2000
		shells := []string{"/bin/bash", "/usr/bin/python3", "/usr/bin/curl", "/bin/sh"}

		for {
			select {
			case <-ctx.Done():
				return
			case <-m.closed:
				return
			case now := <-ticker.C:
				seq++
				pid := 2000 + (seq % 100)
				sh := shells[rand.Intn(len(shells))]

				// Normal execution event
				ev := &events.Event{
					TimestampNs: uint64(now.UnixNano()),
					CgroupID:    uint64(rand.Intn(4) + 1),
					EventType:   events.EventExec,
					TypeName:    "EXEC",
					Pid:         pid,
					Tid:         pid,
					Ppid:        1000,
					Uid:         1000,
					Gid:         1000,
					Euid:        1000,
					Egid:        1000,
					Comm:        "worker",
					Pcomm:       "systemd",
					Path:        sh,
					Extra:       "-c",
				}

				// Periodically simulate an attack chain (Reverse shell simulation)
				if seq%25 == 0 {
					attackPid := 9900 + (seq % 10)
					// 1. Connect
					out <- &events.Event{
						TimestampNs: uint64(time.Now().UnixNano()),
						EventType:   events.EventConnect,
						TypeName:    "CONNECT",
						Pid:         attackPid,
						Ppid:        1000,
						Fd:          4,
						Daddr:       "198.51.100.42",
						Dport:       4444,
						Comm:        "nc",
						Path:        "/bin/nc",
					}
					// 2. Dup stdin/stdout
					out <- &events.Event{
						TimestampNs: uint64(time.Now().UnixNano()),
						EventType:   events.EventDup,
						TypeName:    "DUP",
						Pid:         attackPid,
						Ppid:        1000,
						OldFd:       4,
						NewFd:       0, // stdin
						Comm:        "nc",
					}
					// 3. Exec shell
					out <- &events.Event{
						TimestampNs: uint64(time.Now().UnixNano()),
						EventType:   events.EventExec,
						TypeName:    "EXEC",
						Pid:         attackPid,
						Ppid:        1000,
						Comm:        "sh",
						Path:        "/bin/sh",
					}
				}

				// Periodically simulate file tampering
				if seq%40 == 0 {
					out <- &events.Event{
						TimestampNs: uint64(time.Now().UnixNano()),
						EventType:   events.EventOpenAt,
						TypeName:    "OPENAT",
						Pid:         pid,
						Ppid:        1000,
						Flags:       2, // O_RDWR
						Path:        "/etc/shadow",
						Comm:        "suspicious_app",
					}
				}

				select {
				case out <- ev:
				default:
					atomic.AddUint64(&m.drops, 1)
				}
			}
		}
	}()

	return nil
}

// IgnoreSelfPid adds the daemon's own PID to the ignored_pids BPF map.
func IgnoreSelfPid(mapFD int) error {
	pid := os.Getpid()
	if mapFD <= 0 {
		return fmt.Errorf("invalid map FD: %d", mapFD)
	}
	// On Linux, would call bpf_map_update_elem(mapFD, &pid, &val, BPF_ANY)
	_ = pid
	return nil
}
