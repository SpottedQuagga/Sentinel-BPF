package bpf

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
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

// Start launches a mock event emission loop generating diverse system behaviors
// with realistic multi-level process lineage.
//
// Process tree layout:
//
//	init(1) → sshd(100) → bash(200) → python3(300) → worker(400..409)
//	                                 ↘ nc(500)         [reverse shell chain]
//	                                 ↘ suspicious_app(600) [file tampering]
func (m *MockReader) Start(ctx context.Context, out chan<- *events.Event) error {
	go func() {
		now := time.Now()

		// Seed the root process tree so the process table has
		// realistic multi-level ancestry from the start.
		seedProcesses := []*events.Event{
			{
				TimestampNs: uint64(now.UnixNano()),
				EventType:   events.EventExec,
				TypeName:    "EXEC",
				Pid:         1, Tid: 1, Ppid: 0,
				Uid: 0, Gid: 0, Euid: 0, Egid: 0,
				Comm: "systemd", Pcomm: "", Path: "/usr/lib/systemd/systemd",
				CgroupID: 1,
			},
			{
				TimestampNs: uint64(now.Add(1 * time.Millisecond).UnixNano()),
				EventType:   events.EventExec,
				TypeName:    "EXEC",
				Pid:         100, Tid: 100, Ppid: 1,
				Uid: 0, Gid: 0, Euid: 0, Egid: 0,
				Comm: "sshd", Pcomm: "systemd", Path: "/usr/sbin/sshd",
				CgroupID: 1,
			},
			{
				TimestampNs: uint64(now.Add(2 * time.Millisecond).UnixNano()),
				EventType:   events.EventExec,
				TypeName:    "EXEC",
				Pid:         200, Tid: 200, Ppid: 100,
				Uid: 1000, Gid: 1000, Euid: 1000, Egid: 1000,
				Comm: "bash", Pcomm: "sshd", Path: "/bin/bash",
				CgroupID: 2,
			},
			{
				TimestampNs: uint64(now.Add(3 * time.Millisecond).UnixNano()),
				EventType:   events.EventExec,
				TypeName:    "EXEC",
				Pid:         300, Tid: 300, Ppid: 200,
				Uid: 1000, Gid: 1000, Euid: 1000, Egid: 1000,
				Comm: "python3", Pcomm: "bash", Path: "/usr/bin/python3",
				CgroupID: 2,
			},
		}

		for _, ev := range seedProcesses {
			select {
			case out <- ev:
			case <-ctx.Done():
				return
			case <-m.closed:
				return
			}
		}

		ticker := time.NewTicker(350 * time.Millisecond)
		defer ticker.Stop()

		var seq uint32 = 0
		// Bounded set of worker PIDs: 400..409 (10 workers max)
		const workerBase uint32 = 400
		const workerCount uint32 = 10
		workerBins := []string{"/usr/bin/curl", "/usr/bin/grep", "/usr/bin/awk", "/bin/cat"}

		for {
			select {
			case <-ctx.Done():
				return
			case <-m.closed:
				return
			case ts := <-ticker.C:
				seq++
				tsNs := uint64(ts.UnixNano())

				// Determine the current worker PID (rotating)
				workerPid := workerBase + (seq % workerCount)
				workerBin := workerBins[seq%uint32(len(workerBins))]
				workerComm := filepath.Base(workerBin)

				// Exit the previous occupant of this PID slot (if any after first cycle)
				if seq > workerCount {
					select {
					case out <- &events.Event{
						TimestampNs: tsNs,
						EventType:   events.EventExit,
						TypeName:    "EXIT",
						Pid:         workerPid,
						Ppid:        300,
						Comm:        workerComm,
						CgroupID:    2,
					}:
					default:
						atomic.AddUint64(&m.drops, 1)
					}
				}

				// Fork a new worker as a child of python3(300)
				forkEv := &events.Event{
					TimestampNs: tsNs + 1,
					EventType:   events.EventFork,
					TypeName:    "FORK",
					Pid:         300,
					Ppid:        200,
					NewFd:       workerPid, // child PID carried in NewFd
					Uid:         1000, Gid: 1000, Euid: 1000, Egid: 1000,
					Comm:    "python3",
					Pcomm:   "bash",
					Path:    "/usr/bin/python3",
					CgroupID: 2,
				}
				select {
				case out <- forkEv:
				default:
					atomic.AddUint64(&m.drops, 1)
				}

				// Exec the worker binary in the child
				execEv := &events.Event{
					TimestampNs: tsNs + 2,
					EventType:   events.EventExec,
					TypeName:    "EXEC",
					Pid:         workerPid,
					Tid:         workerPid,
					Ppid:        300,
					Uid:         1000, Gid: 1000, Euid: 1000, Egid: 1000,
					Comm:    workerComm,
					Pcomm:   "python3",
					Path:    workerBin,
					Extra:   "--help",
					CgroupID: 2,
				}
				select {
				case out <- execEv:
				default:
					atomic.AddUint64(&m.drops, 1)
				}

				// Periodically simulate reverse shell attack chain:
				// bash(200) → nc(500): connect → dup stdin → exec /bin/sh
				if seq%25 == 0 {
					attackPid := uint32(500)
					attackTs := uint64(time.Now().UnixNano())

					// Exit the previous occupant of PID 500
					out <- &events.Event{
						TimestampNs: attackTs,
						EventType:   events.EventExit,
						TypeName:    "EXIT",
						Pid:         attackPid,
						Ppid:        200,
						Comm:        "nc",
						CgroupID:    2,
					}

					// 1. Connect to external address
					out <- &events.Event{
						TimestampNs: attackTs + 1,
						EventType:   events.EventConnect,
						TypeName:    "CONNECT",
						Pid:         attackPid,
						Ppid:        200,
						Fd:          4,
						Daddr:       "198.51.100.42",
						Dport:       4444,
						Comm:        "nc",
						Pcomm:       "bash",
						Path:        "/bin/nc",
						CgroupID:    2,
					}
					// 2. Dup socket fd to stdin
					out <- &events.Event{
						TimestampNs: attackTs + 2,
						EventType:   events.EventDup,
						TypeName:    "DUP",
						Pid:         attackPid,
						Ppid:        200,
						OldFd:       4,
						NewFd:       0, // stdin
						Comm:        "nc",
						Pcomm:       "bash",
						CgroupID:    2,
					}
					// 3. Exec a shell
					out <- &events.Event{
						TimestampNs: attackTs + 3,
						EventType:   events.EventExec,
						TypeName:    "EXEC",
						Pid:         attackPid,
						Ppid:        200,
						Comm:        "sh",
						Pcomm:       "nc",
						Path:        "/bin/sh",
						CgroupID:    2,
					}
				}

				// Periodically simulate file tampering:
				// bash(200) → suspicious_app(600) opens /etc/shadow
				if seq%40 == 0 {
					tamperPid := uint32(600)
					tamperTs := uint64(time.Now().UnixNano())

					// Exit + re-exec to keep PID slot clean
					out <- &events.Event{
						TimestampNs: tamperTs,
						EventType:   events.EventExit,
						TypeName:    "EXIT",
						Pid:         tamperPid,
						Ppid:        200,
						Comm:        "suspicious_app",
						CgroupID:    2,
					}
					out <- &events.Event{
						TimestampNs: tamperTs + 1,
						EventType:   events.EventExec,
						TypeName:    "EXEC",
						Pid:         tamperPid,
						Ppid:        200,
						Uid:         1000, Gid: 1000, Euid: 1000, Egid: 1000,
						Comm:    "suspicious_app",
						Pcomm:   "bash",
						Path:    "/tmp/suspicious_app",
						CgroupID: 2,
					}
					out <- &events.Event{
						TimestampNs: tamperTs + 2,
						EventType:   events.EventOpenAt,
						TypeName:    "OPENAT",
						Pid:         tamperPid,
						Ppid:        200,
						Uid:         1000, Gid: 1000, Euid: 1000, Egid: 1000,
						Flags:   2, // O_RDWR
						Path:    "/etc/shadow",
						Comm:    "suspicious_app",
						CgroupID: 2,
					}
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
