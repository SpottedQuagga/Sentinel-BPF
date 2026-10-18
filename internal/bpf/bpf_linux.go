//go:build linux

package bpf

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/sentinel-bpf/sentinel/internal/config"
	"github.com/sentinel-bpf/sentinel/internal/events"
)

// LinuxRingbufReader consumes records from a live eBPF ring buffer map.
type LinuxRingbufReader struct {
	reader *ringbuf.Reader
	drops  uint64
}

// NewLinuxRingbufReader creates a ring buffer reader attached to an ebpf.Map.
func NewLinuxRingbufReader(eventsMap *ebpf.Map) (*LinuxRingbufReader, error) {
	rd, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		return nil, fmt.Errorf("create ringbuf reader: %w", err)
	}

	return &LinuxRingbufReader{
		reader: rd,
	}, nil
}

func (r *LinuxRingbufReader) KernelDrops() uint64 {
	return atomic.LoadUint64(&r.drops)
}

func (r *LinuxRingbufReader) Close() error {
	if r.reader != nil {
		return r.reader.Close()
	}
	return nil
}

// Start runs the hot-path ring buffer read loop:
// "The ring buffer reader loop must never block or do slow work.
// No JSON encoding, disk I/O, network I/O or long-held locks in it.
// Decode, push to a buffered channel, continue."
func (r *LinuxRingbufReader) Start(ctx context.Context, out chan<- *events.Event) error {
	go func() {
		var record ringbuf.Record
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			err := r.reader.ReadInto(&record)
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				continue
			}

			// Fast decode
			ev, err := events.FromRaw(record.RawSample)
			if err != nil {
				continue
			}

			// Non-blocking push to channel
			select {
			case out <- ev:
			default:
				// Userspace queue drop
				atomic.AddUint64(&r.drops, 1)
			}
		}
	}()

	return nil
}

// UpdateIgnoredPids adds a PID to the ignored_pids map.
func UpdateIgnoredPids(ignoredMap *ebpf.Map, pid uint32) error {
	if ignoredMap == nil {
		return errors.New("ignored_pids map is nil")
	}
	var val uint8 = 1
	return ignoredMap.Update(&pid, &val, ebpf.UpdateAny)
}

// IgnoreSelf adds the current process PID to the ignored_pids map.
func IgnoreSelf(ignoredMap *ebpf.Map) error {
	return UpdateIgnoredPids(ignoredMap, uint32(os.Getpid()))
}

// LinuxBPFSession holds loaded objects, ring buffer reader, and attached trace links.
type LinuxBPFSession struct {
	Objs   sentinelObjects
	Links  []link.Link
	Reader *LinuxRingbufReader
}

// Close cleanly releases all eBPF links, reader, and object descriptors.
func (s *LinuxBPFSession) Close() error {
	var firstErr error
	if s.Reader != nil {
		if err := s.Reader.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for _, l := range s.Links {
		if err := l.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if err := s.Objs.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// ReadKernelDrops reads the kernel drop counter from the drops map.
func (s *LinuxBPFSession) ReadKernelDrops() uint64 {
	if s.Objs.Drops == nil {
		return 0
	}
	var key uint32 = 0
	var val uint64 = 0
	if err := s.Objs.Drops.Lookup(&key, &val); err == nil {
		return val
	}
	return 0
}

// LoadAndAttach loads eBPF objects, applies config, attaches hooks, and initializes ring buffer.
func LoadAndAttach(cfg *config.Config) (*LinuxBPFSession, error) {
	// 1. Verify root privileges (EUID 0)
	if os.Geteuid() != 0 {
		return nil, errors.New("root privileges (EUID 0) required to load eBPF programs into kernel")
	}

	// 2. Verify kernel BTF support
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		return nil, fmt.Errorf("kernel BTF (/sys/kernel/btf/vmlinux) not accessible: %w (CONFIG_DEBUG_INFO_BTF=y required)", err)
	}

	// 3. Remove memlock limit
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock limit: %w", err)
	}

	// 4. Load collection spec and adjust ring buffer size
	spec, err := loadSentinel()
	if err != nil {
		return nil, fmt.Errorf("load sentinel spec: %w", err)
	}

	if eventsSpec, ok := spec.Maps["events"]; ok && cfg.BPF.RingBufferSize > 0 {
		eventsSpec.MaxEntries = uint32(cfg.BPF.RingBufferSize)
	}

	// 5. Load and assign objects into kernel
	var objs sentinelObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Printf("[ERROR] eBPF Verifier Error:\n%+v", ve)
		}
		return nil, fmt.Errorf("load eBPF objects: %w", err)
	}

	// 6. Put current daemon PID in ignored_pids map
	if err := IgnoreSelf(objs.IgnoredPids); err != nil {
		log.Printf("[WARN] Failed to add self to ignored_pids map: %v", err)
	}

	// 7. Attach tracepoints & tracing hooks
	var links []link.Link
	cleanupLinks := func() {
		for _, l := range links {
			_ = l.Close()
		}
		_ = objs.Close()
	}

	// tp_btf / tracing: sched_process_exec
	execLink, err := link.AttachTracing(link.TracingOptions{
		Program: objs.TraceSchedProcessExec,
	})
	if err != nil {
		cleanupLinks()
		return nil, fmt.Errorf("attach tp_btf/sched_process_exec: %w", err)
	}
	links = append(links, execLink)

	// tracepoints
	type tpDef struct {
		group string
		name  string
		prog  *ebpf.Program
		opt   bool // optional
	}

	hooks := []tpDef{
		{"sched", "sched_process_exit", objs.TraceSchedProcessExit, false},
		{"sched", "sched_process_fork", objs.TraceSchedProcessFork, false},
		{"syscalls", "sys_enter_openat", objs.TraceSysEnterOpenat, false},
		{"syscalls", "sys_enter_connect", objs.TraceSysEnterConnect, false},
		{"syscalls", "sys_enter_dup3", objs.TraceSysEnterDup3, false},
		{"syscalls", "sys_enter_dup2", objs.TraceSysEnterDup2, true}, // optional (not on arm64/some kernels)
		{"syscalls", "sys_enter_ptrace", objs.TraceSysEnterPtrace, false},
		{"syscalls", "sys_enter_mount", objs.TraceSysEnterMount, false},
		{"syscalls", "sys_enter_setuid", objs.TraceSysEnterSetuid, false},
	}

	for _, h := range hooks {
		l, err := link.Tracepoint(h.group, h.name, h.prog, nil)
		if err != nil {
			if h.opt {
				log.Printf("[WARN] attach %s/%s (optional): %v", h.group, h.name, err)
				continue
			}
			cleanupLinks()
			return nil, fmt.Errorf("attach %s/%s: %w", h.group, h.name, err)
		}
		links = append(links, l)
	}

	// 8. Open ring buffer reader
	rd, err := NewLinuxRingbufReader(objs.Events)
	if err != nil {
		cleanupLinks()
		return nil, fmt.Errorf("create ring buffer reader: %w", err)
	}

	return &LinuxBPFSession{
		Objs:   objs,
		Links:  links,
		Reader: rd,
	}, nil
}
