package proctable

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sentinel-bpf/sentinel/internal/events"
)

// ProcessInfo holds in-memory metadata and lineage for a tracked process.
type ProcessInfo struct {
	Pid         uint32 `json:"pid"`
	Ppid        uint32 `json:"ppid"`
	Uid         uint32 `json:"uid"`
	Gid         uint32 `json:"gid"`
	Euid        uint32 `json:"euid"`
	Egid        uint32 `json:"egid"`
	Comm        string `json:"comm"`
	Path        string `json:"path"`
	Args        string `json:"args,omitempty"`
	CgroupID    uint64 `json:"cgroup_id"`
	StartTimeNs uint64 `json:"start_time_ns"`
	Exited      bool   `json:"exited"`
}

// Table maintains a bounded in-memory process table.
type Table struct {
	mu           sync.RWMutex
	procs        map[uint32]*ProcessInfo
	maxProcs     int
	lastProcRead time.Time
}

// New creates an initialized process table with a maximum size bound.
func New(maxProcs int) *Table {
	if maxProcs <= 0 {
		maxProcs = 10000
	}
	return &Table{
		procs:    make(map[uint32]*ProcessInfo, 1024),
		maxProcs: maxProcs,
	}
}

// Put inserts or updates a process in the table.
func (t *Table) Put(info *ProcessInfo) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// If at capacity and adding new process, evict oldest or exited procs
	if len(t.procs) >= t.maxProcs {
		if _, exists := t.procs[info.Pid]; !exists {
			t.evictOldestLocked()
		}
	}

	t.procs[info.Pid] = info
}

// Get retrieves a process from the table by PID.
func (t *Table) Get(pid uint32) (*ProcessInfo, bool) {
	t.mu.RLock()
	info, found := t.procs[pid]
	t.mu.RUnlock()

	if found {
		return info, true
	}

	// Cold cache miss: attempt rate-limited /proc fallback (only on Linux)
	return t.fallbackProcRead(pid)
}

// HandleExec updates process state upon process exec event.
func (t *Table) HandleExec(ev *events.Event) {
	t.Put(&ProcessInfo{
		Pid:         ev.Pid,
		Ppid:        ev.Ppid,
		Uid:         ev.Uid,
		Gid:         ev.Gid,
		Euid:        ev.Euid,
		Egid:        ev.Egid,
		Comm:        ev.Comm,
		Path:        ev.Path,
		Args:        ev.Extra,
		CgroupID:    ev.CgroupID,
		StartTimeNs: ev.TimestampNs,
		Exited:      false,
	})
}

// HandleFork registers child process inheritance.
func (t *Table) HandleFork(ev *events.Event) {
	parentPid := ev.Pid
	childPid := ev.NewFd // carried in NewFd

	t.mu.RLock()
	parent, exists := t.procs[parentPid]
	t.mu.RUnlock()

	comm := ev.Comm
	path := ""
	if exists && parent != nil {
		comm = parent.Comm
		path = parent.Path
	}

	t.Put(&ProcessInfo{
		Pid:         childPid,
		Ppid:        parentPid,
		Uid:         ev.Uid,
		Gid:         ev.Gid,
		Euid:        ev.Euid,
		Egid:        ev.Egid,
		Comm:        comm,
		Path:        path,
		CgroupID:    ev.CgroupID,
		StartTimeNs: ev.TimestampNs,
		Exited:      false,
	})
}

// HandleExit marks a process as exited and reparents orphaned child processes to PID 1.
func (t *Table) HandleExit(ev *events.Event) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if info, exists := t.procs[ev.Pid]; exists {
		info.Exited = true
	}

	for _, proc := range t.procs {
		if proc.Ppid == ev.Pid && !proc.Exited {
			proc.Ppid = 1
		}
	}
}

// GetLineage returns the ancestry chain from the process up to the root.
// Limits maximum depth to 32 to prevent cyclic parent loops.
func (t *Table) GetLineage(pid uint32) []*ProcessInfo {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var lineage []*ProcessInfo
	visited := make(map[uint32]bool, 16)
	currPid := pid

	for depth := 0; depth < 32 && currPid > 0; depth++ {
		if visited[currPid] {
			break // Prevent infinite cycles
		}
		visited[currPid] = true

		info, exists := t.procs[currPid]
		if !exists {
			break
		}

		lineage = append(lineage, info)
		if info.Ppid == currPid || info.Ppid == 0 {
			break
		}
		currPid = info.Ppid
	}

	return lineage
}

// GetAll returns a snapshot of all active processes.
func (t *Table) GetAll() []*ProcessInfo {
	t.mu.RLock()
	defer t.mu.RUnlock()

	list := make([]*ProcessInfo, 0, len(t.procs))
	for _, p := range t.procs {
		list = append(list, p)
	}
	return list
}

// Count returns the number of tracked processes.
func (t *Table) Count() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.procs)
}

func (t *Table) evictOldestLocked() {
	// First pass: evict any exited process
	for pid, info := range t.procs {
		if info.Exited {
			delete(t.procs, pid)
			return
		}
	}

	// Second pass: evict an arbitrary entry if all are active
	for pid := range t.procs {
		delete(t.procs, pid)
		return
	}
}

// fallbackProcRead performs a rate-limited lookup in /proc/<pid> on Linux.
func (t *Table) fallbackProcRead(pid uint32) (*ProcessInfo, bool) {
	t.mu.Lock()
	now := time.Now()
	// Rate-limit to at most 50 /proc reads per second (20ms interval)
	if now.Sub(t.lastProcRead) < 20*time.Millisecond {
		t.mu.Unlock()
		return nil, false
	}
	t.lastProcRead = now
	t.mu.Unlock()

	statPath := fmt.Sprintf("/proc/%d/stat", pid)
	data, err := os.ReadFile(statPath)
	if err != nil {
		return nil, false
	}

	fields := strings.Fields(string(data))
	if len(fields) < 5 {
		return nil, false
	}

	ppid, _ := strconv.Atoi(fields[3])
	comm := strings.Trim(fields[1], "()")

	info := &ProcessInfo{
		Pid:    pid,
		Ppid:   uint32(ppid),
		Comm:   comm,
		Exited: false,
	}

	t.Put(info)
	return info, true
}
