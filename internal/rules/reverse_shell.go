package rules

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sentinel-bpf/sentinel/internal/events"
)

type shellStage int

const (
	stageNone       shellStage = 0
	stageConnected  shellStage = 1
	stageRedirected shellStage = 2
)

type procShellState struct {
	socketFd      uint32
	remoteIP      string
	remotePort    uint16
	stage         shellStage
	redirectedFDs []uint32
	updatedAt     time.Time
}

// ReverseShellRule detects reverse shells using a strict 3-stage state machine:
// 1. connect() to external IP
// 2. dup2/dup3() of socket fd to stdin/stdout/stderr (0, 1, 2)
// 3. exec() of a shell interpreter
type ReverseShellRule struct {
	mu                      sync.Mutex
	treatLoopbackAsExternal bool
	shellBinaries           map[string]bool
	procStates              map[uint32]*procShellState
	timeout                 time.Duration
}

// NewReverseShellRule initializes the reverse shell rule.
func NewReverseShellRule(treatLoopback bool, shells []string) *ReverseShellRule {
	shellMap := make(map[string]bool, len(shells))
	for _, s := range shells {
		clean := filepath.Clean(s)
		shellMap[clean] = true
		shellMap[filepath.Base(clean)] = true
	}

	return &ReverseShellRule{
		treatLoopbackAsExternal: treatLoopback,
		shellBinaries:           shellMap,
		procStates:              make(map[uint32]*procShellState, 128),
		timeout:                 30 * time.Second,
	}
}

func (r *ReverseShellRule) Name() string {
	return "reverse_shell"
}

func (r *ReverseShellRule) Description() string {
	return "Detects reverse shells via connect -> socket dup to stdio -> shell execution"
}

func (r *ReverseShellRule) Severity() Severity {
	return SeverityCritical
}

func (r *ReverseShellRule) Handle(ev *events.Event, state *State) []Alert {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	r.pruneExpiredLocked(now)

	switch ev.EventType {
	case events.EventConnect:
		// Check destination address
		if !r.isTargetExternal(ev.Daddr) {
			return nil
		}

		// Stage 1: Process connected to external address
		r.procStates[ev.Pid] = &procShellState{
			socketFd:      ev.Fd,
			remoteIP:      ev.Daddr,
			remotePort:    ev.Dport,
			stage:         stageConnected,
			redirectedFDs: make([]uint32, 0, 3),
			updatedAt:     now,
		}
		return nil

	case events.EventDup:
		st, exists := r.procStates[ev.Pid]
		if !exists || st.stage < stageConnected {
			return nil
		}

		// Verify that the file descriptor duplicated is the connected socket
		// and the target is stdin (0), stdout (1), or stderr (2)
		if ev.OldFd == st.socketFd && ev.NewFd <= 2 {
			st.stage = stageRedirected
			st.redirectedFDs = append(st.redirectedFDs, ev.NewFd)
			st.updatedAt = now
		}
		return nil

	case events.EventExec:
		st, exists := r.procStates[ev.Pid]
		if !exists || st.stage != stageRedirected {
			return nil
		}

		// Stage 3: Process in redirected state attempts to exec a shell
		cleanPath := filepath.Clean(ev.Path)
		baseName := filepath.Base(cleanPath)

		if r.shellBinaries[cleanPath] || r.shellBinaries[baseName] || r.shellBinaries[ev.Comm] {
			// CRITICAL: Reverse Shell Detected!
			remoteEp := fmt.Sprintf("%s:%d", st.remoteIP, st.remotePort)
			alert := Alert{
				RuleName:       r.Name(),
				Severity:       r.Severity(),
				MitreTechnique: "T1059.004", // Unix Shell
				Pid:            ev.Pid,
				Ppid:           ev.Ppid,
				Comm:           ev.Comm,
				Path:           cleanPath,
				Message:        fmt.Sprintf("Reverse shell detected: stdio redirected to %s followed by execution of %s", remoteEp, cleanPath),
				Details: map[string]interface{}{
					"remote_endpoint": remoteEp,
					"remote_ip":       st.remoteIP,
					"remote_port":     st.remotePort,
					"redirected_fds":  st.redirectedFDs,
					"socket_fd":       st.socketFd,
					"binary":          cleanPath,
				},
			}

			// Clean up process state
			delete(r.procStates, ev.Pid)
			return []Alert{alert}
		}

	case events.EventExit:
		delete(r.procStates, ev.Pid)
	}

	return nil
}

func (r *ReverseShellRule) isTargetExternal(ip string) bool {
	if ip == "" {
		return false
	}
	// Loopback check
	if strings.HasPrefix(ip, "127.") || ip == "::1" || ip == "0.0.0.0" {
		return r.treatLoopbackAsExternal
	}
	return true
}

func (r *ReverseShellRule) pruneExpiredLocked(now time.Time) {
	if len(r.procStates) > 64 {
		for pid, st := range r.procStates {
			if now.Sub(st.updatedAt) > r.timeout {
				delete(r.procStates, pid)
			}
		}
	}
}
