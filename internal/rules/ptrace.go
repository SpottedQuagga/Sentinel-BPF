package rules

import (
	"fmt"

	"github.com/sentinel-bpf/sentinel/internal/events"
)

// ProcessInjectionRule detects unauthorized ptrace usage against running processes.
type ProcessInjectionRule struct {
	allowedDebuggers map[string]bool
}

// NewProcessInjectionRule creates an initialized ptrace injection rule.
func NewProcessInjectionRule() *ProcessInjectionRule {
	return &ProcessInjectionRule{
		allowedDebuggers: map[string]bool{
			"gdb":    true,
			"lldb":   true,
			"strace": true,
			"dlv":    true,
		},
	}
}

func (r *ProcessInjectionRule) Name() string {
	return "process_injection"
}

func (r *ProcessInjectionRule) Description() string {
	return "Detects ptrace process inspection or memory injection attempts"
}

func (r *ProcessInjectionRule) Severity() Severity {
	return SeverityHigh
}

func (r *ProcessInjectionRule) Handle(ev *events.Event, state *State) []Alert {
	if ev.EventType != events.EventPtrace {
		return nil
	}

	targetPID := ev.NewFd // carried in NewFd

	// Allow known debuggers unless configured otherwise
	if r.allowedDebuggers[ev.Comm] {
		return nil
	}

	return []Alert{
		{
			RuleName:       r.Name(),
			Severity:       r.Severity(),
			MitreTechnique: "T1055.008", // Process Injection: Ptrace
			Pid:            ev.Pid,
			Ppid:           ev.Ppid,
			Comm:           ev.Comm,
			Path:           ev.Path,
			Message:        fmt.Sprintf("Suspicious ptrace injection attempt: %s (PID %d) invoked ptrace against PID %d", ev.Comm, ev.Pid, targetPID),
			Details: map[string]interface{}{
				"caller_comm":    ev.Comm,
				"caller_pid":     ev.Pid,
				"target_pid":     targetPID,
				"ptrace_request": ev.Flags,
			},
		},
	}
}
