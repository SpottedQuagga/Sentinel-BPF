package rules

import (
	"fmt"
	"path/filepath"

	"github.com/sentinel-bpf/sentinel/internal/events"
)

// PrivilegeEscalationRule detects suspicious setuid calls or unexpected elevation attempts.
type PrivilegeEscalationRule struct {
	privEscBinaries map[string]bool
}

// NewPrivilegeEscalationRule creates an initialized rule.
func NewPrivilegeEscalationRule() *PrivilegeEscalationRule {
	return &PrivilegeEscalationRule{
		privEscBinaries: map[string]bool{
			"sudo":   true,
			"pkexec": true,
			"su":     true,
			"doas":   true,
		},
	}
}

func (r *PrivilegeEscalationRule) Name() string {
	return "privilege_escalation"
}

func (r *PrivilegeEscalationRule) Description() string {
	return "Detects setuid(0) syscalls by non-root callers and privilege escalation tools"
}

func (r *PrivilegeEscalationRule) Severity() Severity {
	return SeverityHigh
}

func (r *PrivilegeEscalationRule) Handle(ev *events.Event, state *State) []Alert {
	// Rule requires non-root caller based on effective UID (euid)
	// Legitimate setuid tools (e.g., passwd running setuid root) have euid==0 and are not flagged.
	if ev.EventType == events.EventSetUID {
		targetUID := ev.Retval // retval carries requested uid argument
		if targetUID == 0 && ev.Euid != 0 {
			return []Alert{
				{
					RuleName:       r.Name(),
					Severity:       r.Severity(),
					MitreTechnique: "T1548.001", // Setuid and Setgid
					Pid:            ev.Pid,
					Ppid:           ev.Ppid,
					Comm:           ev.Comm,
					Path:           ev.Path,
					Message:        fmt.Sprintf("Privilege escalation attempt: process %s (PID %d, EUID %d) attempted setuid(0)", ev.Comm, ev.Pid, ev.Euid),
					Details: map[string]interface{}{
						"requested_uid": targetUID,
						"euid":          ev.Euid,
						"uid":           ev.Uid,
						"comm":          ev.Comm,
					},
				},
			}
		}
	}

	if ev.EventType == events.EventExec {
		clean := filepath.Clean(ev.Path)
		base := filepath.Base(clean)

		// Non-root caller invoking elevation binaries
		if ev.Euid != 0 && (r.privEscBinaries[base] || r.privEscBinaries[ev.Comm]) {
			return []Alert{
				{
					RuleName:       r.Name(),
					Severity:       SeverityMedium,
					MitreTechnique: "T1548.003", // Sudo and Sudo Caching
					Pid:            ev.Pid,
					Ppid:           ev.Ppid,
					Comm:           ev.Comm,
					Path:           clean,
					Message:        fmt.Sprintf("Privilege elevation tool executed: %s by user %d (PID %d)", base, ev.Euid, ev.Pid),
					Details: map[string]interface{}{
						"binary": clean,
						"euid":   ev.Euid,
						"uid":    ev.Uid,
					},
				},
			}
		}
	}

	return nil
}
