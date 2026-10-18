package rules

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/sentinel-bpf/sentinel/internal/events"
)

// FileTamperingRule detects modification attempts targeting critical system files.
type FileTamperingRule struct {
	sensitivePaths      map[string]bool
	sensitivePrefixes   []string
	allowlistedBinaries map[string]bool
}

// NewFileTamperingRule creates an initialized file tampering detection rule.
func NewFileTamperingRule(paths []string, allowlist []string) *FileTamperingRule {
	sensMap := make(map[string]bool, len(paths))
	var prefixes []string

	for _, p := range paths {
		clean := filepath.Clean(p)
		sensMap[clean] = true
		if strings.HasSuffix(p, "/") || strings.HasSuffix(p, "/*") {
			prefixes = append(prefixes, strings.TrimSuffix(clean, "*"))
		}
	}

	allowMap := make(map[string]bool, len(allowlist))
	for _, b := range allowlist {
		clean := filepath.Clean(b)
		allowMap[clean] = true
		allowMap[filepath.Base(clean)] = true
	}

	return &FileTamperingRule{
		sensitivePaths:      sensMap,
		sensitivePrefixes:   prefixes,
		allowlistedBinaries: allowMap,
	}
}

func (r *FileTamperingRule) Name() string {
	return "file_tampering"
}

func (r *FileTamperingRule) Description() string {
	return "Detects write/create access to critical system files (/etc/passwd, shadow, sudoers, etc.)"
}

func (r *FileTamperingRule) Severity() Severity {
	return SeverityHigh
}

func (r *FileTamperingRule) Handle(ev *events.Event, state *State) []Alert {
	if ev.EventType != events.EventOpenAt {
		return nil
	}

	if ev.Path == "" {
		return nil
	}

	targetPath := filepath.Clean(ev.Path)

	// Check if the opened path is sensitive
	if !r.isSensitivePath(targetPath) {
		return nil
	}

	// Check if accessing process is allowlisted
	callerComm := ev.Comm
	callerPath := ""
	if state != nil && state.ProcTable != nil {
		if proc, ok := state.ProcTable.Get(ev.Pid); ok && proc.Path != "" {
			callerPath = filepath.Clean(proc.Path)
		}
	}

	if r.allowlistedBinaries[callerComm] || (callerPath != "" && r.allowlistedBinaries[callerPath]) {
		// Benign allowed system tool
		return nil
	}

	return []Alert{
		{
			RuleName:       r.Name(),
			Severity:       r.Severity(),
			MitreTechnique: "T1565.001", // Stored Data Manipulation
			Pid:            ev.Pid,
			Ppid:           ev.Ppid,
			Comm:           ev.Comm,
			Path:           targetPath,
			Message:        fmt.Sprintf("Sensitive system file tampering attempt: %s opened %s with write flags", ev.Comm, targetPath),
			Details: map[string]interface{}{
				"target_path": targetPath,
				"caller_comm": ev.Comm,
				"caller_path": callerPath,
				"open_flags":  ev.Flags,
				"euid":        ev.Euid,
			},
		},
	}
}

func (r *FileTamperingRule) isSensitivePath(target string) bool {
	if r.sensitivePaths[target] {
		return true
	}
	for sens := range r.sensitivePaths {
		if strings.HasPrefix(target, sens+"/") {
			return true
		}
	}
	for _, pfx := range r.sensitivePrefixes {
		cleanPfx := strings.TrimSuffix(pfx, "/") + "/"
		if strings.HasPrefix(target, cleanPfx) {
			return true
		}
	}
	return false
}
