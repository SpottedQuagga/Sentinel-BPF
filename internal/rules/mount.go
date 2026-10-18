package rules

import (
	"fmt"
	"path/filepath"

	"github.com/sentinel-bpf/sentinel/internal/events"
)

// UnauthorizedMountRule detects suspicious filesystem mount attempts, e.g. from containers.
type UnauthorizedMountRule struct{}

// NewUnauthorizedMountRule creates an initialized mount detection rule.
func NewUnauthorizedMountRule() *UnauthorizedMountRule {
	return &UnauthorizedMountRule{}
}

func (r *UnauthorizedMountRule) Name() string {
	return "unauthorized_mount"
}

func (r *UnauthorizedMountRule) Description() string {
	return "Detects filesystem mount attempts from containers or non-standard processes"
}

func (r *UnauthorizedMountRule) Severity() Severity {
	return SeverityHigh
}

func (r *UnauthorizedMountRule) Handle(ev *events.Event, state *State) []Alert {
	if ev.EventType != events.EventMount {
		return nil
	}

	containerID := ev.ContainerID
	if containerID == "" && state != nil && state.Container != nil {
		containerID = state.Container.Resolve(ev.CgroupID, ev.Pid)
	}

	cleanDir := filepath.Clean(ev.Path)
	cleanDev := filepath.Clean(ev.Extra)

	// An unauthorized mount is especially critical when executed within a container
	severity := SeverityMedium
	msg := fmt.Sprintf("Filesystem mount invocation: %s mounting %s to %s", ev.Comm, cleanDev, cleanDir)
	if containerID != "" {
		severity = SeverityHigh
		msg = fmt.Sprintf("Container escape indicator: filesystem mount attempted inside container %s by %s", containerID, ev.Comm)
	}

	return []Alert{
		{
			RuleName:       r.Name(),
			Severity:       severity,
			MitreTechnique: "T1611", // Escape to Host
			Pid:            ev.Pid,
			Ppid:           ev.Ppid,
			Comm:           ev.Comm,
			Path:           cleanDir,
			ContainerID:    containerID,
			Message:        msg,
			Details: map[string]interface{}{
				"mount_source": cleanDev,
				"mount_target": cleanDir,
				"container_id": containerID,
			},
		},
	}
}
