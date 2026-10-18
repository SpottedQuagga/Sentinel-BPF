package events

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

// RawEventSize is the exact size of struct event in bpf/sentinel.h (strictly 480 bytes)
const RawEventSize = 480

// EventType corresponds to enum event_type in bpf/sentinel.h
type EventType uint64

const (
	EventUnknown EventType = 0
	EventExec    EventType = 1
	EventExit    EventType = 2
	EventFork    EventType = 3
	EventOpenAt  EventType = 4
	EventConnect EventType = 5
	EventDup     EventType = 6
	EventPtrace  EventType = 7
	EventMount   EventType = 8
	EventSetUID  EventType = 9
)

func (e EventType) String() string {
	switch e {
	case EventExec:
		return "EXEC"
	case EventExit:
		return "EXIT"
	case EventFork:
		return "FORK"
	case EventOpenAt:
		return "OPENAT"
	case EventConnect:
		return "CONNECT"
	case EventDup:
		return "DUP"
	case EventPtrace:
		return "PTRACE"
	case EventMount:
		return "MOUNT"
	case EventSetUID:
		return "SETUID"
	default:
		return "UNKNOWN"
	}
}

// RawEvent directly maps to struct event in bpf/sentinel.h.
// It is strictly 480 bytes, 8-byte aligned, with no compiler padding.
type RawEvent struct {
	TimestampNs uint64
	CgroupID    uint64
	EventType   uint64
	Retval      uint64
	Flags       uint64

	Pid   uint32
	Tid   uint32
	Ppid  uint32
	Uid   uint32
	Gid   uint32
	Euid  uint32
	Egid  uint32
	Fd    uint32
	OldFd uint32
	NewFd uint32

	Saddr    uint32
	Daddr    uint32
	Sport    uint16
	Dport    uint16
	Family   uint16
	Protocol uint16

	Comm  [16]byte
	Pcomm [16]byte
	Path  [256]byte
	Extra [96]byte
}

// Event is the decoded user-space event structure.
type Event struct {
	TimestampNs uint64    `json:"timestamp_ns"`
	CgroupID    uint64    `json:"cgroup_id"`
	ContainerID string    `json:"container_id,omitempty"`
	EventType   EventType `json:"event_type"`
	TypeName    string    `json:"type_name"`
	Retval      uint64    `json:"retval"`
	Flags       uint64    `json:"flags"`

	Pid   uint32 `json:"pid"`
	Tid   uint32 `json:"tid"`
	Ppid  uint32 `json:"ppid"`
	Uid   uint32 `json:"uid"`
	Gid   uint32 `json:"gid"`
	Euid  uint32 `json:"euid"`
	Egid  uint32 `json:"egid"`
	Fd    uint32 `json:"fd"`
	OldFd uint32 `json:"old_fd"`
	NewFd uint32 `json:"new_fd"`

	Saddr    string `json:"saddr,omitempty"`
	Daddr    string `json:"daddr,omitempty"`
	Sport    uint16 `json:"sport,omitempty"`
	Dport    uint16 `json:"dport,omitempty"`
	Family   uint16 `json:"family,omitempty"`
	Protocol uint16 `json:"protocol,omitempty"`

	Comm  string `json:"comm"`
	Pcomm string `json:"pcomm"`
	Path  string `json:"path"`
	Extra string `json:"extra,omitempty"`
}

// NullTerminatedString extracts a Go string from a byte slice up to the first NUL byte.
func NullTerminatedString(b []byte) string {
	idx := bytes.IndexByte(b, 0)
	if idx >= 0 {
		return string(b[:idx])
	}
	return string(b)
}

// IPToString converts uint32 IPv4 address to string.
func IPToString(ip uint32) string {
	if ip == 0 {
		return ""
	}
	b := []byte{
		byte(ip),
		byte(ip >> 8),
		byte(ip >> 16),
		byte(ip >> 24),
	}
	return net.IP(b).String()
}

// FromRaw decodes a 480-byte binary buffer from the ring buffer into an Event.
func FromRaw(data []byte) (*Event, error) {
	if len(data) < RawEventSize {
		return nil, fmt.Errorf("buffer too short: expected %d bytes, got %d", RawEventSize, len(data))
	}

	var raw RawEvent
	buf := bytes.NewReader(data[:RawEventSize])
	if err := binary.Read(buf, binary.NativeEndian, &raw); err != nil {
		return nil, fmt.Errorf("failed to decode raw event: %w", err)
	}

	ev := &Event{
		TimestampNs: raw.TimestampNs,
		CgroupID:    raw.CgroupID,
		EventType:   EventType(raw.EventType),
		TypeName:    EventType(raw.EventType).String(),
		Retval:      raw.Retval,
		Flags:       raw.Flags,
		Pid:         raw.Pid,
		Tid:         raw.Tid,
		Ppid:        raw.Ppid,
		Uid:         raw.Uid,
		Gid:         raw.Gid,
		Euid:        raw.Euid,
		Egid:        raw.Egid,
		Fd:          raw.Fd,
		OldFd:       raw.OldFd,
		NewFd:       raw.NewFd,
		Saddr:       IPToString(raw.Saddr),
		Daddr:       IPToString(raw.Daddr),
		Sport:       raw.Sport,
		Dport:       raw.Dport,
		Family:      raw.Family,
		Protocol:    raw.Protocol,
		Comm:        NullTerminatedString(raw.Comm[:]),
		Pcomm:       NullTerminatedString(raw.Pcomm[:]),
		Path:        NullTerminatedString(raw.Path[:]),
		Extra:       NullTerminatedString(raw.Extra[:]),
	}

	return ev, nil
}
