package events

import (
	"bytes"
	"encoding/binary"
	"testing"
	"unsafe"
)

func TestRawEventSize(t *testing.T) {
	var raw RawEvent
	size := unsafe.Sizeof(raw)
	if size != RawEventSize {
		t.Fatalf("RawEvent struct size mismatch: expected %d bytes, got %d", RawEventSize, size)
	}

	// Also verify using binary.Size
	binSize := binary.Size(raw)
	if binSize != RawEventSize {
		t.Fatalf("binary.Size(RawEvent) mismatch: expected %d, got %d", RawEventSize, binSize)
	}
}

func TestFromRawDecoding(t *testing.T) {
	var raw RawEvent
	raw.TimestampNs = 1700000000123456789
	raw.CgroupID = 1048576
	raw.EventType = uint64(EventExec)
	raw.Retval = 0
	raw.Flags = 0x2
	raw.Pid = 1337
	raw.Tid = 1337
	raw.Ppid = 1000
	raw.Uid = 1000
	raw.Gid = 1000
	raw.Euid = 0 // Root execution
	raw.Egid = 0
	raw.Fd = 3
	raw.OldFd = 3
	raw.NewFd = 0
	raw.Saddr = 0x0100007F // 127.0.0.1
	raw.Daddr = 0x0101A8C0 // 192.168.1.1
	raw.Sport = 54321
	raw.Dport = 4444
	raw.Family = 2
	raw.Protocol = 6

	copy(raw.Comm[:], "bash\x00")
	copy(raw.Pcomm[:], "sshd\x00")
	copy(raw.Path[:], "/bin/bash\x00")
	copy(raw.Extra[:], "-i\x00")

	var buf bytes.Buffer
	err := binary.Write(&buf, binary.NativeEndian, &raw)
	if err != nil {
		t.Fatalf("failed to encode raw event: %v", err)
	}

	if buf.Len() != 480 {
		t.Fatalf("expected encoded buffer length 480, got %d", buf.Len())
	}

	ev, err := FromRaw(buf.Bytes())
	if err != nil {
		t.Fatalf("FromRaw failed: %v", err)
	}

	if ev.TimestampNs != 1700000000123456789 {
		t.Errorf("expected TimestampNs 1700000000123456789, got %d", ev.TimestampNs)
	}
	if ev.EventType != EventExec {
		t.Errorf("expected EventType EventExec, got %v", ev.EventType)
	}
	if ev.TypeName != "EXEC" {
		t.Errorf("expected TypeName EXEC, got %s", ev.TypeName)
	}
	if ev.Pid != 1337 {
		t.Errorf("expected Pid 1337, got %d", ev.Pid)
	}
	if ev.Ppid != 1000 {
		t.Errorf("expected Ppid 1000, got %d", ev.Ppid)
	}
	if ev.Euid != 0 {
		t.Errorf("expected Euid 0, got %d", ev.Euid)
	}
	if ev.Comm != "bash" {
		t.Errorf("expected Comm bash, got %q", ev.Comm)
	}
	if ev.Pcomm != "sshd" {
		t.Errorf("expected Pcomm sshd, got %q", ev.Pcomm)
	}
	if ev.Path != "/bin/bash" {
		t.Errorf("expected Path /bin/bash, got %q", ev.Path)
	}
	if ev.Extra != "-i" {
		t.Errorf("expected Extra -i, got %q", ev.Extra)
	}
	if ev.Dport != 4444 {
		t.Errorf("expected Dport 4444, got %d", ev.Dport)
	}
}

func TestFromRawBufferTooShort(t *testing.T) {
	shortBuf := make([]byte, 200)
	_, err := FromRaw(shortBuf)
	if err == nil {
		t.Fatal("expected error for buffer shorter than 480 bytes, got nil")
	}
}

func TestNullTerminatedString(t *testing.T) {
	tests := []struct {
		input    []byte
		expected string
	}{
		{[]byte("hello\x00world"), "hello"},
		{[]byte("fullstring"), "fullstring"},
		{[]byte("\x00initialnull"), ""},
		{[]byte{}, ""},
	}

	for _, tt := range tests {
		res := NullTerminatedString(tt.input)
		if res != tt.expected {
			t.Errorf("NullTerminatedString(%v) = %q, expected %q", tt.input, res, tt.expected)
		}
	}
}
