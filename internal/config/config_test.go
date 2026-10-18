package config

import (
	"testing"
)

func TestDefaultConfigValid(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("DefaultConfig() should be valid, got: %v", err)
	}
}

func TestRingBufferSizePowerOfTwo(t *testing.T) {
	tests := []struct {
		name    string
		size    int
		wantErr bool
	}{
		{"Valid 4096", 4096, false},
		{"Valid 16MB", 16 * 1024 * 1024, false},
		{"Valid 64MB", 64 * 1024 * 1024, false},
		{"Invalid non-power-of-two (1000)", 1000, true},
		{"Invalid non-power-of-two (15000000)", 15000000, true},
		{"Invalid zero", 0, true},
		{"Invalid negative", -1024, true},
		{"Invalid too small (2048)", 2048, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.BPF.RingBufferSize = tt.size
			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() for size %d err = %v, wantErr %v", tt.size, err, tt.wantErr)
			}
		})
	}
}

func TestPortValidation(t *testing.T) {
	tests := []struct {
		port    int
		wantErr bool
	}{
		{8080, false},
		{1, false},
		{65535, false},
		{0, true},
		{-1, true},
		{70000, true},
	}

	for _, tt := range tests {
		cfg := DefaultConfig()
		cfg.Server.Port = tt.port
		err := cfg.Validate()
		if (err != nil) != tt.wantErr {
			t.Errorf("Validate() for port %d err = %v, wantErr %v", tt.port, err, tt.wantErr)
		}
	}
}

func TestRelativePathsRejected(t *testing.T) {
	// Sensitive paths must be absolute
	cfg := DefaultConfig()
	cfg.Rules.FileTampering.SensitivePaths = []string{"etc/passwd"} // relative
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for relative sensitive path 'etc/passwd', got nil")
	}

	// Allowlisted binaries must be absolute
	cfg = DefaultConfig()
	cfg.Rules.FileTampering.AllowlistedBinaries = []string{"bin/passwd"}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for relative allowlisted binary 'bin/passwd', got nil")
	}

	// Shell binaries must be absolute
	cfg = DefaultConfig()
	cfg.Rules.ReverseShell.ShellBinaries = []string{"bash"}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for relative shell binary 'bash', got nil")
	}
}

func TestCIDRValidation(t *testing.T) {
	tests := []struct {
		cidr    string
		wantErr bool
	}{
		{"192.168.1.0/24", false},
		{"10.0.0.0/8", false},
		{"127.0.0.1/32", false},
		{"::1/128", false},
		{"invalid-cidr", true},
		{"192.168.1.300/24", true},
		{"192.168.1.1", true}, // Missing mask
	}

	for _, tt := range tests {
		err := ValidateCIDR(tt.cidr)
		if (err != nil) != tt.wantErr {
			t.Errorf("ValidateCIDR(%q) err = %v, wantErr %v", tt.cidr, err, tt.wantErr)
		}
	}
}
