package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config represents the complete SentinelBPF configuration.
type Config struct {
	Server  ServerConfig  `yaml:"server"`
	BPF     BPFConfig     `yaml:"bpf"`
	Rules   RulesConfig   `yaml:"rules"`
	Logging LoggingConfig `yaml:"logging"`
}

type ServerConfig struct {
	Host           string   `yaml:"host"`
	Port           int      `yaml:"port"`
	AuthToken      string   `yaml:"auth_token"`
	AllowedOrigins []string `yaml:"allowed_origins"`
}

type BPFConfig struct {
	RingBufferSize  int `yaml:"ring_buffer_size"`
	EventBufferSize int `yaml:"event_buffer_size"`
}

type RulesConfig struct {
	TreatLoopbackAsExternal bool                      `yaml:"treat_loopback_as_external"`
	AlertCooldownSeconds    int                       `yaml:"alert_cooldown_seconds"`
	ReverseShell            ReverseShellConfig        `yaml:"reverse_shell"`
	PrivilegeEscalation     PrivilegeEscalationConfig `yaml:"privilege_escalation"`
	FileTampering           FileTamperingConfig       `yaml:"file_tampering"`
	ProcessInjection        ProcessInjectionConfig    `yaml:"process_injection"`
	UnauthorizedMount       UnauthorizedMountConfig   `yaml:"unauthorized_mount"`
}

type ReverseShellConfig struct {
	Enabled                  bool     `yaml:"enabled"`
	ConnectionTimeoutSeconds int      `yaml:"connection_timeout_seconds"`
	ShellBinaries            []string `yaml:"shell_binaries"`
}

type PrivilegeEscalationConfig struct {
	Enabled               bool `yaml:"enabled"`
	MonitorSetuidBinaries bool `yaml:"monitor_setuid_binaries"`
}

type FileTamperingConfig struct {
	Enabled             bool     `yaml:"enabled"`
	SensitivePaths      []string `yaml:"sensitive_paths"`
	AllowlistedBinaries []string `yaml:"allowlisted_binaries"`
}

type ProcessInjectionConfig struct {
	Enabled bool `yaml:"enabled"`
}

type UnauthorizedMountConfig struct {
	Enabled bool `yaml:"enabled"`
}

type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// DefaultConfig returns safe default configuration values.
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Host:      "127.0.0.1",
			Port:      8080,
			AuthToken: "",
			AllowedOrigins: []string{
				"http://localhost:3000",
				"http://127.0.0.1:3000",
				"http://localhost:8080",
				"http://127.0.0.1:8080",
			},
		},
		BPF: BPFConfig{
			RingBufferSize:  16 * 1024 * 1024, // 16 MB
			EventBufferSize: 65536,
		},
		Rules: RulesConfig{
			TreatLoopbackAsExternal: false,
			AlertCooldownSeconds:    10,
			ReverseShell: ReverseShellConfig{
				Enabled:                  true,
				ConnectionTimeoutSeconds: 30,
				ShellBinaries: []string{
					"/bin/sh",
					"/bin/bash",
					"/bin/zsh",
					"/bin/dash",
					"/usr/bin/sh",
					"/usr/bin/bash",
					"/usr/bin/python",
					"/usr/bin/python3",
					"/usr/bin/perl",
					"/usr/bin/ruby",
					"/bin/nc",
					"/usr/bin/nc",
					"/bin/socat",
					"/usr/bin/socat",
				},
			},
			PrivilegeEscalation: PrivilegeEscalationConfig{
				Enabled:               true,
				MonitorSetuidBinaries: true,
			},
			FileTampering: FileTamperingConfig{
				Enabled: true,
				SensitivePaths: []string{
					"/etc/passwd",
					"/etc/shadow",
					"/etc/sudoers",
					"/etc/ld.so.preload",
				},
				AllowlistedBinaries: []string{
					"/usr/bin/passwd",
					"/usr/sbin/useradd",
					"/usr/sbin/usermod",
					"/usr/sbin/vipw",
				},
			},
			ProcessInjection: ProcessInjectionConfig{
				Enabled: true,
			},
			UnauthorizedMount: UnauthorizedMountConfig{
				Enabled: true,
			},
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "text",
		},
	}
}

// Load reads and parses a YAML configuration file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file %s: %w", path, err)
	}

	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config YAML %s: %w", path, err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate config %s: %w", path, err)
	}

	return cfg, nil
}

// Validate checks the configuration values for correctness and safety.
func (c *Config) Validate() error {
	// Port range check
	if c.Server.Port <= 0 || c.Server.Port > 65535 {
		return fmt.Errorf("invalid server port %d: must be between 1 and 65535", c.Server.Port)
	}

	// Host check
	if c.Server.Host == "" {
		return fmt.Errorf("server host cannot be empty")
	}

	// Ring buffer size must be power of 2 and >= 4096
	rbs := c.BPF.RingBufferSize
	if rbs < 4096 || (rbs&(rbs-1)) != 0 {
		return fmt.Errorf("ring_buffer_size (%d) must be a power of 2 and at least 4096 bytes", rbs)
	}

	// Event buffer size must be positive
	if c.BPF.EventBufferSize <= 0 {
		return fmt.Errorf("event_buffer_size (%d) must be positive", c.BPF.EventBufferSize)
	}

	// Cooldown seconds
	if c.Rules.AlertCooldownSeconds < 0 {
		return fmt.Errorf("alert_cooldown_seconds (%d) cannot be negative", c.Rules.AlertCooldownSeconds)
	}

	// Validate paths: all sensitive paths, allowlisted binaries, and shell binaries must be absolute paths
	for _, p := range c.Rules.FileTampering.SensitivePaths {
		if !isUnixAbs(p) {
			return fmt.Errorf("sensitive path %q must be an absolute path (starting with /)", p)
		}
	}

	for _, p := range c.Rules.FileTampering.AllowlistedBinaries {
		if !isUnixAbs(p) {
			return fmt.Errorf("allowlisted binary %q must be an absolute path (starting with /)", p)
		}
	}

	for _, p := range c.Rules.ReverseShell.ShellBinaries {
		if !isUnixAbs(p) {
			return fmt.Errorf("shell binary %q must be an absolute path (starting with /)", p)
		}
	}

	return nil
}

// ValidateCIDR verifies if a string is a valid CIDR representation
func ValidateCIDR(cidr string) error {
	_, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}
	return nil
}

func isUnixAbs(p string) bool {
	clean := filepath.ToSlash(strings.TrimSpace(p))
	return strings.HasPrefix(clean, "/")
}
