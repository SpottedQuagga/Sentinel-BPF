export type Severity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type EventType =
  | 'EXEC'
  | 'EXIT'
  | 'FORK'
  | 'OPENAT'
  | 'CONNECT'
  | 'DUP'
  | 'PTRACE'
  | 'MOUNT'
  | 'SETUID'
  | 'UNKNOWN';

export interface KernelEvent {
  timestamp_ns: number;
  cgroup_id: number;
  container_id?: string;
  event_type: number;
  type_name: EventType;
  retval: number;
  flags: number;
  pid: number;
  tid: number;
  ppid: number;
  uid: number;
  gid: number;
  euid: number;
  egid: number;
  fd: number;
  old_fd: number;
  new_fd: number;
  saddr?: string;
  daddr?: string;
  sport?: number;
  dport?: number;
  family?: number;
  protocol?: number;
  comm: string;
  pcomm: string;
  path: string;
  extra?: string;
}

export interface SecurityAlert {
  id: string;
  timestamp: string;
  rule_name: string;
  severity: Severity;
  mitre_technique: string;
  pid: number;
  ppid: number;
  comm: string;
  path: string;
  container_id?: string;
  message: string;
  details?: Record<string, string | number | boolean | string[] | number[] | Record<string, unknown>>;
}

export interface SystemMetrics {
  events_per_sec: number;
  total_events: number;
  kernel_drops: number;
  active_processes: number;
  active_clients: number;
  uptime_seconds?: number;
}

export interface InitialStateData {
  alerts: SecurityAlert[];
  active_processes: number;
  uptime_seconds: number;
}

export type WSMessage =
  | { type: 'hello'; mock: boolean; version?: string }
  | { type: 'snapshot'; data: InitialStateData & { mock?: boolean } }
  | { type: 'initial_state'; data: InitialStateData & { mock?: boolean } }
  | { type: 'event'; data: KernelEvent }
  | { type: 'alert'; data: SecurityAlert }
  | { type: 'metrics'; data: SystemMetrics };

export interface ProcessNode {
  pid: number;
  ppid: number;
  comm: string;
  path?: string;
  container_id?: string;
  hasAlert?: boolean;
  children?: ProcessNode[];
}

export type ConnectionStatus = 'CONNECTED' | 'CONNECTING' | 'DISCONNECTED' | 'ERROR';
