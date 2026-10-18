'use client';

import React, { useState, useMemo } from 'react';
import { KernelEvent, EventType } from '../types';
import { Pause, Play, Search, Trash2 } from 'lucide-react';

interface LiveEventStreamProps {
  events: KernelEvent[];
  onClear: () => void;
}

export const LiveEventStream: React.FC<LiveEventStreamProps> = ({ events, onClear }) => {
  const [isPaused, setIsPaused] = useState(false);
  const [filterType, setFilterType] = useState<EventType | 'ALL'>('ALL');
  const [searchTerm, setSearchTerm] = useState('');
  const [frozenEvents, setFrozenEvents] = useState<KernelEvent[]>([]);

  // When paused, freeze the events view
  const displayEvents = isPaused ? frozenEvents : events;

  const handleTogglePause = () => {
    if (!isPaused) {
      setFrozenEvents([...events]);
    }
    setIsPaused((prev) => !prev);
  };

  const filteredEvents = useMemo(() => {
    return displayEvents
      .filter((ev) => {
        const matchType = filterType === 'ALL' || ev.type_name === filterType;
        const matchSearch =
          searchTerm === '' ||
          ev.comm.toLowerCase().includes(searchTerm.toLowerCase()) ||
          ev.path.toLowerCase().includes(searchTerm.toLowerCase()) ||
          ev.pid.toString().includes(searchTerm);
        return matchType && matchSearch;
      })
      .slice(-300) // Show last 300 in UI list for smooth virtual rendering
      .reverse();
  }, [displayEvents, filterType, searchTerm]);

  const getEventTypeColor = (type: EventType) => {
    switch (type) {
      case 'EXEC':
        return '#38bdf8'; // Sky blue
      case 'CONNECT':
        return '#818cf8'; // Indigo
      case 'OPENAT':
        return '#fbbf24'; // Amber
      case 'DUP':
        return '#f472b6'; // Pink
      case 'SETUID':
        return '#f87171'; // Red
      case 'PTRACE':
        return '#c084fc'; // Purple
      case 'MOUNT':
        return '#34d399'; // Emerald
      default:
        return '#94a3b8'; // Slate
    }
  };

  return (
    <div className="glass-panel" style={{ padding: '20px' }}>
      {/* Header & Controls */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
        <div>
          <h2 style={{ fontSize: '1.1rem', fontWeight: 600, color: '#fff' }}>Kernel Event Stream</h2>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Real-time eBPF tracepoint and syscall stream (showing {filteredEvents.length} of {events.length} buffered)
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          {/* Pause / Resume Button */}
          <button
            onClick={handleTogglePause}
            className={`btn ${isPaused ? 'btn-primary' : ''}`}
            style={{ fontSize: '0.8rem', padding: '6px 12px' }}
          >
            {isPaused ? <Play size={14} /> : <Pause size={14} />}
            {isPaused ? 'Resume Stream' : 'Pause'}
          </button>

          {/* Search */}
          <div style={{ position: 'relative' }}>
            <Search size={14} style={{ position: 'absolute', left: '10px', top: '9px', color: 'var(--text-muted)' }} />
            <input
              type="text"
              placeholder="Search comm / path / PID..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              style={{
                background: 'rgba(15, 23, 42, 0.8)',
                border: '1px solid var(--border)',
                borderRadius: '6px',
                padding: '6px 12px 6px 30px',
                fontSize: '0.8rem',
                color: '#fff',
                outline: 'none',
              }}
            />
          </div>

          <button onClick={onClear} className="btn" title="Clear Event Stream" style={{ color: 'var(--text-muted)' }}>
            <Trash2 size={14} />
          </button>
        </div>
      </div>

      {/* Filter Chips */}
      <div style={{ display: 'flex', gap: '6px', marginBottom: '12px', overflowX: 'auto', paddingBottom: '4px' }}>
        {(['ALL', 'EXEC', 'OPENAT', 'CONNECT', 'DUP', 'SETUID', 'PTRACE', 'MOUNT', 'EXIT'] as const).map((t) => (
          <button
            key={t}
            onClick={() => setFilterType(t as EventType | 'ALL')}
            style={{
              background: filterType === t ? 'rgba(56, 189, 248, 0.2)' : 'rgba(15, 23, 42, 0.6)',
              border: `1px solid ${filterType === t ? 'var(--accent-cyan)' : 'var(--border)'}`,
              color: filterType === t ? '#fff' : 'var(--text-muted)',
              borderRadius: '4px',
              padding: '3px 8px',
              fontSize: '0.7rem',
              cursor: 'pointer',
              fontWeight: 500,
            }}
          >
            {t}
          </button>
        ))}
      </div>

      {/* Events Table */}
      <div
        style={{
          border: '1px solid var(--border)',
          borderRadius: '8px',
          overflow: 'hidden',
          background: 'rgba(11, 16, 27, 0.7)',
        }}
      >
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: '110px 90px 90px 140px 1fr 140px',
            padding: '8px 12px',
            background: 'rgba(15, 23, 42, 0.9)',
            borderBottom: '1px solid var(--border)',
            fontSize: '0.75rem',
            color: 'var(--text-muted)',
            fontWeight: 600,
            textTransform: 'uppercase',
          }}
        >
          <span>Type</span>
          <span>PID</span>
          <span>PPID</span>
          <span>Comm</span>
          <span>Path / Target</span>
          <span>Destination</span>
        </div>

        <div style={{ maxHeight: '480px', overflowY: 'auto' }}>
          {filteredEvents.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '30px', color: 'var(--text-muted)', fontSize: '0.8rem' }}>
              Waiting for kernel events...
            </div>
          ) : (
            filteredEvents.map((ev, idx) => (
              <div
                key={`${ev.timestamp_ns}-${idx}`}
                style={{
                  display: 'grid',
                  gridTemplateColumns: '110px 90px 90px 140px 1fr 140px',
                  padding: '7px 12px',
                  borderBottom: '1px solid rgba(56, 189, 248, 0.05)',
                  fontSize: '0.75rem',
                  fontFamily: 'JetBrains Mono, monospace',
                  alignItems: 'center',
                }}
              >
                <div>
                  <span
                    style={{
                      padding: '2px 6px',
                      borderRadius: '4px',
                      fontSize: '0.65rem',
                      fontWeight: 700,
                      background: 'rgba(255,255,255,0.06)',
                      color: getEventTypeColor(ev.type_name),
                      border: `1px solid ${getEventTypeColor(ev.type_name)}40`,
                    }}
                  >
                    {ev.type_name}
                  </span>
                </div>
                <span style={{ color: '#fff' }}>{ev.pid}</span>
                <span style={{ color: 'var(--text-faint)' }}>{ev.ppid}</span>
                <span style={{ color: '#38bdf8', fontWeight: 500 }}>{ev.comm}</span>
                <span style={{ color: 'var(--text-main)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  {ev.path || ev.extra || '-'}
                </span>
                <span style={{ color: ev.daddr ? 'var(--accent-cyan)' : 'var(--text-faint)' }}>
                  {ev.daddr ? `${ev.daddr}:${ev.dport}` : '-'}
                </span>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};
