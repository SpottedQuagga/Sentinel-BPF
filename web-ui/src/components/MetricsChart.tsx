'use client';

import React, { useEffect, useState, useMemo } from 'react';
import { SystemMetrics, KernelEvent, EventType } from '../types';
import { TrendingUp, PieChart } from 'lucide-react';

interface MetricsChartProps {
  metrics: SystemMetrics;
  events: KernelEvent[];
}

export const MetricsChart: React.FC<MetricsChartProps> = ({ metrics, events }) => {
  const [history, setHistory] = useState<number[]>(() => new Array(30).fill(0));

  // Push latest EPS into 30-sample sliding window
  useEffect(() => {
    setHistory((prev) => [...prev.slice(1), metrics.events_per_sec]);
  }, [metrics.events_per_sec]);

  // Event type distribution from recent events
  const distribution = useMemo(() => {
    const counts: Record<string, number> = {};
    events.slice(-500).forEach((ev) => {
      counts[ev.type_name] = (counts[ev.type_name] || 0) + 1;
    });
    return counts;
  }, [events]);

  const maxEPS = Math.max(...history, 100);

  // SVG dimensions for sparkline chart
  const width = 450;
  const height = 140;
  const padding = 15;

  const points = history
    .map((val, idx) => {
      const x = padding + (idx / (history.length - 1)) * (width - 2 * padding);
      const y = height - padding - (val / maxEPS) * (height - 2 * padding);
      return `${x},${y}`;
    })
    .join(' ');

  const areaPoints = `${padding},${height - padding} ${points} ${width - padding},${height - padding}`;

  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
        gap: '16px',
        marginBottom: '24px',
      }}
    >
      {/* Real-time Throughput Chart */}
      <div className="glass-panel" style={{ padding: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
          <div>
            <h3 style={{ fontSize: '0.9rem', fontWeight: 600, color: '#fff', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <TrendingUp size={16} color="var(--accent-cyan)" />
              Throughput Dynamics (30s)
            </h3>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Real-time ring buffer drain rate (Events / second)
            </p>
          </div>
          <span style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--accent-cyan)' }}>
            {metrics.events_per_sec} <span style={{ fontSize: '0.7rem' }}>EPS</span>
          </span>
        </div>

        <div style={{ width: '100%', height: `${height}px`, position: 'relative' }}>
          <svg viewBox={`0 0 ${width} ${height}`} style={{ width: '100%', height: '100%', overflow: 'visible' }}>
            <defs>
              <linearGradient id="epsGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#06b6d4" stopOpacity="0.4" />
                <stop offset="100%" stopColor="#06b6d4" stopOpacity="0.0" />
              </linearGradient>
            </defs>

            {/* Grid lines */}
            <line x1={padding} y1={padding} x2={width - padding} y2={padding} stroke="rgba(255,255,255,0.05)" strokeDasharray="3" />
            <line x1={padding} y1={height / 2} x2={width - padding} y2={height / 2} stroke="rgba(255,255,255,0.05)" strokeDasharray="3" />
            <line x1={padding} y1={height - padding} x2={width - padding} y2={height - padding} stroke="rgba(255,255,255,0.1)" />

            {/* Shaded Area */}
            <polygon points={areaPoints} fill="url(#epsGrad)" />

            {/* Line */}
            <polyline fill="none" stroke="#38bdf8" strokeWidth="2.5" points={points} strokeLinecap="round" strokeLinejoin="round" />
          </svg>
        </div>
      </div>

      {/* Event Type Telemetry Breakdown */}
      <div className="glass-panel" style={{ padding: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
          <div>
            <h3 style={{ fontSize: '0.9rem', fontWeight: 600, color: '#fff', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <PieChart size={16} color="var(--accent-blue)" />
              Kernel Hook Distribution
            </h3>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Syscall and tracepoint event distribution
            </p>
          </div>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Recent 500
          </span>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '10px' }}>
          {(['EXEC', 'OPENAT', 'CONNECT', 'DUP', 'SETUID', 'PTRACE', 'FORK', 'EXIT', 'MOUNT'] as EventType[]).map((t) => {
            const count = distribution[t] || 0;
            const total = Math.max(events.length, 1);
            const pct = Math.min(Math.round((count / total) * 100), 100);

            return (
              <div key={t} style={{ display: 'flex', alignItems: 'center', gap: '10px', fontSize: '0.75rem' }}>
                <span className="mono" style={{ width: '65px', color: 'var(--text-muted)' }}>
                  {t}
                </span>
                <div style={{ flex: 1, height: '6px', background: 'rgba(255,255,255,0.08)', borderRadius: '3px', overflow: 'hidden' }}>
                  <div
                    style={{
                      width: `${pct}%`,
                      height: '100%',
                      background: 'linear-gradient(90deg, #38bdf8 0%, #3b82f6 100%)',
                      borderRadius: '3px',
                      transition: 'width 0.3s ease',
                    }}
                  />
                </div>
                <span className="mono" style={{ width: '40px', textAlign: 'right', color: '#fff' }}>
                  {count}
                </span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
