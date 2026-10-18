'use client';

import React from 'react';
import { SecurityAlert, SystemMetrics } from '../types';
import { Activity, Cpu, ShieldAlert, CheckCircle2, AlertOctagon } from 'lucide-react';

interface MetricsOverviewProps {
  metrics: SystemMetrics;
  alerts: SecurityAlert[];
}

export const MetricsOverview: React.FC<MetricsOverviewProps> = ({ metrics, alerts }) => {
  const criticalCount = alerts.filter((a) => a.severity === 'CRITICAL').length;
  const highCount = alerts.filter((a) => a.severity === 'HIGH').length;
  const medCount = alerts.filter((a) => a.severity === 'MEDIUM').length;

  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
        gap: '16px',
        marginBottom: '24px',
      }}
    >
      {/* Events Per Second */}
      <div className="glass-panel" style={{ padding: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
          <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', fontWeight: 500, textTransform: 'uppercase' }}>
            Event Throughput
          </span>
          <div style={{ padding: '6px', borderRadius: '6px', background: 'rgba(6, 182, 212, 0.1)' }}>
            <Activity size={18} color="var(--accent-cyan)" />
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'baseline', gap: '8px' }}>
          <span style={{ fontSize: '1.8rem', fontWeight: 700, color: '#fff' }}>
            {metrics.events_per_sec.toLocaleString()}
          </span>
          <span style={{ fontSize: '0.8rem', color: 'var(--accent-cyan)', fontWeight: 600 }}>events/sec</span>
        </div>
        <p style={{ fontSize: '0.75rem', color: 'var(--text-faint)', marginTop: '6px' }}>
          Total Intercepted: {metrics.total_events.toLocaleString()}
        </p>
      </div>

      {/* Active Monitored Processes */}
      <div className="glass-panel" style={{ padding: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
          <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', fontWeight: 500, textTransform: 'uppercase' }}>
            Tracked Processes
          </span>
          <div style={{ padding: '6px', borderRadius: '6px', background: 'rgba(59, 130, 246, 0.1)' }}>
            <Cpu size={18} color="var(--accent-blue)" />
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'baseline', gap: '8px' }}>
          <span style={{ fontSize: '1.8rem', fontWeight: 700, color: '#fff' }}>
            {metrics.active_processes.toLocaleString()}
          </span>
          <span style={{ fontSize: '0.8rem', color: 'var(--accent-blue)', fontWeight: 600 }}>in cache</span>
        </div>
        <p style={{ fontSize: '0.75rem', color: 'var(--text-faint)', marginTop: '6px' }}>
          Lineage trees maintained with PID 0 root
        </p>
      </div>

      {/* Security Alerts */}
      <div className="glass-panel" style={{ padding: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
          <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', fontWeight: 500, textTransform: 'uppercase' }}>
            Security Incidents
          </span>
          <div style={{ padding: '6px', borderRadius: '6px', background: 'rgba(239, 68, 68, 0.1)' }}>
            <ShieldAlert size={18} color="var(--accent-red)" />
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'baseline', gap: '8px' }}>
          <span style={{ fontSize: '1.8rem', fontWeight: 700, color: alerts.length > 0 ? '#f87171' : '#fff' }}>
            {alerts.length}
          </span>
          <span style={{ fontSize: '0.8rem', color: 'var(--accent-red)', fontWeight: 600 }}>active alerts</span>
        </div>
        <div style={{ display: 'flex', gap: '8px', marginTop: '6px', fontSize: '0.75rem' }}>
          <span style={{ color: '#f87171' }}>{criticalCount} Critical</span>
          <span style={{ color: 'var(--text-faint)' }}>•</span>
          <span style={{ color: '#fbbf24' }}>{highCount} High</span>
          <span style={{ color: 'var(--text-faint)' }}>•</span>
          <span style={{ color: '#facc15' }}>{medCount} Medium</span>
        </div>
      </div>

      {/* Kernel Drops */}
      <div className="glass-panel" style={{ padding: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
          <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', fontWeight: 500, textTransform: 'uppercase' }}>
            Ring Buffer Health
          </span>
          <div
            style={{
              padding: '6px',
              borderRadius: '6px',
              background: metrics.kernel_drops === 0 ? 'rgba(16, 185, 129, 0.1)' : 'rgba(245, 158, 11, 0.1)',
            }}
          >
            {metrics.kernel_drops === 0 ? (
              <CheckCircle2 size={18} color="var(--accent-emerald)" />
            ) : (
              <AlertOctagon size={18} color="var(--accent-amber)" />
            )}
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'baseline', gap: '8px' }}>
          <span
            style={{
              fontSize: '1.8rem',
              fontWeight: 700,
              color: metrics.kernel_drops === 0 ? 'var(--accent-emerald)' : '#fbbf24',
            }}
          >
            {metrics.kernel_drops}
          </span>
          <span
            style={{
              fontSize: '0.8rem',
              color: metrics.kernel_drops === 0 ? 'var(--accent-emerald)' : '#fbbf24',
              fontWeight: 600,
            }}
          >
            {metrics.kernel_drops === 0 ? '0.00% loss' : 'drops detected'}
          </span>
        </div>
        <p style={{ fontSize: '0.75rem', color: 'var(--text-faint)', marginTop: '6px' }}>
          16 MB ring buffer capacity
        </p>
      </div>
    </div>
  );
};
