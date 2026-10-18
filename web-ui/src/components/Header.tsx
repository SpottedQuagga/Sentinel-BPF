'use client';

import React from 'react';
import { ConnectionStatus, SystemMetrics } from '../types';
import { Shield, Activity, AlertTriangle } from 'lucide-react';

interface HeaderProps {
  status: ConnectionStatus;
  metrics: SystemMetrics;
  alertCount: number;
  activeTab: 'overview' | 'tree' | 'alerts' | 'events';
  setActiveTab: (tab: 'overview' | 'tree' | 'alerts' | 'events') => void;
  isMock?: boolean;
}

export const Header: React.FC<HeaderProps> = ({
  status,
  metrics,
  alertCount,
  activeTab,
  setActiveTab,
  isMock = false,
}) => {
  const getStatusColor = () => {
    switch (status) {
      case 'CONNECTED':
        return '#10b981'; // Emerald
      case 'CONNECTING':
        return '#f59e0b'; // Amber
      default:
        return '#ef4444'; // Red
    }
  };

  return (
    <header
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '16px 28px',
        borderBottom: '1px solid var(--border)',
        background: 'rgba(11, 16, 27, 0.85)',
        backdropFilter: 'blur(20px)',
        position: 'sticky',
        top: 0,
        zIndex: 100,
      }}
    >
      {/* Brand */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
        <div
          style={{
            width: '42px',
            height: '42px',
            borderRadius: '10px',
            background: 'linear-gradient(135deg, #0284c7 0%, #0f172a 100%)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            border: '1px solid rgba(56, 189, 248, 0.4)',
            boxShadow: 'var(--glow-cyan)',
          }}
        >
          <Shield size={24} color="#38bdf8" />
        </div>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <h1 style={{ fontSize: '1.25rem', fontWeight: 700, letterSpacing: '-0.02em', color: '#fff' }}>
              Sentinel<span style={{ color: 'var(--accent-cyan)' }}>BPF</span>
            </h1>
            <span
              style={{
                fontSize: '0.7rem',
                padding: '2px 6px',
                background: 'rgba(6, 182, 212, 0.15)',
                color: '#38bdf8',
                borderRadius: '4px',
                border: '1px solid rgba(6, 182, 212, 0.3)',
                fontWeight: 600,
              }}
            >
              eBPF IDS
            </span>
            {isMock && (
              <span
                id="simulation-badge"
                style={{
                  fontSize: '0.7rem',
                  padding: '2px 8px',
                  background: 'rgba(245, 158, 11, 0.2)',
                  color: '#f59e0b',
                  borderRadius: '4px',
                  border: '1px solid rgba(245, 158, 11, 0.5)',
                  fontWeight: 700,
                  letterSpacing: '0.05em',
                  boxShadow: '0 0 10px rgba(245, 158, 11, 0.3)',
                }}
              >
                SIMULATION
              </span>
            )}
          </div>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Linux Kernel Host Intrusion Detection Engine
          </p>
        </div>
      </div>

      {/* Navigation Tabs */}
      <nav style={{ display: 'flex', gap: '6px', background: 'rgba(15, 23, 42, 0.6)', padding: '4px', borderRadius: '8px', border: '1px solid var(--border)' }}>
        <button
          onClick={() => setActiveTab('overview')}
          className={`btn ${activeTab === 'overview' ? 'btn-primary' : ''}`}
          style={{ padding: '6px 14px', fontSize: '0.8rem' }}
        >
          Overview
        </button>
        <button
          onClick={() => setActiveTab('tree')}
          className={`btn ${activeTab === 'tree' ? 'btn-primary' : ''}`}
          style={{ padding: '6px 14px', fontSize: '0.8rem' }}
        >
          Process Tree
        </button>
        <button
          onClick={() => setActiveTab('alerts')}
          className={`btn ${activeTab === 'alerts' ? 'btn-primary' : ''}`}
          style={{ padding: '6px 14px', fontSize: '0.8rem' }}
        >
          Alerts
          {alertCount > 0 && (
            <span
              style={{
                background: 'var(--accent-red)',
                color: '#fff',
                fontSize: '0.65rem',
                padding: '1px 6px',
                borderRadius: '999px',
                fontWeight: 700,
              }}
            >
              {alertCount}
            </span>
          )}
        </button>
        <button
          onClick={() => setActiveTab('events')}
          className={`btn ${activeTab === 'events' ? 'btn-primary' : ''}`}
          style={{ padding: '6px 14px', fontSize: '0.8rem' }}
        >
          Live Events
        </button>
      </nav>

      {/* Telemetry Status Indicator */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
          <Activity size={16} color="var(--accent-cyan)" />
          <span>
            <strong style={{ color: '#fff' }}>{metrics.events_per_sec}</strong> EPS
          </span>
        </div>

        {metrics.kernel_drops > 0 && (
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              fontSize: '0.75rem',
              color: '#f87171',
              background: 'rgba(239, 68, 68, 0.1)',
              padding: '4px 8px',
              borderRadius: '6px',
              border: '1px solid rgba(239, 68, 68, 0.3)',
            }}
          >
            <AlertTriangle size={14} />
            <span>Drops: {metrics.kernel_drops}</span>
          </div>
        )}

        {/* WebSocket Connection Pill */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            padding: '5px 12px',
            borderRadius: '999px',
            background: 'rgba(15, 23, 42, 0.8)',
            border: `1px solid ${getStatusColor()}`,
            fontSize: '0.75rem',
            fontWeight: 600,
          }}
        >
          <div
            className="pulse-dot"
            style={{
              backgroundColor: getStatusColor(),
            }}
          />
          <span style={{ color: getStatusColor() }}>{status}</span>
        </div>
      </div>
    </header>
  );
};
