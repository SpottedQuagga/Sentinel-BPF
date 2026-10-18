'use client';

import React, { useState, useMemo } from 'react';
import { SecurityAlert, Severity } from '../types';
import { ShieldAlert, AlertTriangle, ChevronDown, ChevronRight, Search, Trash2 } from 'lucide-react';

interface AlertFeedProps {
  alerts: SecurityAlert[];
  onClear: () => void;
}

export const AlertFeed: React.FC<AlertFeedProps> = ({ alerts, onClear }) => {
  const [filterSeverity, setFilterSeverity] = useState<Severity | 'ALL'>('ALL');
  const [searchTerm, setSearchTerm] = useState('');
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const filteredAlerts = useMemo(() => {
    return alerts.filter((alt) => {
      const matchSeverity = filterSeverity === 'ALL' || alt.severity === filterSeverity;
      const matchSearch =
        searchTerm === '' ||
        alt.rule_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        alt.comm.toLowerCase().includes(searchTerm.toLowerCase()) ||
        alt.message.toLowerCase().includes(searchTerm.toLowerCase()) ||
        alt.pid.toString().includes(searchTerm);
      return matchSeverity && matchSearch;
    });
  }, [alerts, filterSeverity, searchTerm]);

  const toggleExpand = (id: string) => {
    setExpandedId((prev) => (prev === id ? null : id));
  };

  const getSeverityBadgeClass = (sev: Severity) => {
    switch (sev) {
      case 'CRITICAL':
        return 'badge badge-critical';
      case 'HIGH':
        return 'badge badge-high';
      case 'MEDIUM':
        return 'badge badge-medium';
      case 'LOW':
        return 'badge badge-low';
      default:
        return 'badge badge-info';
    }
  };

  return (
    <div className="glass-panel" style={{ padding: '20px' }}>
      {/* Header & Controls */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
        <div>
          <h2 style={{ fontSize: '1.1rem', fontWeight: 600, color: '#fff', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <ShieldAlert size={18} color="var(--accent-red)" />
            Real-Time Security Alert Feed
          </h2>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Stateful intrusion alerts evaluated against eBPF kernel events
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          {/* Search */}
          <div style={{ position: 'relative' }}>
            <Search size={14} style={{ position: 'absolute', left: '10px', top: '9px', color: 'var(--text-muted)' }} />
            <input
              type="text"
              placeholder="Search rule, PID, comm..."
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

          {alerts.length > 0 && (
            <button onClick={onClear} className="btn" title="Clear All Alerts" style={{ color: 'var(--text-muted)' }}>
              <Trash2 size={14} />
            </button>
          )}
        </div>
      </div>

      {/* Severity Filter Tabs */}
      <div style={{ display: 'flex', gap: '8px', marginBottom: '16px', overflowX: 'auto', paddingBottom: '4px' }}>
        {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map((sev) => {
          const count = sev === 'ALL' ? alerts.length : alerts.filter((a) => a.severity === sev).length;
          return (
            <button
              key={sev}
              onClick={() => setFilterSeverity(sev)}
              style={{
                background: filterSeverity === sev ? 'rgba(56, 189, 248, 0.2)' : 'rgba(15, 23, 42, 0.6)',
                border: `1px solid ${filterSeverity === sev ? 'var(--accent-cyan)' : 'var(--border)'}`,
                color: filterSeverity === sev ? '#fff' : 'var(--text-muted)',
                borderRadius: '6px',
                padding: '4px 10px',
                fontSize: '0.75rem',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                fontWeight: 500,
              }}
            >
              <span>{sev}</span>
              <span style={{ fontSize: '0.65rem', background: 'rgba(255,255,255,0.1)', padding: '1px 5px', borderRadius: '4px' }}>
                {count}
              </span>
            </button>
          );
        })}
      </div>

      {/* Alert List */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', maxHeight: '560px', overflowY: 'auto' }}>
        {filteredAlerts.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '40px 0', color: 'var(--text-muted)', fontSize: '0.85rem' }}>
            <AlertTriangle size={32} style={{ margin: '0 auto 8px', opacity: 0.4 }} />
            <p>No alerts matching current filters.</p>
          </div>
        ) : (
          filteredAlerts.map((alt) => {
            const isExpanded = expandedId === alt.id;
            return (
              <div
                key={alt.id}
                style={{
                  background: 'rgba(15, 23, 42, 0.7)',
                  border: `1px solid ${alt.severity === 'CRITICAL' ? 'rgba(239, 68, 68, 0.35)' : 'var(--border)'}`,
                  borderRadius: '8px',
                  padding: '12px 16px',
                  transition: 'background 0.2s',
                  boxShadow: alt.severity === 'CRITICAL' ? '0 0 14px rgba(239,68,68,0.1)' : 'none',
                }}
              >
                {/* Header row */}
                <div
                  onClick={() => toggleExpand(alt.id)}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    cursor: 'pointer',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    {isExpanded ? <ChevronDown size={16} color="var(--text-muted)" /> : <ChevronRight size={16} color="var(--text-muted)" />}
                    <span className={getSeverityBadgeClass(alt.severity)}>{alt.severity}</span>
                    <span style={{ fontWeight: 600, fontSize: '0.85rem', color: '#fff' }}>{alt.rule_name}</span>
                    {alt.mitre_technique && (
                      <span
                        style={{
                          fontSize: '0.7rem',
                          padding: '2px 6px',
                          background: 'rgba(139, 92, 246, 0.15)',
                          color: '#c084fc',
                          borderRadius: '4px',
                          border: '1px solid rgba(139, 92, 246, 0.3)',
                          fontFamily: 'JetBrains Mono, monospace',
                        }}
                      >
                        MITRE {alt.mitre_technique}
                      </span>
                    )}
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                    <span>
                      PID: <strong style={{ color: '#fff' }}>{alt.pid}</strong> ({alt.comm})
                    </span>
                    <span className="mono">{new Date(alt.timestamp).toLocaleTimeString()}</span>
                  </div>
                </div>

                {/* Summary message */}
                <div style={{ marginTop: '8px', fontSize: '0.8rem', color: 'var(--text-main)', paddingLeft: '26px' }}>
                  {alt.message}
                </div>

                {/* Expanded Details Drawer */}
                {isExpanded && (
                  <div
                    style={{
                      marginTop: '12px',
                      padding: '12px',
                      borderRadius: '6px',
                      background: 'rgba(7, 10, 18, 0.85)',
                      border: '1px solid var(--border)',
                      fontSize: '0.75rem',
                      fontFamily: 'JetBrains Mono, monospace',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '6px',
                    }}
                  >
                    <div>
                      <span style={{ color: 'var(--text-muted)' }}>Alert ID:</span> <span style={{ color: '#fff' }}>{alt.id}</span>
                    </div>
                    <div>
                      <span style={{ color: 'var(--text-muted)' }}>Path:</span> <span style={{ color: '#fff' }}>{alt.path || 'N/A'}</span>
                    </div>
                    <div>
                      <span style={{ color: 'var(--text-muted)' }}>Parent PID:</span> <span style={{ color: '#fff' }}>{alt.ppid}</span>
                    </div>
                    {alt.container_id && (
                      <div>
                        <span style={{ color: 'var(--text-muted)' }}>Container:</span>{' '}
                        <span style={{ color: 'var(--accent-cyan)' }}>{alt.container_id}</span>
                      </div>
                    )}
                    {alt.details && (
                      <div style={{ marginTop: '4px' }}>
                        <span style={{ color: 'var(--text-muted)' }}>Context Details:</span>
                        <pre
                          style={{
                            background: 'rgba(15, 23, 42, 0.6)',
                            padding: '8px',
                            borderRadius: '4px',
                            marginTop: '4px',
                            overflowX: 'auto',
                            color: 'var(--accent-cyan)',
                          }}
                        >
                          {JSON.stringify(alt.details, null, 2)}
                        </pre>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
