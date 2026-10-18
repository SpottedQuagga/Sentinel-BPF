'use client';

import React, { useState } from 'react';
import { useWebSocket } from '../hooks/useWebSocket';
import { Header } from '../components/Header';
import { MetricsOverview } from '../components/MetricsOverview';
import { MetricsChart } from '../components/MetricsChart';
import { ProcessTree } from '../components/ProcessTree';
import { AlertFeed } from '../components/AlertFeed';
import { LiveEventStream } from '../components/LiveEventStream';

export default function DashboardPage() {
  const { status, events, alerts, metrics, isMock, clearAlerts, clearEvents } = useWebSocket();
  const [activeTab, setActiveTab] = useState<'overview' | 'tree' | 'alerts' | 'events'>('overview');

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      {/* Top Navigation & Status Header */}
      <Header
        status={status}
        metrics={metrics}
        alertCount={alerts.length}
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        isMock={isMock}
      />

      {/* Main Content Area */}
      <main style={{ flex: 1, padding: '24px 28px', maxWidth: '1600px', width: '100%', margin: '0 auto' }}>
        {activeTab === 'overview' && (
          <>
            <MetricsOverview metrics={metrics} alerts={alerts} />
            <MetricsChart metrics={metrics} events={events} />

            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(480px, 1fr))',
                gap: '20px',
              }}
            >
              <AlertFeed alerts={alerts} onClear={clearAlerts} />
              <LiveEventStream events={events} onClear={clearEvents} />
            </div>
          </>
        )}

        {activeTab === 'tree' && (
          <div>
            <ProcessTree events={events} alerts={alerts} />
          </div>
        )}

        {activeTab === 'alerts' && (
          <div>
            <AlertFeed alerts={alerts} onClear={clearAlerts} />
          </div>
        )}

        {activeTab === 'events' && (
          <div>
            <LiveEventStream events={events} onClear={clearEvents} />
          </div>
        )}
      </main>

      {/* Footer */}
      <footer
        style={{
          borderTop: '1px solid var(--border)',
          padding: '16px 28px',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          fontSize: '0.75rem',
          color: 'var(--text-faint)',
          background: 'rgba(7, 9, 14, 0.95)',
        }}
      >
        <div>
          <span>SentinelBPF v1.0.0</span> • <span>Detection Only (Passive Observer)</span> • <span>eBPF CO-RE</span>
        </div>
        <div>
          <span>Ring Buffer: 16 MB</span> • <span>Max History: 5,000 events</span>
        </div>
      </footer>
    </div>
  );
}
