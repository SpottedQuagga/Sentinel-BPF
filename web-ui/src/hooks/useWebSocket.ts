'use client';

import { useEffect, useRef, useState, useCallback } from 'react';
import {
  ConnectionStatus,
  KernelEvent,
  SecurityAlert,
  SystemMetrics,
  WSMessage,
} from '../types';

const MAX_EVENT_HISTORY = 5000;
const MAX_ALERT_HISTORY = 500;
const FLUSH_INTERVAL_MS = 100; // 10 Hz batch flush to React state

export function useWebSocket() {
  const [status, setStatus] = useState<ConnectionStatus>('CONNECTING');
  const [events, setEvents] = useState<KernelEvent[]>([]);
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [isMock, setIsMock] = useState<boolean>(false);
  const [metrics, setMetrics] = useState<SystemMetrics>({
    events_per_sec: 0,
    total_events: 0,
    kernel_drops: 0,
    active_processes: 0,
    active_clients: 0,
  });

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const backoffRef = useRef<number>(1000); // 1s initial backoff
  const isUnmountedRef = useRef<boolean>(false);

  // Incoming buffers for 10Hz flush
  const eventBufferRef = useRef<KernelEvent[]>([]);
  const alertBufferRef = useRef<SecurityAlert[]>([]);
  const latestMetricsRef = useRef<SystemMetrics | null>(null);

  // Periodic flush loop running at 10 Hz to prevent React render saturation
  useEffect(() => {
    const timer = setInterval(() => {
      // 1. Flush Events
      if (eventBufferRef.current.length > 0) {
        const batch = eventBufferRef.current;
        eventBufferRef.current = [];
        setEvents((prev) => {
          const combined = [...prev, ...batch];
          if (combined.length > MAX_EVENT_HISTORY) {
            return combined.slice(combined.length - MAX_EVENT_HISTORY);
          }
          return combined;
        });
      }

      // 2. Flush Alerts
      if (alertBufferRef.current.length > 0) {
        const batch = alertBufferRef.current;
        alertBufferRef.current = [];
        setAlerts((prev) => {
          const combined = [...batch, ...prev];
          if (combined.length > MAX_ALERT_HISTORY) {
            return combined.slice(0, MAX_ALERT_HISTORY);
          }
          return combined;
        });
      }

      // 3. Flush Metrics
      if (latestMetricsRef.current !== null) {
        const m = latestMetricsRef.current;
        latestMetricsRef.current = null;
        setMetrics(m);
      }
    }, FLUSH_INTERVAL_MS);

    return () => clearInterval(timer);
  }, []);

  const connect = useCallback(() => {
    if (isUnmountedRef.current) return;

    const wsUrl = process.env.NEXT_PUBLIC_WS_URL || 'ws://127.0.0.1:8080/ws';
    setStatus('CONNECTING');

    try {
      const socket = new WebSocket(wsUrl);
      wsRef.current = socket;

      socket.onopen = () => {
        if (isUnmountedRef.current) return;
        setStatus('CONNECTED');
        backoffRef.current = 1000; // Reset backoff on success
      };

      socket.onmessage = (event) => {
        try {
          const raw = JSON.parse(event.data);
          if (raw.type === 'hello') {
            if (raw.mock) setIsMock(true);
            return;
          }
          if ((raw.type === 'snapshot' || raw.type === 'initial_state') && raw.data?.mock) {
            setIsMock(true);
          }

          const msg: WSMessage = raw;
          switch (msg.type) {
            case 'event':
              eventBufferRef.current.push(msg.data);
              break;

            case 'alert':
              alertBufferRef.current.push(msg.data);
              break;

            case 'metrics':
              latestMetricsRef.current = msg.data;
              break;

            case 'snapshot':
            case 'initial_state':
              if (msg.data.alerts && msg.data.alerts.length > 0) {
                alertBufferRef.current.push(...msg.data.alerts);
              }
              break;
          }
        } catch {
          // Ignore malformed packet
        }
      };

      socket.onerror = () => {
        if (!isUnmountedRef.current) {
          setStatus('ERROR');
        }
      };

      socket.onclose = () => {
        if (isUnmountedRef.current) return;
        setStatus('DISCONNECTED');
        wsRef.current = null;

        // Exponential backoff reconnect: 1s -> 1.5s -> 2.25s -> max 10s
        const nextDelay = Math.min(backoffRef.current * 1.5, 10000);
        backoffRef.current = nextDelay;

        reconnectTimeoutRef.current = setTimeout(() => {
          connect();
        }, nextDelay);
      };
    } catch {
      setStatus('ERROR');
      reconnectTimeoutRef.current = setTimeout(() => {
        connect();
      }, 3000);
    }
  }, []);

  useEffect(() => {
    isUnmountedRef.current = false;
    connect();

    return () => {
      isUnmountedRef.current = true;
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, [connect]);

  const clearAlerts = useCallback(() => {
    setAlerts([]);
  }, []);

  const clearEvents = useCallback(() => {
    setEvents([]);
  }, []);

  return {
    status,
    events,
    alerts,
    metrics,
    isMock,
    clearAlerts,
    clearEvents,
  };
}
