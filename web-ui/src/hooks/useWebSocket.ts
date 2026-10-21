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
  const connectionSeqRef = useRef<number>(0);

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
        // Dedupe events within the batch by composite key. Duplicate WebSocket
        // connections deliver the same server-side event with identical kernel
        // timestamps, so this safely preserves legitimate repeated events which
        // always have distinct timestamps.
        const seenEvents = new Set<string>();
        const dedupedBatch = batch.filter((e) => {
          const key = `${e.timestamp_ns}:${e.pid}:${e.event_type}`;
          if (seenEvents.has(key)) return false;
          seenEvents.add(key);
          return true;
        });
        setEvents((prev) => {
          const combined = [...prev, ...dedupedBatch];
          if (combined.length > MAX_EVENT_HISTORY) {
            return combined.slice(combined.length - MAX_EVENT_HISTORY);
          }
          return combined;
        });
      }

      // 2. Flush Alerts — dedupe by unique id to prevent duplicates from
      // snapshot+live overlap or reconnection scenarios.
      if (alertBufferRef.current.length > 0) {
        const batch = alertBufferRef.current;
        alertBufferRef.current = [];
        setAlerts((prev) => {
          const existingIds = new Set(prev.map((a) => a.id));
          const newAlerts = batch.filter((a) => {
            if (existingIds.has(a.id)) return false;
            existingIds.add(a.id); // also dedupe within batch
            return true;
          });
          if (newAlerts.length === 0) return prev;
          const combined = [...newAlerts, ...prev];
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

    // Prevent duplicate connections (e.g., React Strict Mode double-invoking effects)
    if (wsRef.current && wsRef.current.readyState <= WebSocket.OPEN) return;

    const mySeq = ++connectionSeqRef.current;

    const wsUrl = process.env.NEXT_PUBLIC_WS_URL || 'ws://127.0.0.1:8080/ws';
    const token = process.env.NEXT_PUBLIC_SENTINEL_TOKEN;
    let url = wsUrl;
    if (token) {
      const separator = url.includes('?') ? '&' : '?';
      url = `${url}${separator}token=${token}`;
    }
    setStatus('CONNECTING');

    try {
      const socket = new WebSocket(url);
      wsRef.current = socket;

      socket.onopen = () => {
        if (isUnmountedRef.current) return;
        if (mySeq !== connectionSeqRef.current) return; // stale connection
        setStatus('CONNECTED');
        backoffRef.current = 1000; // Reset backoff on success
      };

      socket.onmessage = (event) => {
        if (mySeq !== connectionSeqRef.current) return; // stale connection
        try {
          const msg: WSMessage = JSON.parse(event.data);
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
        if (wsRef.current !== socket) return;
        if (mySeq !== connectionSeqRef.current) return; // stale connection
        if (!isUnmountedRef.current) {
          setStatus('ERROR');
        }
      };

      socket.onclose = () => {
        if (isUnmountedRef.current) return;
        // Only act on close if this socket is still the active one.
        // Prevents stale WS1.onclose from clearing wsRef after WS2 opens.
        if (wsRef.current !== socket) return;
        if (mySeq !== connectionSeqRef.current) return; // stale connection
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
        wsRef.current = null;
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
    clearAlerts,
    clearEvents,
  };
}
