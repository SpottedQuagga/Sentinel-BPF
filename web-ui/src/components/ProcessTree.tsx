'use client';

import React, { useEffect, useRef, useState, useMemo, useCallback } from 'react';
import * as d3 from 'd3';
import { KernelEvent, SecurityAlert, ProcessNode } from '../types';
import { RotateCcw, Search } from 'lucide-react';
import { buildProcessTree, computeFitTransform, computeTreeBounds, treeDepth } from '../lib/processTreeBuilder';

interface ProcessTreeProps {
  events: KernelEvent[];
  alerts: SecurityAlert[];
}

interface D3HierarchyNode extends d3.HierarchyPointNode<ProcessNode> {
  x0?: number;
  y0?: number;
}

const FIT_PADDING = 40;
const DEFAULT_SCALE = 0.85;
const SCALE_MIN = 0.2;
const SCALE_MAX = 4;

export const ProcessTree: React.FC<ProcessTreeProps> = ({ events, alerts }) => {
  const svgRef = useRef<SVGSVGElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const wrapperRef = useRef<SVGGElement | null>(null);
  const zoomBehaviorRef = useRef<d3.ZoomBehavior<SVGSVGElement, unknown> | null>(null);
  const resizeObserverRef = useRef<ResizeObserver | null>(null);
  const [selectedNode, setSelectedNode] = useState<ProcessNode | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [isFitDone, setIsFitDone] = useState(false);

  // Tracks whether the user has manually zoomed/panned. When true, live
  // updates must not reset the view.
  const hasUserZoomedRef = useRef(false);

  // Tracks whether the wrapper has been initialized (created once, never destroyed)
  const wrapperInitializedRef = useRef(false);

  // Processes fetched from REST /api/v1/processes (complete process list incl. seed processes)
  const [restProcesses, setRestProcesses] = useState<ProcessNode[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  // Set of PIDs that generated an alert
  const alertPIDs = useMemo(() => {
    return new Set(alerts.map((a) => a.pid));
  }, [alerts]);

  // Fetch the complete process list from the REST API so seed processes
  // (systemd, sshd, bash, ...) are always present even if they were sent as
  // WebSocket events before the frontend connected.
  useEffect(() => {
    let cancelled = false;
    const fetchProcesses = async () => {
      try {
        const wsUrl = process.env.NEXT_PUBLIC_WS_URL || 'ws://127.0.0.1:8080/ws';
        const apiBase = wsUrl.replace(/^ws:/, 'http:').replace(/\/ws$/, '');
        const token = process.env.NEXT_PUBLIC_SENTINEL_TOKEN;
        const headers: Record<string, string> = {};
        if (token) {
          headers['Authorization'] = `Bearer ${token}`;
        }
        const res = await fetch(`${apiBase}/api/v1/processes`, { headers });
        if (!res.ok) return;
        const data = await res.json();
        const procs = data.processes || [];
        if (cancelled) return;
        setRestProcesses(
          procs
            // Skip exited processes so they don't accumulate as stale tree nodes
            .filter((p: any) => !p.exited)
            .map((p: any) => ({
              pid: p.pid,
              ppid: p.ppid,
              comm: p.comm || `pid-${p.pid}`,
              path: p.path,
              container_id: p.container_id,
              hasAlert: alertPIDs.has(p.pid),
              children: [],
            })),
        );
      } catch {
        // API unavailable (e.g. daemon not running) — tree falls back to events only
      } finally {
        if (!cancelled) setIsLoading(false);
      }
    };
    fetchProcesses();
    return () => {
      cancelled = true;
    };
  }, [alertPIDs]);

  // Build hierarchy: REST processes (complete list) + WebSocket events (new processes)
  const allProcesses = useMemo<ProcessNode[]>(() => {
    const merged = new Map<number, ProcessNode>();
    // REST data first (authoritative)
    for (const p of restProcesses) merged.set(p.pid, p);
    // Events add any processes not yet known
    for (const ev of events) {
      if (!merged.has(ev.pid)) {
        merged.set(ev.pid, {
          pid: ev.pid,
          ppid: ev.ppid,
          comm: ev.comm || `pid-${ev.pid}`,
          path: ev.path,
          container_id: ev.container_id,
          hasAlert: alertPIDs.has(ev.pid),
          children: [],
        });
      }
    }
    return Array.from(merged.values());
  }, [events, restProcesses, alertPIDs]);

  const treeData = useMemo<ProcessNode>(() => {
    return buildProcessTree(allProcesses, alerts);
  }, [allProcesses, alerts]);

  // Compute max depth for diagnostics
  const maxDepth = useMemo(() => treeDepth(treeData), [treeData]);

  // Zoom behavior — stable ref so live updates don't reset zoom/pan
  const zoom = useMemo(() => {
    const z = d3
      .zoom<SVGSVGElement, unknown>()
      .scaleExtent([SCALE_MIN, SCALE_MAX])
      .on('zoom', (event) => {
        if (wrapperRef.current) {
          wrapperRef.current.setAttribute('transform', event.transform.toString());
          hasUserZoomedRef.current = true;
        }
      });
    zoomBehaviorRef.current = z;
    return z;
  }, []);

  const handleZoomIn = useCallback(() => {
    if (!svgRef.current || !wrapperRef.current || !zoomBehaviorRef.current) return;
    const svg = d3.select(svgRef.current);
    const t = d3.zoomTransform(wrapperRef.current);
    const newScale = Math.min(t.k * 1.3, SCALE_MAX);
    svg.transition().duration(300).call(
      zoomBehaviorRef.current.transform,
      d3.zoomIdentity.translate(t.x, t.y).scale(newScale)
    );
    hasUserZoomedRef.current = true;
  }, []);

  const handleZoomOut = useCallback(() => {
    if (!svgRef.current || !wrapperRef.current || !zoomBehaviorRef.current) return;
    const svg = d3.select(svgRef.current);
    const t = d3.zoomTransform(wrapperRef.current);
    const newScale = Math.max(t.k / 1.3, SCALE_MIN);
    svg.transition().duration(300).call(
      zoomBehaviorRef.current.transform,
      d3.zoomIdentity.translate(t.x, t.y).scale(newScale)
    );
    hasUserZoomedRef.current = true;
  }, []);

  const handleFitToView = useCallback(() => {
    if (DEBUG) console.log('[ProcessTree] handleFitToView called');

    if (!svgRef.current || !wrapperRef.current || !containerRef.current) {
      if (DEBUG) console.log('[ProcessTree] handleFitToView: missing refs', { svg: !!svgRef.current, wrapper: !!wrapperRef.current, container: !!containerRef.current });
      return;
    }
    const svg = d3.select(svgRef.current);
    const container = containerRef.current;
    const width = container.clientWidth;
    const height = container.clientHeight;

    // Guard: container must have nonzero size
    if (!width || !height) {
      if (DEBUG) console.log('[ProcessTree] handleFitToView: zero container size', { width, height });
      return;
    }

    if (DEBUG) console.log('[ProcessTree] handleFitToView: container size', { width, height });

    // Compute bounding box from d3 layout coordinates (NOT DOM measurement).
    // We need the current layout root. Re-derive from treeData.
    const treeLayout = d3.tree<ProcessNode>().nodeSize([60, 200]);
    const hierarchy = d3.hierarchy<ProcessNode>(treeData);
    const root = treeLayout(hierarchy) as D3HierarchyNode;

    const bounds = computeTreeBounds(root);
    if (DEBUG) console.log('[ProcessTree] handleFitToView: layout bounds', bounds);

    const transform = computeFitTransform(bounds, width, height, FIT_PADDING);
    if (DEBUG) console.log('[ProcessTree] handleFitToView: computed transform', transform);

    // Guard against non-finite transform
    if (!Number.isFinite(transform.k) || !Number.isFinite(transform.x) || !Number.isFinite(transform.y)) {
      if (DEBUG) console.log('[ProcessTree] handleFitToView: non-finite transform, using identity');
      svg.transition().duration(600).call(zoomBehaviorRef.current!.transform, d3.zoomIdentity);
      return;
    }

    svg.transition().duration(600).call(
      zoomBehaviorRef.current!.transform,
      d3.zoomIdentity.translate(transform.x, transform.y).scale(transform.k)
    );

    const actualTransform = d3.zoomTransform(wrapperRef.current);
    if (DEBUG) console.log('[ProcessTree] handleFitToView: actual wrapper transform after fit', actualTransform);

    hasUserZoomedRef.current = false;
  }, [treeData]);

  // Main drawing effect: creates SVG structure once, updates tree content on data changes.
  // The wrapper <g> is created exactly once and never destroyed — zoom transform persists.
  useEffect(() => {
    if (DEBUG) console.log('[ProcessTree] drawing effect: treeData changed, maxDepth=', maxDepth);

    if (!svgRef.current || !containerRef.current) {
      if (DEBUG) console.log('[ProcessTree] drawing effect: missing refs', { svg: !!svgRef.current, container: !!containerRef.current });
      return;
    }

    const svg = d3.select(svgRef.current);
    const width = containerRef.current.clientWidth || 900;
    const height = containerRef.current.clientHeight || 520;

    if (DEBUG) console.log('[ProcessTree] drawing effect: container size', { width, height });

    // Create the wrapper group exactly once. Never destroy it — zoom transform must persist.
    const existingWrapper = svg.select('.tree-wrapper');
    let wrapper: d3.Selection<SVGGElement, unknown, null, undefined>;
    if (existingWrapper.empty()) {
      if (DEBUG) console.log('[ProcessTree] drawing effect: creating new wrapper');
      wrapper = svg.append('g').attr('class', 'tree-wrapper');
    } else {
      if (DEBUG) console.log('[ProcessTree] drawing effect: reusing existing wrapper');
      wrapper = existingWrapper as unknown as d3.Selection<SVGGElement, unknown, null, undefined>;
    }
    wrapperRef.current = wrapper.node();
    wrapperInitializedRef.current = true;

    // Clear only the content inside the wrapper, not the wrapper itself.
    wrapper.selectAll('*').remove();

    // D3 Tree Layout
    const treeLayout = d3.tree<ProcessNode>().nodeSize([60, 200]);
    const hierarchy = d3.hierarchy<ProcessNode>(treeData);
    const root = treeLayout(hierarchy) as D3HierarchyNode;

    const nodeCount = root.descendants().length;
    const linkCount = root.links().length;
    if (DEBUG) console.log('[ProcessTree] drawing effect: layout nodes=', nodeCount, 'links=', linkCount);
    if (DEBUG) console.log('[ProcessTree] drawing effect: root coords x=', root.x, 'y=', root.y);

    // Compute layout bounds for fit
    const bounds = computeTreeBounds(root);
    if (DEBUG) console.log('[ProcessTree] drawing effect: computed bounds', bounds);

    // Links (Curves) — enter new
    wrapper.selectAll('.link')
      .data(root.links())
      .enter()
      .append('path')
      .attr('class', 'link')
      .attr('fill', 'none')
      .attr('stroke', 'rgba(56, 189, 248, 0.25)')
      .attr('stroke-width', 1.5);

    // Update all links' geometry
    wrapper.selectAll('.link')
      .data(root.links())
      .attr(
        'd',
        d3
          .linkHorizontal<d3.HierarchyPointLink<ProcessNode>, d3.HierarchyPointNode<ProcessNode>>()
          .x((d) => d.y)
          .y((d) => d.x)
      );

    // Remove old links
    wrapper.selectAll('.link')
      .data(root.links())
      .exit()
      .remove();

    // Node Groups — enter new
    const nodeEnter = wrapper.selectAll('.node')
      .data(root.descendants())
      .enter()
      .append('g')
      .attr('class', 'node')
      .style('cursor', 'pointer')
      .on('click', (_, d) => {
        setSelectedNode(d.data);
      });

    // Update all nodes' transforms
    wrapper.selectAll('.node')
      .data(root.descendants())
      .attr('transform', (d) => `translate(${d.y},${d.x})`);

    // Remove old nodes
    wrapper.selectAll('.node')
      .data(root.descendants())
      .exit()
      .remove();

    // Re-select all nodes (enter + existing) for child element updates
    const node = wrapper.selectAll('.node').data(root.descendants());

    // Node Circles — enter new
    nodeEnter.selectAll('circle')
      .data(d => [d])
      .enter()
      .append('circle')
      .attr('r', (d) => (d.data.pid === 0 ? 9 : 7))
      .attr('fill', (d) => {
        if (d.data.hasAlert) return '#ef4444';
        if (d.data.pid === 0) return '#3b82f6';
        if (d.data.container_id) return '#06b6d4';
        return '#64748b';
      })
      .attr('stroke', (d) => (d.data.hasAlert ? '#f87171' : '#38bdf8'))
      .attr('stroke-width', (d) => (d.data.hasAlert ? 3 : 1.5))
      .style('filter', (d) => (d.data.hasAlert ? 'drop-shadow(0 0 8px rgba(239,68,68,0.8))' : 'none'));

    // Update all circles
    node.selectAll('circle')
      .data(d => [d])
      .attr('r', (d) => (d.data.pid === 0 ? 9 : 7))
      .attr('fill', (d) => {
        if (d.data.hasAlert) return '#ef4444';
        if (d.data.pid === 0) return '#3b82f6';
        if (d.data.container_id) return '#06b6d4';
        return '#64748b';
      })
      .attr('stroke', (d) => (d.data.hasAlert ? '#f87171' : '#38bdf8'))
      .attr('stroke-width', (d) => (d.data.hasAlert ? 3 : 1.5))
      .style('filter', (d) => (d.data.hasAlert ? 'drop-shadow(0 0 8px rgba(239,68,68,0.8))' : 'none'));

    // Remove old circles
    node.selectAll('circle')
      .data(d => [d])
      .exit()
      .remove();

    // Node Text Labels — enter new
    nodeEnter.selectAll('text')
      .data(d => [d])
      .enter()
      .append('text')
      .attr('dy', '0.31em')
      .attr('font-size', '11px')
      .attr('font-family', 'JetBrains Mono, monospace');

    // Update all text labels
    node.selectAll('text')
      .data(d => [d])
      .attr('x', (d) => (d.children ? -12 : 12))
      .attr('text-anchor', (d) => (d.children ? 'end' : 'start'))
      .text((d) => `${d.data.comm} [${d.data.pid}]`)
      .attr('fill', (d) => (d.data.hasAlert ? '#f87171' : '#f1f5f9'))
      .attr('font-weight', (d) => (d.data.hasAlert ? '700' : '500'));

    // Remove old text
    node.selectAll('text')
      .data(d => [d])
      .exit()
      .remove();

    svg.call(zoom);

    // Apply initial transform. On first render, use a sane default that puts
    // the root inside the viewport. Then fit to view once the DOM is ready.
    const initialTransform = d3.zoomIdentity.translate(60, height / 2).scale(DEFAULT_SCALE);
    if (!isFitDone) {
      if (DEBUG) console.log('[ProcessTree] drawing effect: applying initial transform', initialTransform);
      svg.call(zoom.transform, initialTransform);
      // Defer fit so the DOM is ready
      setTimeout(() => {
        if (DEBUG) console.log('[ProcessTree] drawing effect: deferred fit-to-view');
        handleFitToView();
        setIsFitDone(true);
      }, 0);
    } else {
      // On subsequent updates, don't reset transform if user has manually zoomed.
      if (!hasUserZoomedRef.current) {
        if (DEBUG) console.log('[ProcessTree] drawing effect: re-applying fit (user has not zoomed)');
        handleFitToView();
      } else {
        if (DEBUG) console.log('[ProcessTree] drawing effect: skipping fit (user has manually zoomed)');
      }
    }

    if (wrapperRef.current) {
      const wrapperTransform = d3.zoomTransform(wrapperRef.current);
      if (DEBUG) console.log('[ProcessTree] drawing effect: final wrapper transform', wrapperTransform);
    }
  }, [treeData, zoom, handleFitToView, isFitDone, maxDepth]);

  // ResizeObserver: re-fit when the container size changes (e.g. window resize,
  // tab switch that changes layout). Only auto-fits if the user hasn't manually
  // zoomed.
  useEffect(() => {
    if (!containerRef.current) return;
    const container = containerRef.current;

    const ro = new ResizeObserver(() => {
      if (hasUserZoomedRef.current) return;
      if (!svgRef.current || !wrapperRef.current) return;
      const width = container.clientWidth;
      const height = container.clientHeight;
      if (!width || !height) return;
      setTimeout(() => handleFitToView(), 0);
    });

    ro.observe(container);
    resizeObserverRef.current = ro;

    return () => {
      ro.disconnect();
    };
  }, [handleFitToView]);

  // Re-fit when the page/tab becomes visible (container may have had zero size
  // while hidden). Only auto-fits if the user hasn't manually zoomed.
  useEffect(() => {
    const onVisibilityChange = () => {
      if (hasUserZoomedRef.current) return;
      if (document.visibilityState === 'visible') {
        setTimeout(() => handleFitToView(), 0);
      }
    };
    document.addEventListener('visibilitychange', onVisibilityChange);
    return () => {
      document.removeEventListener('visibilitychange', onVisibilityChange);
    };
  }, [handleFitToView]);

  const handleResetZoom = useCallback(() => {
    if (!svgRef.current || !zoomBehaviorRef.current) return;
    const svg = d3.select(svgRef.current);
    svg.transition().duration(500).call(
      zoomBehaviorRef.current.transform,
      d3.zoomIdentity.translate(60, 260).scale(DEFAULT_SCALE)
    );
    // After reset, re-run fit so the view is valid.
    setTimeout(() => handleFitToView(), 550);
    hasUserZoomedRef.current = false;
  }, [handleFitToView]);

  return (
    <div className="glass-panel" style={{ padding: '20px', position: 'relative' }} ref={containerRef}>
      {/* Header & Controls */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
        <div>
          <h2 style={{ fontSize: '1.1rem', fontWeight: 600, color: '#fff' }}>Process Ancestry & Lineage Tree</h2>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Hierarchical process relationships rooted at Virtual PID 0. Red nodes denote active intrusion alerts. Max depth: {maxDepth}.
          </p>
        </div>

        {/* Toolbar */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <div style={{ position: 'relative' }}>
            <Search size={14} style={{ position: 'absolute', left: '10px', top: '9px', color: 'var(--text-muted)' }} />
            <input
              type="text"
              placeholder="Search PID / comm..."
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

          <button
            onClick={handleZoomOut}
            className="btn"
            title="Zoom out"
            style={{ padding: '4px 8px', fontSize: '0.75rem' }}
          >
            −
          </button>
          <button
            onClick={handleResetZoom}
            className="btn"
            title="Reset View"
          >
            <RotateCcw size={14} />
          </button>
          <button
            onClick={handleZoomIn}
            className="btn"
            title="Zoom in"
            style={{ padding: '4px 8px', fontSize: '0.75rem' }}
          >
            +
          </button>
          <button
            onClick={handleFitToView}
            className="btn"
            title="Fit to view"
            style={{ padding: '4px 10px', fontSize: '0.75rem', fontWeight: 600 }}
          >
            Fit
          </button>
        </div>
      </div>

      {/* SVG Canvas */}
      <div
        style={{
          width: '100%',
          height: '520px',
          background: 'radial-gradient(circle, rgba(15,23,42,0.6) 0%, rgba(7,9,14,0.95) 100%)',
          borderRadius: '8px',
          border: '1px solid var(--border)',
          overflow: 'hidden',
          position: 'relative',
        }}
      >
        <svg ref={svgRef} width="100%" height="100%" />

        {/* Selected Node Details Drawer */}
        {selectedNode && (
          <div
            style={{
              position: 'absolute',
              right: '16px',
              top: '16px',
              width: '280px',
              background: 'rgba(11, 16, 27, 0.95)',
              border: '1px solid var(--border-strong)',
              borderRadius: '8px',
              padding: '14px',
              boxShadow: '0 8px 24px rgba(0,0,0,0.6)',
              backdropFilter: 'blur(10px)',
              zIndex: 10,
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
              <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--accent-cyan)' }}>
                Process Inspector
              </span>
              <button
                onClick={() => setSelectedNode(null)}
                style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}
              >
                ✕
              </button>
            </div>
            <div style={{ fontSize: '0.75rem', display: 'flex', flexDirection: 'column', gap: '6px' }}>
              <div>
                <strong style={{ color: 'var(--text-muted)' }}>PID:</strong>{' '}
                <span className="mono" style={{ color: '#fff' }}>{selectedNode.pid}</span>
              </div>
              <div>
                <strong style={{ color: 'var(--text-muted)' }}>PPID:</strong>{' '}
                <span className="mono" style={{ color: '#fff' }}>{selectedNode.ppid}</span>
              </div>
              <div>
                <strong style={{ color: 'var(--text-muted)' }}>Comm:</strong>{' '}
                <span className="mono" style={{ color: '#fff' }}>{selectedNode.comm}</span>
              </div>
              {selectedNode.path && (
                <div>
                  <strong style={{ color: 'var(--text-muted)' }}>Path:</strong>{' '}
                  <span className="mono" style={{ color: '#fff', wordBreak: 'break-all' }}>{selectedNode.path}</span>
                </div>
              )}
              {selectedNode.container_id && (
                <div>
                  <strong style={{ color: 'var(--text-muted)' }}>Container:</strong>{' '}
                  <span className="mono" style={{ color: 'var(--accent-cyan)' }}>{selectedNode.container_id}</span>
                </div>
              )}
              {selectedNode.hasAlert && (
                <div
                  style={{
                    marginTop: '8px',
                    padding: '6px',
                    background: 'rgba(239, 68, 68, 0.15)',
                    border: '1px solid rgba(239, 68, 68, 0.4)',
                    borderRadius: '4px',
                    color: '#f87171',
                    fontWeight: 600,
                  }}
                >
                  Active Intrusion Alert Flagged!
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
