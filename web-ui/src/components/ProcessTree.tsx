'use client';

import React, { useEffect, useRef, useState, useMemo } from 'react';
import * as d3 from 'd3';
import { KernelEvent, SecurityAlert, ProcessNode } from '../types';
import { RotateCcw, Search } from 'lucide-react';

interface ProcessTreeProps {
  events: KernelEvent[];
  alerts: SecurityAlert[];
}

interface D3HierarchyNode extends d3.HierarchyPointNode<ProcessNode> {
  x0?: number;
  y0?: number;
}

export const ProcessTree: React.FC<ProcessTreeProps> = ({ events, alerts }) => {
  const svgRef = useRef<SVGSVGElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [selectedNode, setSelectedNode] = useState<ProcessNode | null>(null);
  const [searchTerm, setSearchTerm] = useState('');

  // Set of PIDs that generated an alert
  const alertPIDs = useMemo(() => {
    return new Set(alerts.map((a) => a.pid));
  }, [alerts]);

  // Construct hierarchy from events with Virtual Root PID 0
  const treeData = useMemo<ProcessNode>(() => {
    const nodeMap = new Map<number, ProcessNode>();

    // 1. Virtual Root (PID 0) required by AGENTS.md
    const root: ProcessNode = {
      pid: 0,
      ppid: -1,
      comm: 'system_root (pid 0)',
      children: [],
    };
    nodeMap.set(0, root);

    // 2. Populate from recent events
    events.forEach((ev) => {
      if (!nodeMap.has(ev.pid)) {
        nodeMap.set(ev.pid, {
          pid: ev.pid,
          ppid: ev.ppid,
          comm: ev.comm || `pid-${ev.pid}`,
          path: ev.path,
          container_id: ev.container_id,
          hasAlert: alertPIDs.has(ev.pid),
          children: [],
        });
      }
    });

    // 3. Link child nodes to parent or fallback to root (0)
    nodeMap.forEach((node) => {
      if (node.pid === 0) return;

      const parentPID = node.ppid;
      if (nodeMap.has(parentPID) && parentPID !== node.pid) {
        const parent = nodeMap.get(parentPID)!;
        if (!parent.children) parent.children = [];
        if (!parent.children.some((c) => c.pid === node.pid)) {
          parent.children.push(node);
        }
      } else {
        // Orphan process attaches to virtual root PID 0
        root.children!.push(node);
      }
    });

    return root;
  }, [events, alertPIDs]);

  useEffect(() => {
    if (!svgRef.current || !containerRef.current) return;

    const width = containerRef.current.clientWidth || 900;
    const height = 550;

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    const g = svg.append('g').attr('class', 'tree-container');

    // Zoom behavior
    const zoom = d3
      .zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.3, 3])
      .on('zoom', (event) => {
        g.attr('transform', event.transform);
      });

    svg.call(zoom);

    // D3 Tree Layout
    const treeLayout = d3.tree<ProcessNode>().nodeSize([60, 200]);
    const hierarchy = d3.hierarchy<ProcessNode>(treeData);
    const root = treeLayout(hierarchy) as D3HierarchyNode;

    // Links (Curves)
    g.selectAll('.link')
      .data(root.links())
      .enter()
      .append('path')
      .attr('class', 'link')
      .attr(
        'd',
        d3
          .linkHorizontal<d3.HierarchyPointLink<ProcessNode>, d3.HierarchyPointNode<ProcessNode>>()
          .x((d) => d.y)
          .y((d) => d.x)
      )
      .attr('fill', 'none')
      .attr('stroke', 'rgba(56, 189, 248, 0.25)')
      .attr('stroke-width', 1.5);

    // Node Groups
    const node = g
      .selectAll('.node')
      .data(root.descendants())
      .enter()
      .append('g')
      .attr('class', 'node')
      .attr('transform', (d) => `translate(${d.y},${d.x})`)
      .style('cursor', 'pointer')
      .on('click', (_, d) => {
        setSelectedNode(d.data);
      });

    // Node Circles
    node
      .append('circle')
      .attr('r', (d) => (d.data.pid === 0 ? 9 : 7))
      .attr('fill', (d) => {
        if (d.data.hasAlert) return '#ef4444'; // Red for alert node
        if (d.data.pid === 0) return '#3b82f6';
        if (d.data.container_id) return '#06b6d4'; // Cyan for container
        return '#64748b';
      })
      .attr('stroke', (d) => (d.data.hasAlert ? '#f87171' : '#38bdf8'))
      .attr('stroke-width', (d) => (d.data.hasAlert ? 3 : 1.5))
      .style('filter', (d) => (d.data.hasAlert ? 'drop-shadow(0 0 8px rgba(239,68,68,0.8))' : 'none'));

    // Node Text Labels
    node
      .append('text')
      .attr('dy', '0.31em')
      .attr('x', (d) => (d.children ? -12 : 12))
      .attr('text-anchor', (d) => (d.children ? 'end' : 'start'))
      .text((d) => `${d.data.comm} [${d.data.pid}]`)
      .attr('fill', (d) => (d.data.hasAlert ? '#f87171' : '#f1f5f9'))
      .attr('font-size', '11px')
      .attr('font-family', 'JetBrains Mono, monospace')
      .attr('font-weight', (d) => (d.data.hasAlert ? '700' : '500'));

    // Initial centering
    svg.call(
      zoom.transform,
      d3.zoomIdentity.translate(80, height / 2).scale(0.85)
    );
  }, [treeData]);

  const handleResetZoom = () => {
    if (!svgRef.current) return;
    const svg = d3.select(svgRef.current);
    const zoom = d3.zoom<SVGSVGElement, unknown>().scaleExtent([0.3, 3]);
    svg.transition().duration(500).call(
      zoom.transform,
      d3.zoomIdentity.translate(80, 275).scale(0.85)
    );
  };

  return (
    <div className="glass-panel" style={{ padding: '20px', position: 'relative' }} ref={containerRef}>
      {/* Header & Controls */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
        <div>
          <h2 style={{ fontSize: '1.1rem', fontWeight: 600, color: '#fff' }}>Process Ancestry & Lineage Tree</h2>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Hierarchical process relationships rooted at Virtual PID 0. Red nodes denote active intrusion alerts.
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

          <button onClick={handleResetZoom} className="btn" title="Reset View">
            <RotateCcw size={14} />
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
