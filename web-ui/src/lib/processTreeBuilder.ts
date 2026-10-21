import * as d3 from 'd3';
import { ProcessNode, SecurityAlert } from '../types';

/**
 * Build a process hierarchy tree from a list of flat process nodes.
 *
 * A virtual root (PID 0) is always created. Every process with a parent that
 * exists in the node map is attached to that parent; processes whose parent is
 * absent (or PID 0) attach to the virtual root. This guarantees that seed
 * processes (systemd, sshd, bash, ...) always appear in the tree even when
 * they are missing from the live WebSocket event stream.
 *
 * @param processes - Flat list of process nodes (pid, ppid, comm, path, ...)
 * @param alerts    - Alerts used to flag hasAlert on matching PIDs
 * @returns Virtual root node with the full hierarchy attached
 */
export function buildProcessTree(
  processes: ProcessNode[],
  alerts: SecurityAlert[],
): ProcessNode {
  const nodeMap = new Map<number, ProcessNode>();

  const alertPIDs = new Set(alerts.map((a) => a.pid));

  // Virtual root (PID 0) required by AGENTS.md
  const root: ProcessNode = {
    pid: 0,
    ppid: -1,
    comm: 'system_root (pid 0)',
    children: [],
  };
  nodeMap.set(0, root);

  // 1. Insert all processes (REST data first, then events can overwrite)
  processes.forEach((p) => {
    if (!nodeMap.has(p.pid)) {
      nodeMap.set(p.pid, {
        pid: p.pid,
        ppid: p.ppid,
        comm: p.comm || `pid-${p.pid}`,
        path: p.path,
        container_id: p.container_id,
        hasAlert: alertPIDs.has(p.pid),
        children: [],
      });
    }
  });

  // 2. Link each node to its parent (or fall back to virtual root)
  nodeMap.forEach((node) => {
    if (node.pid === 0) return;

    const parentPID = node.ppid;
    if (parentPID !== node.pid && nodeMap.has(parentPID)) {
      const parent = nodeMap.get(parentPID)!;
      if (!parent.children) parent.children = [];
      if (!parent.children.some((c) => c.pid === node.pid)) {
        parent.children.push(node);
      }
    } else {
      // Parent absent from map: attach to virtual root so nothing is lost
      root.children!.push(node);
    }
  });

  return root;
}

/**
 * Compute the maximum depth of a process tree rooted at the given node.
 * Virtual root (PID 0) counts as depth 0.
 */
export function treeDepth(node: ProcessNode): number {
  if (!node.children || node.children.length === 0) return 0;
  let maxChild = 0;
  for (let i = 0; i < node.children.length; i++) {
    const d = treeDepth(node.children[i]);
    if (d > maxChild) maxChild = d;
  }
  return 1 + maxChild;
}

/**
 * Flatten a process tree into a list of all descendant PIDs (excluding root).
 */
export function allPids(node: ProcessNode): number[] {
  const out: number[] = [];
  const children = node.children || [];
  for (let i = 0; i < children.length; i++) {
    const c = children[i];
    out.push(c.pid);
    out.push(...allPids(c));
  }
  return out;
}

/**
 * Pure function: compute the bounding box of a d3 tree layout in SVG
 * coordinate space, using only the layout coordinates (node.x, node.y).
 *
 * With d3.tree().nodeSize([dx, dy]) and linkHorizontal().x(d => d.y).y(d => d.x):
 *   - node.y maps to the horizontal (x) screen axis — siblings spread horizontally
 *   - node.x maps to the vertical (y) screen axis — depth spreads vertically
 *
 * Padding accounts for node radius and label width (labels are left- or
 * right-aligned depending on whether the node has children).
 *
 * @param root - d3 hierarchy root node after treeLayout
 * @param nodeRadius - radius of node circles (px)
 * @param labelPadding - extra horizontal space for labels (px)
 * @returns { minX, minY, maxX, maxY } in SVG coordinate space
 */
export function computeTreeBounds(
  root: d3.HierarchyPointNode<ProcessNode>,
  nodeRadius: number = 7,
  labelPadding: number = 100,
): { minX: number; minY: number; maxX: number; maxY: number } {
  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;

  for (const node of root.descendants()) {
    const x = node.y; // horizontal axis (siblings)
    const y = node.x; // vertical axis (depth)
    const isParent = node.children && node.children.length > 0;

    // Horizontal extent: labels extend right for leaves, left for parents
    const left = isParent ? x - labelPadding : x;
    const right = isParent ? x : x + labelPadding;

    minX = Math.min(minX, left);
    maxX = Math.max(maxX, right);

    // Vertical extent: node radius above and below
    minY = Math.min(minY, y - nodeRadius);
    maxY = Math.max(maxY, y + nodeRadius);
  }

  // Guard: empty tree (only root)
  if (!Number.isFinite(minX) || !Number.isFinite(minY)) {
    return { minX: 0, minY: 0, maxX: 0, maxY: 0 };
  }

  return { minX, minY, maxX, maxY };
}

/**
 * Pure function: given a tree bounding box and container size, compute a
 * zoom transform that centers the tree with padding, clamped to scaleExtent.
 *
 * @param bbox - { minX, minY, maxX, maxY } in SVG coordinate space
 * @param containerWidth - visible width of the SVG container
 * @param containerHeight - visible height of the SVG container
 * @param padding - padding around the tree (px)
 * @returns { k, x, y } zoom transform, or identity if inputs are invalid
 */
export function computeFitTransform(
  bbox: { minX: number; minY: number; maxX: number; maxY: number },
  containerWidth: number,
  containerHeight: number,
  padding: number,
): { k: number; x: number; y: number } {
  const { minX, minY, maxX, maxY } = bbox;

  // Guard: empty or degenerate tree
  if (!Number.isFinite(minX) || !Number.isFinite(minY) ||
      !Number.isFinite(maxX) || !Number.isFinite(maxY)) {
    return { k: 1, x: 0, y: 0 };
  }

  const treeWidth = maxX - minX;
  const treeHeight = maxY - minY;

  // Guard: zero-size bbox (single point or nothing)
  if (treeWidth <= 0 && treeHeight <= 0) {
    return { k: 1, x: 0, y: 0 };
  }

  // Guard: invalid container size
  if (!Number.isFinite(containerWidth) || !Number.isFinite(containerHeight) ||
      containerWidth <= 0 || containerHeight <= 0) {
    return { k: 1, x: 0, y: 0 };
  }

  const scaleX = (containerWidth - 2 * padding) / Math.max(treeWidth, 1);
  const scaleY = (containerHeight - 2 * padding) / Math.max(treeHeight, 1);
  let scale = Math.min(scaleX, scaleY, 4);

  // Clamp to scaleExtent and guard against non-finite
  if (!Number.isFinite(scale) || scale < 0.2) scale = 0.2;
  if (scale > 4) scale = 4;

  const centerX = (minX + maxX) / 2;
  const centerY = (minY + maxY) / 2;
  const tx = containerWidth / 2 - centerX * scale;
  const ty = containerHeight / 2 - centerY * scale;

  if (!Number.isFinite(tx) || !Number.isFinite(ty)) {
    return { k: 1, x: 0, y: 0 };
  }

  return { k: scale, x: tx, y: ty };
}
