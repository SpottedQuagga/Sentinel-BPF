import { buildProcessTree, computeFitTransform, computeTreeBounds, treeDepth } from './processTreeBuilder';

// 16 processes: full multi-level lineage
//   systemd(1) -> sshd(100) -> bash(200) -> python3(300) -> worker(400..409)
//                                 -> nc(500)
//                                 -> suspicious_app(600)
const processes = [
  { pid: 1, ppid: 0, comm: 'systemd', path: '/usr/lib/systemd/systemd' },
  { pid: 100, ppid: 1, comm: 'sshd', path: '/usr/sbin/sshd' },
  { pid: 200, ppid: 100, comm: 'bash', path: '/bin/bash' },
  { pid: 300, ppid: 200, comm: 'python3', path: '/usr/bin/python3' },
  { pid: 400, ppid: 300, comm: 'curl', path: '/usr/bin/curl' },
  { pid: 401, ppid: 300, comm: 'grep', path: '/usr/bin/grep' },
  { pid: 402, ppid: 300, comm: 'awk', path: '/usr/bin/awk' },
  { pid: 403, ppid: 300, comm: 'cat', path: '/bin/cat' },
  { pid: 404, ppid: 300, comm: 'curl', path: '/usr/bin/curl' },
  { pid: 405, ppid: 300, comm: 'grep', path: '/usr/bin/grep' },
  { pid: 406, ppid: 300, comm: 'awk', path: '/usr/bin/awk' },
  { pid: 407, ppid: 300, comm: 'cat', path: '/bin/cat' },
  { pid: 408, ppid: 300, comm: 'curl', path: '/usr/bin/curl' },
  { pid: 409, ppid: 300, comm: 'grep', path: '/usr/bin/grep' },
  { pid: 500, ppid: 200, comm: 'nc', path: '/bin/nc' },
  { pid: 600, ppid: 200, comm: 'suspicious_app', path: '/tmp/suspicious_app' },
];

const alerts = [
  { id: 'a1', timestamp: '2026-01-01T00:00:00Z', rule_name: 'reverse_shell', severity: 'CRITICAL' as const, mitre_technique: 'T1059.004', pid: 500, ppid: 200, comm: 'nc', path: '/bin/nc', message: 'test', details: {} },
  { id: 'a2', timestamp: '2026-01-01T00:00:00Z', rule_name: 'file_tampering', severity: 'HIGH' as const, mitre_technique: 'T1565.001', pid: 600, ppid: 200, comm: 'suspicious_app', path: '/tmp/suspicious_app', message: 'test', details: {} },
];

const root = buildProcessTree(processes, alerts);
const depth = treeDepth(root);
const pids = new Set([0, ...(root.children || []).map((c) => c.pid)]);

// Collect all descendant PIDs
function collectPids(node: any, out: number[] = []): number[] {
  for (const c of node.children || []) {
    out.push(c.pid);
    collectPids(c, out);
  }
  return out;
}
const allPids = collectPids(root);

let failures = 0;

function assert(cond: boolean, msg: string) {
  if (!cond) {
    console.error(`FAIL: ${msg}`);
    failures++;
  } else {
    console.log(`PASS: ${msg}`);
  }
}

// 1. All 16 processes present (excluding virtual root pid 0)
const expectedPids = new Set(processes.map((p) => p.pid));
const foundPids = new Set(allPids);
expectedPids.forEach((pid) => {
  assert(foundPids.has(pid), `PID ${pid} present in tree`);
});

// 2. Virtual root is PID 0
assert(root.pid === 0, 'Virtual root has PID 0');

// 3. systemd attaches to virtual root
const systemd = findNode(root, 1);
assert(systemd && systemd.ppid === 0, 'systemd(1) attaches to virtual root (ppid=0)');

// 4. Full chain: systemd -> sshd -> bash -> python3 -> worker (depth >= 5)
assert(depth >= 5, `Tree depth >= 5 (got ${depth})`);

// 5. Lineage integrity
const sshd = findNode(root, 100);
assert(sshd && sshd.ppid === 1, 'sshd(100) ppid=1 (child of systemd)');
const bash = findNode(root, 200);
assert(bash && bash.ppid === 100, 'bash(200) ppid=100 (child of sshd)');
const python3 = findNode(root, 300);
assert(python3 && python3.ppid === 200, 'python3(300) ppid=200 (child of bash)');
const worker400 = findNode(root, 400);
assert(worker400 && worker400.ppid === 300, 'worker(400) ppid=300 (child of python3)');

// 6. nc and suspicious_app attach to bash(200), not to root
const nc = findNode(root, 500);
assert(nc && nc.ppid === 200, 'nc(500) ppid=200 (child of bash, not orphaned to root)');
const susp = findNode(root, 600);
assert(susp && susp.ppid === 200, 'suspicious_app(600) ppid=200 (child of bash, not orphaned to root)');

// 7. Alerts flag the correct nodes
assert(nc && nc.hasAlert === true, 'nc(500) hasAlert=true (reverse shell alert)');
assert(susp && susp.hasAlert === true, 'suspicious_app(600) hasAlert=true (file tampering alert)');

// 8. No process is orphaned to root unless its parent is truly absent
const rootChildren = (root.children || []).map((c) => c.pid);
assert(!rootChildren.includes(100), 'sshd not orphaned to root (has parent systemd)');
assert(!rootChildren.includes(200), 'bash not orphaned to root (has parent sshd)');
assert(!rootChildren.includes(300), 'python3 not orphaned to root (has parent bash)');

// --- Exited process handling ---
const exitedProcesses = [
  ...processes,
  { pid: 9000, ppid: 200, comm: 'exited_proc', path: '/bin/exited' },
];
const rootExited = buildProcessTree(exitedProcesses, []);
const exitedNode = findNode(rootExited, 9000);
assert(exitedNode !== null, 'buildProcessTree includes all input nodes (exited not filtered here)');

// Component-level: filter exited before building — exited_proc should not appear
const nonExited = exitedProcesses.filter((p) => p.pid !== 9000);
const rootClean = buildProcessTree(nonExited, []);
const exitedNodeClean = findNode(rootClean, 9000);
assert(exitedNodeClean === null, 'Exited process 9000 absent when filtered before build');
assert(findNode(rootClean, 200) !== null, 'bash(200) still present after filtering');

// --- computeFitTransform unit tests ---
function assertFinite(val: number, label: string) {
  assert(Number.isFinite(val), `${label} is finite (got ${val})`);
}

// 1. Zero-size bbox (all zeros) → identity transform
const t1 = computeFitTransform({ minX: 0, minY: 0, maxX: 0, maxY: 0 }, 900, 520, 40);
assert(t1.k === 1, 'zero-size bbox → scale=1');
assert(t1.x === 0 && t1.y === 0, 'zero-size bbox → identity translate');

// 2. Normal bbox → finite transform, scale clamped to [0.2, 4]
const t2 = computeFitTransform({ minX: 100, minY: 100, maxX: 500, maxY: 400 }, 900, 520, 40);
assertFinite(t2.k, 'normal bbox scale');
assertFinite(t2.x, 'normal bbox tx');
assertFinite(t2.y, 'normal bbox ty');
assert(t2.k >= 0.2 && t2.k <= 4, 'normal bbox scale within [0.2, 4]');

// 3. Very wide tree → scale clamped by width, not height
const t3 = computeFitTransform({ minX: 0, minY: 0, maxX: 5000, maxY: 100 }, 900, 520, 40);
assert(t3.k < 1, 'wide tree → scale < 1 (width-limited)');
assertFinite(t3.k, 'wide tree scale finite');
assertFinite(t3.x, 'wide tree tx finite');
assertFinite(t3.y, 'wide tree ty finite');

// 4. Zero container size → identity transform
const t4 = computeFitTransform({ minX: 0, minY: 0, maxX: 100, maxY: 100 }, 0, 520, 40);
assert(t4.k === 1 && t4.x === 0 && t4.y === 0, 'zero-width container → identity');
const t5 = computeFitTransform({ minX: 0, minY: 0, maxX: 100, maxY: 100 }, 900, 0, 40);
assert(t5.k === 1 && t5.x === 0 && t5.y === 0, 'zero-height container → identity');

// 5. Non-finite bbox values → identity transform
const t6 = computeFitTransform({ minX: NaN, minY: 0, maxX: 100, maxY: 100 }, 900, 520, 40);
assert(t6.k === 1 && t6.x === 0 && t6.y === 0, 'NaN bbox → identity');
const t7 = computeFitTransform({ minX: 0, minY: 0, maxX: Infinity, maxY: 100 }, 900, 520, 40);
assert(t7.k === 1 && t7.x === 0 && t7.y === 0, 'Infinity bbox → identity');

// --- computeTreeBounds unit tests ---

// Mock hierarchy node that mimics d3.HierarchyPointNode
function mockNode(x: number, y: number, children: any[] = []): any {
  return {
    x, y, children,
    descendants() {
      const out: any[] = [this];
      for (const c of children) out.push(...c.descendants());
      return out;
    },
    links() {
      const out: any[] = [];
      for (const c of children) {
        out.push({ source: this, target: c });
        out.push(...c.links());
      }
      return out;
    }
  };
}

// 1. Empty hierarchy (root only) → finite bounds with label padding and node radius
const h1 = mockNode(0, 0, []);
const b1 = computeTreeBounds(h1);
assertFinite(b1.minX, 'empty hierarchy minX finite');
assertFinite(b1.minY, 'empty hierarchy minY finite');
assertFinite(b1.maxX, 'empty hierarchy maxX finite');
assertFinite(b1.maxY, 'empty hierarchy maxY finite');
assert(b1.maxX > b1.minX, 'empty hierarchy has positive width (label padding)');
assert(b1.maxY > b1.minY, 'empty hierarchy has positive height (node radius)');

// 2. Simple hierarchy → finite bounds covering parent and child
//    Root at x=0 (vertical=0), y=0 (horizontal=0); child at x=60 (depth), y=200 (sibling)
const child2 = mockNode(60, 200, []);
const h2 = mockNode(0, 0, [child2]);
const b2 = computeTreeBounds(h2);
assertFinite(b2.minX, 'simple hierarchy minX finite');
assertFinite(b2.minY, 'simple hierarchy minY finite');
assertFinite(b2.maxX, 'simple hierarchy maxX finite');
assertFinite(b2.maxY, 'simple hierarchy maxY finite');
assert(b2.maxX > b2.minX, 'simple hierarchy has positive width');
assert(b2.maxY > b2.minY, 'simple hierarchy has positive height');

// 3. Deep hierarchy → vertical extent >= depth * nodeSizeY
//    Chain of depth 5: root(0) -> d1(60) -> d2(120) -> d3(180) -> d4(240)
const d4 = mockNode(240, 0, []);
const d3 = mockNode(180, 0, [d4]);
const d2 = mockNode(120, 0, [d3]);
const d1 = mockNode(60, 0, [d2]);
const rootDeep = mockNode(0, 0, [d1]);
const bDeep = computeTreeBounds(rootDeep);
assertFinite(bDeep.minX, 'deep hierarchy minX finite');
assertFinite(bDeep.minY, 'deep hierarchy minY finite');
assertFinite(bDeep.maxX, 'deep hierarchy maxX finite');
assertFinite(bDeep.maxY, 'deep hierarchy maxY finite');
assert(bDeep.maxY - bDeep.minY >= 4 * 60, 'deep hierarchy vertical extent >= 4 * 60 (got ' + (bDeep.maxY - bDeep.minY) + ')');

// 4. Real 16-process tree bounds via buildProcessTree + manual layout coords
const root16 = buildProcessTree(processes, alerts);
// Manually compute layout-like coordinates: depth * 60 for x, sibling index * 200 for y
function assignCoords(node: any, depth: number = 0, siblingIdx: number = 0): void {
  node.y = siblingIdx * 200; // horizontal
  node.x = depth * 60;       // vertical
  let idx = 0;
  for (const c of (node.children || [])) {
    assignCoords(c, depth + 1, idx);
    idx++;
  }
}
assignCoords(root16);
// Add descendants/links methods so root16 satisfies HierarchyPointNode shape
const root16h = {
  ...root16,
  descendants() {
    const out: any[] = [this];
    const walk = (n: any) => {
      for (const c of (n.children || [])) {
        out.push(c);
        walk(c);
      }
    };
    walk(this);
    return out;
  },
  links() {
    const out: any[] = [];
    const walk = (n: any) => {
      for (const c of (n.children || [])) {
        out.push({ source: n, target: c });
        walk(c);
      }
    };
    walk(this);
    return out;
  }
};
const b16 = computeTreeBounds(root16h as any);
assertFinite(b16.minX, '16-process tree minX finite');
assertFinite(b16.minY, '16-process tree minY finite');
assertFinite(b16.maxX, '16-process tree maxX finite');
assertFinite(b16.maxY, '16-process tree maxY finite');
assert(b16.maxY - b16.minY >= 0, '16-process tree has non-negative vertical extent (got ' + (b16.maxY - b16.minY) + ')');

console.log(`\nDepth: ${depth}, Total PIDs in tree: ${allPids.length}`);
if (failures === 0) {
  console.log('\nAll assertions passed.');
  process.exit(0);
} else {
  console.log(`\n${failures} assertion(s) failed.`);
  process.exit(1);
}

function findNode(node: any, pid: number): any | null {
  if (node.pid === pid) return node;
  for (const c of node.children || []) {
    const found = findNode(c, pid);
    if (found) return found;
  }
  return null;
}
