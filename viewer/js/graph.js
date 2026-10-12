/* Project map: nested boxes (project > region > VPC > subnet) with typed edges, pan/zoom, highlight.
 * Plain SVG, no dependencies. Used by the "Project map" tab and the map view of "Waste & findings". */
(function () {
  'use strict';
  const A = (window.AWSA = window.AWSA || {});
  const h = A.h, S = A.svg;
  A.tabs = A.tabs || {};

  const NW = 178, NH = 54, GAP = 10, PAD = 12, TITLE = 26, MAXROW = 1500, MAX_NODES = 900, COLLAPSE_OVER = 12;

  const EDGE_KINDS = [
    { id: 'behind', label: 'Target group → load balancer', on: true },
    { id: 'targets', label: 'Load balancer / target group → instance', on: true },
    { id: 'serves', label: 'ECS service → target group', on: true },
    { id: 'attached-to', label: 'Volume / interface attached to instance', on: true },
    { id: 'associated-with', label: 'Elastic IP association', on: true },
    { id: 'uses-eip', label: 'NAT gateway → Elastic IP', on: false },
    { id: 'origin', label: 'CloudFront → origin', on: true },
    { id: 'dns', label: 'DNS record → target', on: true, dotted: true },
    { id: 'member-of', label: 'Cluster / replication group member', on: true },
    { id: 'in-cluster', label: 'Service / node group in cluster', on: true },
    { id: 'node-of', label: 'EC2 node of EKS cluster', on: true },
    { id: 'replica-of', label: 'Read replica', on: true },
    { id: 'snapshot-of', label: 'Snapshot of', on: false },
    { id: 'backed-by', label: 'AMI backed by snapshot', on: false },
    { id: 'logs-of', label: 'Log group of', on: false, dotted: true },
    { id: 'uses-sg', label: 'Uses security group', on: false, dotted: true },
    { id: 'consumes', label: 'Lambda reads from queue/stream', on: true },
    { id: 'delivers-to', label: 'SNS topic delivers to', on: true },
    { id: 'dead-letter-to', label: 'Failed messages go to (dead-letter)', on: true },
    { id: 'uses-role', label: 'Uses IAM role', on: false, dotted: true },
    { id: 'may-connect', label: 'Allowed by security group rule', on: false, dotted: true },
  ];
  // permission/attachment edges: never pull extra resources into the waste map as "context"
  const NO_CONTEXT = new Set(['uses-sg', 'uses-role', 'may-connect']);
  const KIND = Object.fromEntries(EDGE_KINDS.map((k) => [k.id, k]));
  const SHOW_TYPES = [
    { id: 'sg', label: 'Security groups', test: (t) => t === 'ec2:security-group' },
    { id: 'eni', label: 'Network interfaces', test: (t) => t === 'ec2:eni' },
    { id: 'iam', label: 'IAM', test: (t) => t.startsWith('iam:') },
    { id: 'logs', label: 'Log groups', test: (t) => t === 'logs:log-group' },
    { id: 'other', label: 'Other (tag-only)', test: (t) => t.startsWith('other:') },
  ];

  // ------------------------------------------------------------------------------------------ model
  function buildModel(resources, o) {
    const byKey = new Map(resources.map((r) => [r.key, r]));
    const subnetVpc = new Map();
    A.res.forEach((r) => { if (r.type === 'ec2:subnet') subnetVpc.set(`${r.account}:${r.region}:${r.rid}`, r.attrs.vpc); });

    const flagged = (r) => (r.findings || []).some((id) => { const f = A.findingById.get(id); return f && (o.findingOk ? o.findingOk(f) : (!o.cats || o.cats.has(f.category))); });
    let visible;
    let context = new Set();
    if (o.mode === 'waste') {
      const core = resources.filter(flagged);
      const coreKeys = new Set(core.map((r) => r.key));
      if (o.context) {
        core.forEach((r) => {
          (r.relations || []).forEach((rel) => { if (byKey.has(rel.to) && !coreKeys.has(rel.to) && !NO_CONTEXT.has(rel.kind)) context.add(rel.to); });
          (A.incoming.get(r.key) || []).forEach((x) => { if (byKey.has(x.from) && !coreKeys.has(x.from) && !NO_CONTEXT.has(x.kind)) context.add(x.from); });
        });
      }
      const hidden = (r) => SHOW_TYPES.some((st) => st.test(r.type) && !o.show.has(st.id));
      visible = resources.filter((r) => coreKeys.has(r.key) || (context.has(r.key) && !hidden(r)));
    } else {
      visible = resources.filter((r) => !SHOW_TYPES.some((st) => st.test(r.type) && !o.show.has(st.id)));
    }
    const vis = new Map(visible.map((r) => [r.key, r]));

    const isBox = (r) => r.type === 'ec2:vpc' || r.type === 'ec2:subnet';
    const placement = (r) => {
      const a = r.attrs || {};
      let subnet = null, vpc = null;
      const inst = (rid) => A.byKey.get(`${r.account}:${r.region}:ec2:instance:${rid}`);
      const eni = (rid) => A.byKey.get(`${r.account}:${r.region}:ec2:eni:${rid}`);
      if (a.subnet) subnet = a.subnet;
      if (r.type === 'ec2:volume' && (a.attached_to || []).length) { const i = inst(a.attached_to[0]); if (i) subnet = i.attrs.subnet; }
      if (r.type === 'ec2:eip') {
        const i = a.instance_id && inst(a.instance_id); const e = a.eni_id && eni(a.eni_id);
        subnet = (i && i.attrs.subnet) || (e && e.attrs.subnet) || null;
      }
      if (subnet) vpc = subnetVpc.get(`${r.account}:${r.region}:${subnet}`) || a.vpc || null;
      else {
        vpc = a.vpc || (r.type === 'ec2:igw' ? (a.vpcs || [])[0] : null) ||
          (a.subnet_ids && a.subnet_ids.length ? subnetVpc.get(`${r.account}:${r.region}:${a.subnet_ids[0]}`) : null);
        if (!vpc && r.type === 'eks:nodegroup') { const c = A.byKey.get(`${r.account}:${r.region}:eks:cluster:${a.cluster}`); vpc = c && c.attrs.vpc; }
      }
      return { subnet, vpc };
    };

    const regionBoxes = new Map();   // "project|region" -> region box
    const projectBoxes = new Map();
    const nodes = [];
    const nodeOf = new Map();        // resource key -> node
    const boxOf = new Map();         // resource key -> box (vpc/subnet)
    let boxSeq = 0;
    const mkBox = (kind, title, sub, depth, resKey) => ({ uid: ++boxSeq, kind, title, sub, depth, resKey, boxes: [], nodes: [], maxCols: 4 });

    const single = o.project || null;
    const getProject = (name) => {
      if (single) return null;
      if (!projectBoxes.has(name)) projectBoxes.set(name, mkBox('project', name, '', 0, null));
      return projectBoxes.get(name);
    };
    const getRegion = (r) => {
      const pk = single ? '' : (r.project || 'Unassigned');
      const k = pk + '|' + r.region;
      if (!regionBoxes.has(k)) {
        const b = mkBox('region', r.region === 'global' ? 'Global / edge' : r.region, '', single ? 0 : 1, null);
        b.proj = pk;
        regionBoxes.set(k, b);
        const p = getProject(pk);
        if (p) p.boxes.push(b);
      }
      return regionBoxes.get(k);
    };
    const sub = (parent, key, make) => { parent._m = parent._m || new Map(); if (!parent._m.has(key)) { const b = make(); parent._m.set(key, b); parent.boxes.push(b); } return parent._m.get(key); };

    // VPC / subnet resources become boxes (so empty ones still appear)
    const vpcBox = (region, vpcId, acct) => sub(region, 'vpc:' + vpcId, () => {
      const vr = A.byKey.get(`${acct}:${region._reg}:ec2:vpc:${vpcId}`);
      const b = mkBox('vpc', vr ? (vr.name || vpcId) : vpcId, vr ? vr.attrs.cidr || '' : '', region.depth + 1, vr ? vr.key : null);
      if (vr) boxOf.set(vr.key, b);
      b.maxCols = 4;
      return b;
    });
    const subnetBox = (vb, subId, acct, reg) => sub(vb, 'subnet:' + subId, () => {
      const sr = A.byKey.get(`${acct}:${reg}:ec2:subnet:${subId}`);
      const b = mkBox('subnet', sr ? (sr.name || subId) : subId,
        sr ? [sr.attrs.az && sr.attrs.az.replace(reg, ''), sr.attrs.cidr, sr.attrs.public_on_launch ? 'public' : 'private'].filter(Boolean).join(' · ') : '', vb.depth + 1, sr ? sr.key : null);
      if (sr) boxOf.set(sr.key, b);
      return b;
    });
    const groupBox = (parent, key, title) => sub(parent, key, () => { const b = mkBox('group', title, '', parent.depth + 1, null); b.maxCols = 6; return b; });

    const placed = [];
    for (const r of visible) {
      if (isBox(r)) {
        // make sure the box exists even if nothing is inside
        const reg = getRegion(r);
        reg._reg = r.region;
        if (r.type === 'ec2:vpc') vpcBox(reg, r.rid, r.account);
        else { const pl = placement(r); const vid = r.attrs.vpc || pl.vpc; if (vid) subnetBox(vpcBox(reg, vid, r.account), r.rid, r.account, r.region); }
        continue;
      }
      placed.push(r);
    }
    for (const r of placed) {
      const reg = getRegion(r);
      reg._reg = r.region;
      const pl = placement(r);
      let parent;
      if (pl.vpc) {
        const vb = vpcBox(reg, pl.vpc, r.account);
        parent = pl.subnet ? subnetBox(vb, pl.subnet, r.account, r.region) : groupBox(vb, 'vpclevel', 'VPC-level services');
      } else {
        parent = groupBox(reg, 'regional', r.region === 'global' ? 'Global services' : 'Regional services & storage');
      }
      (parent._pending = parent._pending || []).push(r);
    }

    // collapse big same-type groups into one summary node (click to expand)
    const allBoxes = [];
    (function walk(b) { allBoxes.push(b); b.boxes.forEach(walk); })({ boxes: [...projectBoxes.values(), ...(single ? [...regionBoxes.values()] : [])] });
    for (const b of allBoxes) {
      const items = b._pending || [];
      const byType = new Map();
      items.forEach((r) => { if (!byType.has(r.type)) byType.set(r.type, []); byType.get(r.type).push(r); });
      const ordered = [...byType.entries()].sort((x, y) => A.typeInfo(x[0]).group.localeCompare(A.typeInfo(y[0]).group) || x[0].localeCompare(y[0]));
      for (const [type, rs] of ordered) {
        const sid = `${b.uid}|${type}|${rs[0].region}|${rs[0].account}`;     // uid: titles repeat across projects/VPCs
        const flaggedMembers = rs.some((r) => (r.findings || []).length);
        if (rs.length > COLLAPSE_OVER && !o.expanded.has(sid) && !(o.mode === 'waste' && flaggedMembers && rs.length <= 40)) {
          const n = { id: 'sum:' + sid, summary: true, sid, type, members: rs, r: rs[0], cost: rs.reduce((s, r) => s + r.est_monthly_usd, 0) };
          nodes.push(n); b.nodes.push(n);
          rs.forEach((r) => nodeOf.set(r.key, n));
        } else {
          rs.sort((x, y) => (x.name || x.rid).localeCompare(y.name || y.rid)).forEach((r) => {
            const n = { id: r.key, r, members: [r], cost: r.est_monthly_usd, context: context.has(r.key) };
            nodes.push(n); b.nodes.push(n); nodeOf.set(r.key, n);
          });
        }
      }
    }

    // edges
    const edges = [];
    const seen = new Set();
    for (const r of visible) {
      const a = nodeOf.get(r.key);
      if (!a) continue;
      for (const rel of r.relations || []) {
        if (!o.kinds.has(rel.kind)) continue;
        const b = nodeOf.get(rel.to);
        if (!b || b === a) continue;
        const id = a.id + '>' + b.id + '>' + rel.kind;
        if (seen.has(id)) continue;
        seen.add(id);
        edges.push({ a, b, kind: rel.kind, label: rel.label });
      }
    }
    // empty subnets are noise (empty VPCs are kept: they are a finding)
    (function prune(b) {
      b.boxes.forEach(prune);
      b.boxes = b.boxes.filter((c) => c.kind !== 'subnet' || c.nodes.length || c.boxes.length ||
        (c.resKey && (A.byKey.get(c.resKey).findings || []).length));
    })({ boxes: [...regionBoxes.values()], nodes: [] });
    const cost = (b) => { let t = 0; (function w(x) { x.nodes.forEach((n) => { t += n.cost || 0; }); x.boxes.forEach(w); })(b); return t; };
    const rank = (t) => (t === 'Unassigned' ? 1 : t.startsWith('(') ? 2 : 0);
    const tops = single ? [...regionBoxes.values()]
      : [...projectBoxes.values()].sort((a, b) => rank(a.title) - rank(b.title) || cost(b) - cost(a) || a.title.localeCompare(b.title));
    return { tops, nodes, edges, nodeOf, boxOf };
  }

  // ------------------------------------------------------------------------------------------ layout
  function rowsOf(boxes, maxW) {
    const rows = [];
    let cur = null;
    for (const b of boxes) {
      if (!cur || (cur.items.length && cur.w + GAP + b.w > maxW)) { cur = { w: 0, h: 0, items: [] }; rows.push(cur); }
      cur.w += (cur.items.length ? GAP : 0) + b.w;
      cur.h = Math.max(cur.h, b.h);
      cur.items.push(b);
    }
    return rows;
  }
  function measure(b, root) {
    b.boxes.forEach((c) => measure(c));
    const order = { vpc: 0, subnet: 1, group: 2, region: 0, project: 0 };
    if (b.kind !== 'root' && b.kind !== 'project') {
      b.boxes.sort((x, y) => (order[x.kind] - order[y.kind]) || (y.nodes.length + y.boxes.length) - (x.nodes.length + x.boxes.length) || x.title.localeCompare(y.title));
    }
    const pad = root ? 0 : PAD, title = root ? 0 : TITLE;
    b._rows = rowsOf(b.boxes, MAXROW - 2 * pad);
    let iw = b._rows.reduce((m, r) => Math.max(m, r.w), 0);
    let ih = b._rows.reduce((s, r) => s + r.h, 0) + Math.max(0, b._rows.length - 1) * GAP;
    if (b.nodes.length) {
      const cols = Math.max(1, Math.min(b.maxCols || 4, b.nodes.length));
      const rows = Math.ceil(b.nodes.length / cols);
      b._grid = { cols, w: cols * NW + (cols - 1) * GAP, h: rows * NH + (rows - 1) * GAP };
      iw = Math.max(iw, b._grid.w);
      ih += (ih ? GAP : 0) + b._grid.h;
    }
    const titleW = ((b.title || '').length + (b.sub ? b.sub.length + 3 : 0)) * 7 + 2 * pad + 30;
    b.w = Math.max(iw + 2 * pad, root ? 0 : Math.min(titleW, 520), root ? 0 : 150);
    b.h = title + ih + (root ? 0 : pad) + (b.boxes.length || b.nodes.length ? 0 : 20);
  }
  function place(b, x, y, root) {
    b.x = x; b.y = y;
    const pad = root ? 0 : PAD;
    let cy = y + (root ? 0 : TITLE);
    for (const row of b._rows) {
      let cx = x + pad;
      for (const c of row.items) { place(c, cx, cy); cx += c.w + GAP; }
      cy += row.h + GAP;
    }
    if (b._grid) {
      if (b._rows.length) { /* cy already advanced by GAP after the last row */ }
      b.nodes.forEach((n, i) => { n.x = x + pad + (i % b._grid.cols) * (NW + GAP); n.y = cy + Math.floor(i / b._grid.cols) * (NH + GAP); });
    }
  }
  function layout(model) {
    const root = { boxes: model.tops, nodes: [], title: '', sub: '', kind: 'root' };
    measure(root, true);
    place(root, 0, 0, true);
    model.w = Math.max(root.w, 200);
    model.h = Math.max(root.h, 100);
  }

  function edgePath(a, b) {
    let x1, y1, x2, y2, c;
    if (b.x > a.x + NW + 4) { x1 = a.x + NW; y1 = a.y + NH / 2; x2 = b.x; y2 = b.y + NH / 2; c = Math.max(30, (x2 - x1) / 2); return `M${x1},${y1} C${x1 + c},${y1} ${x2 - c},${y2} ${x2},${y2}`; }
    if (b.x + NW + 4 < a.x) { x1 = a.x; y1 = a.y + NH / 2; x2 = b.x + NW; y2 = b.y + NH / 2; c = Math.max(30, (x1 - x2) / 2); return `M${x1},${y1} C${x1 - c},${y1} ${x2 + c},${y2} ${x2},${y2}`; }
    if (b.y >= a.y) { x1 = a.x + NW / 2; y1 = a.y + NH; x2 = b.x + NW / 2; y2 = b.y; c = Math.max(24, (y2 - y1) / 2); return `M${x1},${y1} C${x1},${y1 + c} ${x2},${y2 - c} ${x2},${y2}`; }
    x1 = a.x + NW / 2; y1 = a.y; x2 = b.x + NW / 2; y2 = b.y + NH; c = Math.max(24, (y1 - y2) / 2);
    return `M${x1},${y1} C${x1},${y1 - c} ${x2},${y2 + c} ${x2},${y2}`;
  }

  // ------------------------------------------------------------------------------------------ view
  class GraphView {
    constructor(host, opts) {
      this.host = host;
      this.o = Object.assign({ mode: 'all', project: '', show: new Set(), kinds: new Set(EDGE_KINDS.filter((k) => k.on).map((k) => k.id)), expanded: new Set(), colorBy: 'group', edgeMode: 'auto', cats: null, context: true, onSelect: null }, opts);
      this.view = { x: 20, y: 20, k: 1 };
      this.sel = null;
      this.q = '';
    }

    render(resources) {
      this.resources = resources;
      this.svg = null;                      // nothing drawn yet: helpers below check this
      const host = A.clear(this.host);
      host.classList.add('graph-host');
      const model = (this.model = buildModel(resources, this.o));
      if (model.nodes.length > MAX_NODES && !this.o.force) {
        host.appendChild(h('div', { class: 'empty-state' },
          h('p', null, `${A.fmt.num(model.nodes.length)} nodes is too many to draw readably.`),
          h('p', { class: 'muted' }, 'Filter by project, region or environment above, or draw it anyway (may be slow).'),
          h('button', { class: 'btn', type: 'button', onClick: () => { this.o.force = true; this.render(resources); } }, 'Draw anyway')));
        return;
      }
      if (!model.nodes.length && !model.tops.length) { host.appendChild(A.empty(this.o.mode === 'waste' ? 'No flagged resources for the selected categories and filters.' : 'No resources to draw for the current filters.')); return; }
      layout(model);

      const svg = (this.svg = S('svg', { class: 'graph-svg', role: 'group', 'aria-label': 'Resource map. Use Tab to move between resources, Enter to open details.', tabindex: '-1' }));
      const defs = S('defs', null,
        S('marker', { id: 'arr', viewBox: '0 0 10 10', refX: '9', refY: '5', markerWidth: '7', markerHeight: '7', orient: 'auto-start-reverse' }, S('path', { d: 'M0,1 L9,5 L0,9 z', class: 'arrow' })),
        S('marker', { id: 'arr-hl', viewBox: '0 0 10 10', refX: '9', refY: '5', markerWidth: '8', markerHeight: '8', orient: 'auto-start-reverse' }, S('path', { d: 'M0,1 L9,5 L0,9 z', class: 'arrow hl' })));
      const vp = (this.vp = S('g', { class: 'viewport' }));
      const gBoxes = S('g', { class: 'boxes' }), gEdges = S('g', { class: 'edges' }), gNodes = S('g', { class: 'nodes' });
      vp.append(gBoxes, gEdges, gNodes);
      svg.append(defs, vp);
      host.appendChild(svg);

      const drawBox = (b) => {
        const rk = b.resKey ? A.byKey.get(b.resKey) : null;
        const fs = rk ? A.findingsOf(rk) : [];
        const g = S('g', { class: `box d${Math.min(b.depth, 3)} ${b.kind}` },
          S('rect', { x: b.x, y: b.y, width: b.w, height: b.h, rx: 9 }),
          S('text', { x: b.x + PAD, y: b.y + 17, class: 'box-title' }, b.title, b.kind === 'project' ? ` · ${A.fmt.usd(this.projectCost(b))}/mo` : ''),
          b.sub ? S('text', { x: b.x + PAD + (b.title.length + 1) * 6.6 + (b.kind === 'project' ? 80 : 0), y: b.y + 17, class: 'box-sub' }, b.sub) : null,
          fs.length ? S('text', { x: b.x + b.w - PAD, y: b.y + 17, class: 'box-flag', 'text-anchor': 'end' }, `${A.SEV[A.worstSeverity(fs)].icon} ${fs.length}`) : null);
        if (rk) { g.classList.add('clickable'); g.addEventListener('click', (e) => { if (!this.dragged) { e.stopPropagation(); A.drawer.open(rk.key); } }); }
        gBoxes.appendChild(g);
        b.boxes.forEach(drawBox);
      };
      model.tops.forEach(drawBox);

      this.nodeEls = new Map();
      for (const n of model.nodes) {
        const el = this.drawNode(n);
        gNodes.appendChild(el);
        this.nodeEls.set(n.id, el);
      }
      this.edgeEls = [];
      const drawAll = this.o.edgeMode === 'all' || (this.o.edgeMode === 'auto' && model.edges.length <= 120);
      this.gEdges = gEdges;
      this.drawAll = drawAll;
      if (drawAll) model.edges.forEach((e) => this.addEdge(e));
      this.bindPanZoom();
      this.apply();
      if (!this._fitted) { requestAnimationFrame(() => { this.fitInitial(); this._fitted = true; }); }
      this.refreshHighlight();
    }

    projectCost(b) {
      let t = 0;
      (function walk(x) { x.nodes.forEach((n) => { t += n.cost || 0; }); x.boxes.forEach(walk); })(b);
      return t;
    }

    drawNode(n) {
      const r = n.r;
      const info = A.typeInfo(r.type);
      const grp = A.groupById[info.group];
      const fs = n.summary ? n.members.flatMap((m) => A.findingsOf(m)) : A.findingsOf(r);
      const worst = A.worstSeverity(fs);
      const unused = fs.some((f) => f.category === 'unused');
      const costRamp = (c) => { const i = c >= 500 ? 6 : c >= 200 ? 5 : c >= 100 ? 4 : c >= 50 ? 3 : c >= 20 ? 2 : c > 0 ? 1 : 0; return `var(--seq-${[100, 200, 300, 400, 500, 600, 700][i]})`; };
      const strip = this.o.colorBy === 'cost' ? costRamp(n.cost || 0) : grp.color;
      const name = n.summary ? `${n.members.length} × ${info.label}` : (r.name || r.rid);
      const t = (s, m) => (s.length > m ? s.slice(0, m - 1) + '…' : s);
      const tone = n.summary ? '' : A.stateTone(r);
      const sub3 = n.summary ? 'click to expand' : [n.cost > 0 ? A.fmt.usd(n.cost) + '/mo' : null, r.env || null].filter(Boolean).join(' · ') || (r.state || '');
      const g = S('g', { class: 'node' + (unused ? ' unused' : '') + (n.context ? ' ctx' : '') + (n.summary ? ' summary' : ''), transform: `translate(${n.x},${n.y})`, tabindex: '0', role: 'button',
        'aria-label': `${info.label} ${name}${r.state ? ', ' + r.state : ''}${fs.length ? ', ' + fs.length + ' findings' : ''}` });
      if (n.summary) g.appendChild(S('rect', { class: 'stack', x: 4, y: 4, width: NW, height: NH, rx: 7 }));
      g.appendChild(S('rect', { class: 'card-bg', width: NW, height: NH, rx: 7, style: unused ? { stroke: worst === 'high' ? 'var(--critical)' : 'var(--serious)' } : null }));
      g.appendChild(S('rect', { class: 'strip', x: 0, y: 0, width: 6, height: NH, rx: 3, fill: strip }));
      g.appendChild(S('text', { x: 14, y: 16, class: 'n-type' }, info.abbr.toUpperCase()));
      g.appendChild(S('text', { x: 14, y: 33, class: 'n-name' }, t(name, 23)));
      g.appendChild(S('text', { x: 14, y: 47, class: 'n-sub' }, t(sub3, 26)));
      if (tone) g.appendChild(S('circle', { cx: NW - 11, cy: 12, r: 4.5, class: 'dot ' + tone }));
      if (fs.length) {
        g.appendChild(S('g', { class: 'badge', transform: `translate(${NW - 40},${NH - 20})`, style: { '--sev': A.SEV[worst].color } },
          S('rect', { width: 34, height: 15, rx: 7.5 }), S('text', { x: 17, y: 11.2, 'text-anchor': 'middle' }, `${A.SEV[worst].icon} ${fs.length}`)));
      }
      g.appendChild(S('title', null, `${name}\n${info.label}${r.state ? ' · ' + r.state : ''}${r.project ? '\nProject: ' + r.project : ''}`));
      g.addEventListener('click', (e) => { if (this.dragged) return; e.stopPropagation(); this.activate(n); });
      g.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); this.activate(n); } });
      g.addEventListener('pointerenter', (e) => { if (!this.sel) this.hover = n.id; A.tip.show(e, this.tipFor(n)); this.refreshHighlight(); });
      g.addEventListener('pointermove', (e) => A.tip.move(e));
      g.addEventListener('pointerleave', () => { this.hover = null; A.tip.hide(); this.refreshHighlight(); });
      n.el = g;
      return g;
    }

    tipFor(n) {
      const r = n.r;
      if (n.summary) return h('div', null, h('div', { class: 'tt-value' }, `${n.members.length} × ${A.typeInfo(r.type).label}`), h('div', { class: 'tt-label' }, `${A.fmt.usd(n.cost)}/mo · click to expand`));
      const fs = A.findingsOf(r);
      return h('div', null, h('div', { class: 'tt-value' }, r.name || r.rid), h('div', { class: 'tt-label' }, `${A.typeInfo(r.type).label} · ${r.region}${r.state ? ' · ' + r.state : ''}`),
        r.project ? h('div', { class: 'tt-sub' }, `${r.project}${r.env ? ' / ' + r.env : ''}`) : null,
        r.est_monthly_usd ? h('div', { class: 'tt-sub' }, `${A.fmt.usd(r.est_monthly_usd)}/mo estimated`) : null,
        ...fs.slice(0, 3).map((f) => h('div', { class: 'tt-sub' }, `${A.SEV[f.severity].icon} ${f.title}`)));
    }

    activate(n) {
      if (n.summary) { this.o.expanded.add(n.sid); this._fitted = true; this.render(this.resources); return; }
      this.select(n.id);
      if (this.o.onSelect) this.o.onSelect(n.r.key);
    }

    select(id) {
      if (!this.svg) return;
      this.sel = id;
      if (!this.drawAll) { this.gEdges.replaceChildren(); this.edgeEls = []; if (id) this.model.edges.filter((e) => e.a.id === id || e.b.id === id).forEach((e) => this.addEdge(e)); }
      this.refreshHighlight();
    }

    addEdge(e) {
      const k = KIND[e.kind] || {};
      const p = S('path', { class: 'edge' + (k.dotted ? ' dotted' : ''), d: edgePath(e.a, e.b), 'marker-end': 'url(#arr)' });
      p.appendChild(S('title', null, `${e.a.r.name || e.a.r.rid} → ${e.b.r.name || e.b.r.rid} (${k.label || e.kind}${e.label ? ': ' + e.label : ''})`));
      this.gEdges.appendChild(p);
      this.edgeEls.push({ e, el: p });
    }

    refreshHighlight() {
      if (!this.svg) return;
      const focus = this.sel || this.hover;
      const q = this.q;
      const near = new Set();
      if (focus) {
        near.add(focus);
        this.model.edges.forEach((e) => { if (e.a.id === focus) near.add(e.b.id); else if (e.b.id === focus) near.add(e.a.id); });
      }
      this.model.nodes.forEach((n) => {
        const el = n.el;
        el.classList.toggle('dim', !!((focus && !near.has(n.id)) || (q && !this.matches(n, q))));
        el.classList.toggle('sel', n.id === this.sel);
        el.classList.toggle('hit', !!(q && this.matches(n, q)));
      });
      this.edgeEls.forEach(({ e, el }) => {
        const on = focus && (e.a.id === focus || e.b.id === focus);
        el.classList.toggle('hl', !!on);
        el.classList.toggle('dim', !!focus && !on);
        el.setAttribute('marker-end', on ? 'url(#arr-hl)' : 'url(#arr)');
      });
    }
    matches(n, q) { return n.members.some((m) => A.searchText(m).includes(q)); }
    setQuery(q) { this.q = (q || '').trim().toLowerCase(); this.refreshHighlight(); }

    // -- pan / zoom
    apply() { if (!this.svg) return; this.vp.setAttribute('transform', `translate(${this.view.x},${this.view.y}) scale(${this.view.k})`); }
    fit() {
      if (!this.model || !this.svg) return;
      const r = this.host.getBoundingClientRect();
      const k = Math.min((r.width - 40) / this.model.w, (r.height - 40) / this.model.h, 1.1);
      this.view = { k: Math.max(0.08, k), x: 20 + Math.max(0, (r.width - 40 - this.model.w * k) / 2), y: 20 };
      this.apply();
    }
    /** First view: whole picture if it stays readable, otherwise fit the width and let the user pan down. */
    fitInitial() {
      if (!this.model || !this.svg) return;
      const r = this.host.getBoundingClientRect();
      const kw = (r.width - 40) / this.model.w;
      const kall = Math.min(kw, (r.height - 40) / this.model.h);
      if (kall >= 0.42) return this.fit();
      this.view = { k: Math.max(0.42, Math.min(1, kw)), x: 20, y: 20 };
      this.apply();
    }
    zoom(f, cx, cy) {
      if (!this.svg) return;
      const r = this.host.getBoundingClientRect();
      cx = cx == null ? r.width / 2 : cx; cy = cy == null ? r.height / 2 : cy;
      const k = Math.min(3, Math.max(0.06, this.view.k * f));
      const real = k / this.view.k;
      this.view.x = cx - (cx - this.view.x) * real;
      this.view.y = cy - (cy - this.view.y) * real;
      this.view.k = k;
      this.apply();
    }
    focus(key) {
      const n = this.svg && this.model && this.model.nodeOf.get(key);
      if (!n) return false;
      const r = this.host.getBoundingClientRect();
      this.view.k = Math.max(this.view.k, 0.9);
      this.view.x = r.width / 2 - (n.x + NW / 2) * this.view.k;
      this.view.y = r.height / 2 - (n.y + NH / 2) * this.view.k;
      this.apply();
      this.select(n.id);
      return true;
    }
    bindPanZoom() {
      const svg = this.svg;
      let drag = null;
      svg.addEventListener('wheel', (e) => {
        e.preventDefault();
        const b = this.host.getBoundingClientRect();
        this.zoom(Math.exp(-e.deltaY * (e.ctrlKey ? 0.01 : 0.0015)), e.clientX - b.left, e.clientY - b.top);
      }, { passive: false });
      svg.addEventListener('pointerdown', (e) => {
        if (e.button !== 0) return;
        drag = { x: e.clientX, y: e.clientY, vx: this.view.x, vy: this.view.y, moved: false };
        this.dragged = false;
      });
      window.addEventListener('pointermove', this._mv = (e) => {
        if (!drag) return;
        const dx = e.clientX - drag.x, dy = e.clientY - drag.y;
        if (!drag.moved && Math.hypot(dx, dy) < 4) return;
        drag.moved = true; this.dragged = true;
        svg.classList.add('panning');
        this.view.x = drag.vx + dx; this.view.y = drag.vy + dy; this.apply();
      });
      window.addEventListener('pointerup', this._up = () => {
        if (drag && drag.moved) setTimeout(() => { this.dragged = false; }, 0);
        drag = null; svg.classList.remove('panning');
      });
      svg.addEventListener('click', () => { if (!this.dragged && this.sel) { this.select(null); } });
    }
    destroy() {
      if (this._mv) window.removeEventListener('pointermove', this._mv);
      if (this._up) window.removeEventListener('pointerup', this._up);
    }
  }
  A.GraphView = GraphView;
  A.EDGE_KINDS = EDGE_KINDS;
  A.MAP_SHOW_TYPES = SHOW_TYPES;

  // ------------------------------------------------------------------------------------------ shared chrome
  A.mapLegend = function mapLegend() {
    return h('div', { class: 'map-legend' },
      A.groupLegend(),
      h('ul', { class: 'legend' },
        h('li', null, h('span', { class: 'sw-unused', 'aria-hidden': 'true' }), 'Dashed outline: flagged as unused or wasteful'),
        h('li', null, h('span', { class: 'sev', style: { '--sev': 'var(--critical)' } }, h('span', { class: 'sev-icon' }, '▲'), '3'), 'Findings (worst severity, count)'),
        h('li', null, A.dot('good'), 'healthy'), h('li', null, A.dot('warn'), 'stopped / unattached'), h('li', null, 'Arrows point from a resource to what it uses')));
  };

  A.graphControls = function graphControls(gv, st, onChange) {
    const search = h('input', { class: 'inp', type: 'search', placeholder: 'Highlight resources…', 'aria-label': 'Highlight resources', value: st.q || '',
      onInput: A.debounce((e) => { st.q = e.target.value; gv.setQuery(st.q); }, 120) });
    const kinds = h('details', { class: 'menu' }, h('summary', { class: 'btn' }, 'Connections'),
      h('div', { class: 'menu-body' }, EDGE_KINDS.map((k) => h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: gv.o.kinds.has(k.id),
        onChange(e) { e.target.checked ? gv.o.kinds.add(k.id) : gv.o.kinds.delete(k.id); onChange(); } }), k.label))));
    const show = h('details', { class: 'menu' }, h('summary', { class: 'btn' }, 'Show'),
      h('div', { class: 'menu-body' }, SHOW_TYPES.map((t) => h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: gv.o.show.has(t.id),
        onChange(e) { e.target.checked ? gv.o.show.add(t.id) : gv.o.show.delete(t.id); onChange(); } }), t.label))));
    const colorBy = A.segmented([{ id: 'group', label: 'Service' }, { id: 'cost', label: 'Cost' }], gv.o.colorBy, (v) => { gv.o.colorBy = v; onChange(); }, 'Colour by');
    const zoom = h('div', { class: 'seg' },
      h('button', { type: 'button', 'aria-label': 'Zoom out', onClick: () => gv.zoom(1 / 1.25) }, '−'),
      h('button', { type: 'button', onClick: () => gv.fit() }, 'Fit'),
      h('button', { type: 'button', 'aria-label': 'Zoom in', onClick: () => gv.zoom(1.25) }, '+'));
    return { search, kinds, show, colorBy, zoom };
  };

  // ------------------------------------------------------------------------------------------ Project map tab
  const mapState = { q: '', kinds: null, show: new Set(), expanded: new Set(), colorBy: 'group', select: null, view: null };
  A.tabs.map = {
    id: 'map', title: 'Project map',
    setState(s) { if (s && s.select) mapState.select = s.select; },
    render(root) {
      const { res } = A.scope();
      if (!mapState.kinds) mapState.kinds = new Set(EDGE_KINDS.filter((k) => k.on).map((k) => k.id));
      const host = h('div', { class: 'graph-wrap' });
      const gv = new GraphView(host, { mode: 'all', project: A.filters.project, show: mapState.show, kinds: mapState.kinds, expanded: mapState.expanded, colorBy: mapState.colorBy,
        onSelect: (key) => A.drawer.open(key) });
      if (mapState.view) { gv.view = mapState.view; gv._fitted = true; }
      const redraw = () => { gv.render(res); gv.setQuery(mapState.q); };
      const c = A.graphControls(gv, mapState, redraw);
      const head = h('div', { class: 'toolbar' }, c.search, c.colorBy, c.show, c.kinds, h('span', { class: 'grow' }), c.zoom);
      root.appendChild(A.card(null, null, head, h('p', { class: 'hint' }, A.filters.project ? `Showing project “${A.filters.project}”. ` : 'Showing every project grouped by region and network. ',
        'Scroll to zoom, drag to pan, click a resource to highlight what it connects to and open its details. Groups of more than 12 similar resources collapse: click to expand.')));
      root.appendChild(h('div', { class: 'card flush graph-card' }, host, A.mapLegend()));
      redraw();
      if (mapState.select) {
        const k = mapState.select;
        mapState.select = null;
        setTimeout(() => {
          if (gv.focus(k)) return;
          const r = A.byKey.get(k);
          const hidden = r && SHOW_TYPES.find((t) => t.test(r.type));   // e.g. a security group hidden by default
          if (hidden) { mapState.show.add(hidden.id); redraw(); gv.focus(k); }
        }, 60);
      }
      A.cleanup(() => { mapState.view = mapState.resetView ? null : gv.view; mapState.resetView = false; gv.destroy(); });
    },
  };
  A.on('filters', () => { mapState.resetView = true; });
  A.showOnMap = function showOnMap(key) {
    const r = A.byKey.get(key);
    // make sure the resource is inside the current filter, otherwise widen it
    if (r && !A.scope().keys.has(key)) A.setFilters({ account: '', region: '', project: '', env: '', q: '' });
    A.goto('map', { select: key });
  };
})();
