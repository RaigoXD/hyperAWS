/* 3D map: the pure city model. Turns the scoped resources into a deterministic "world": islands (cities), districts,
   lots, buildings, a street tree, flows (roads with traffic) and overlays. No DOM and no three.js: it is unit-tested in
   Node. Same input -> same world, whatever the input order. */
(function () {
  'use strict';
  const A = (window.AWSA = window.AWSA || {});
  const C = A.cityCatalog;
  const M = (A.city = A.city || {});

  // geometry, in world units (roughly metres)
  const STREET = 4, AVENUE = 5, BOULEVARD = 7, LOT_GAP = 2.5, LINE_GAP = 1.5, ROW_GAP = 3, COL_GAP = 5, MARGIN = 6, SAT = 4;
  const COLLAPSE_OVER = 8, CAR_SPEED = 12, MAX_FLOORS = 40;
  M.MAX_BUILDINGS = 1500;
  M.MAX_CARS = 1500;
  M.CAR_SPEED = CAR_SPEED;
  const SENSITIVE = [20, 21, 22, 23, 25, 445, 1433, 1521, 2049, 2375, 2379, 3306, 3389, 5432, 5601, 5984, 6379, 9042, 9200, 11211, 27017];
  const DB_ARCH = new Set(['vault', 'cabinet', 'corner']);
  const ARCH_ORDER = Object.fromEntries(Object.keys(C.ARCHETYPES).map((k, i) => [k, i]));

  // ---- small helpers ---------------------------------------------------------------------------------------------------
  function fnv(s) {
    let h = 0x811c9dc5;
    for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 0x01000193); }
    return h >>> 0;
  }
  M.hash = fnv;
  const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
  const lg = (x) => Math.log10(1 + Math.max(0, +x || 0));
  const clamp = (x, lo, hi) => Math.max(lo, Math.min(hi, x));
  const nameOf = (r) => r.name || r.rid;
  const typeLabel = (t) => (A.typeInfo ? A.typeInfo(t).label : t);
  const groupOf = (t) => (A.typeInfo ? A.typeInfo(t).group : 'ops');
  const findingsOf = (r) => (A.findingsOf ? A.findingsOf(r) : []);
  const SEV_RANK = { high: 0, medium: 1, low: 2, info: 3 };
  const worst = (fs) => fs.reduce((w, f) => (w == null || SEV_RANK[f.severity] < SEV_RANK[w] ? f.severity : w), null);

  /** Daily traffic of a resource from its CloudWatch totals: {perDay, unit, days} or null when not measured. */
  function daily(r) {
    const spec = C.TRAFFIC[r.type];
    const m = r.metrics || {};
    if (!spec) return null;
    const days = m._days || {};
    for (const [expr, unit] of spec) {
      const names = expr.split('+');
      if (!names.every((n) => typeof m[n] === 'number')) continue;
      const total = names.reduce((s, n) => s + m[n], 0);
      const d = Math.max(1, ...names.map((n) => days[n] || 14));
      return { perDay: total / d, unit, days: d };
    }
    return null;
  }
  M.daily = daily;

  // Requests-equivalent per day, so bytes and requests can share one car scale (1 car ~ 50 kB).
  const reqEq = (rate, unit) => (unit === 'bytes' ? rate / 50e3 : rate);
  /** Cars per second on a route for a daily rate: each step of the scale is ~10x more traffic. */
  M.carsPerSecond = (rate, unit) => clamp(0.25 * Math.log10(1 + reqEq(rate, unit) / 100), 0.034, 1.5);

  // =====================================================================================================================
  // 1. Context: indexes over the scoped resources and over everything (terrain lookups ignore the filters)
  // =====================================================================================================================
  function makeCtx(resources, opts) {
    const res = resources.slice().sort((a, b) => cmp(a.key, b.key));
    const byKey = new Map(res.map((r) => [r.key, r]));
    const all = A.byKey && A.byKey.size ? A.byKey : byKey;
    const allIncoming = new Map();
    for (const r of all.values()) {
      for (const rel of r.relations || []) {
        if (!allIncoming.has(rel.to)) allIncoming.set(rel.to, []);
        allIncoming.get(rel.to).push({ from: r.key, kind: rel.kind, label: rel.label });
      }
    }
    const byTypeName = new Map();
    for (const r of all.values()) byTypeName.set(`${r.account}:${r.region}:${r.type}:${r.name || r.rid}`, r);
    const scanned = Date.parse((A.data && (A.data.scanned_at || A.data.analyzed_at)) || '') || null;
    return { res, byKey, all, allIncoming, byTypeName, opts, scanned };
  }
  const key = (r, type, rid) => `${r.account}:${r.region}:${type}:${rid}`;

  function sgsOf(ctx, r) {
    const out = new Set((r.attrs && r.attrs.sg_ids) || []);
    for (const rel of r.relations || []) if (rel.kind === 'uses-sg') out.add(rel.to.split(':').pop());
    return [...out].sort().map((id) => ctx.all.get(key(r, 'ec2:security-group', id))).filter(Boolean);
  }
  /** World-open ports that matter on any security group of r ("tcp 5432", "all ports"), or null. */
  function openDoor(ctx, r) {
    const hits = [];
    for (const sg of sgsOf(ctx, r)) {
      for (const [proto, lo, hi] of sg.attrs.world_open || []) {
        if (proto === '-1' || proto === 'all' || lo == null) { hits.push('all ports'); continue; }
        const p = SENSITIVE.filter((x) => x >= lo && x <= hi);
        if (p.length || hi - lo > 1000) hits.push(lo === hi ? `${proto} ${lo}` : `${proto} ${lo}-${hi}`);
      }
    }
    return hits.length ? [...new Set(hits)].join(', ') : null;
  }
  M.openDoor = (r) => openDoor(makeCtx([r], {}), r);

  function eniOwner(ctx, eni) {
    if (!eni) return null;
    const a = eni.attrs || {};
    if (a.instance_id) return ctx.all.get(key(eni, 'ec2:instance', a.instance_id)) || null;
    const d = a.description || '';
    let m;
    if (a.if_type === 'nat_gateway' || /^Interface for NAT Gateway/i.test(d)) {
      for (const r of ctx.all.values()) if (r.type === 'ec2:nat-gateway' && r.account === eni.account && r.region === eni.region && (r.attrs || {}).subnet === a.subnet) return r;
    }
    if ((m = /^ELB (?:app|net|gwy)\/([^/]+)\//.exec(d))) return ctx.byTypeName.get(`${eni.account}:${eni.region}:elbv2:lb:${m[1]}`) || null;
    if ((m = /^ELB ([^/\s]+)$/.exec(d))) return ctx.byTypeName.get(`${eni.account}:${eni.region}:elb:clb:${m[1]}`) || null;
    if ((m = /^AWS Lambda VPC ENI-(.+)-[0-9a-f]{8}-[0-9a-f]{4}-/.exec(d))) return ctx.byTypeName.get(`${eni.account}:${eni.region}:lambda:function:${m[1]}`) || null;
    return null;
  }
  /** The resource an Elastic IP is the street address of (instance, load balancer, NAT ...), or null. */
  function eipHost(ctx, eip) {
    for (const rel of eip.relations || []) {
      if (rel.kind !== 'associated-with') continue;
      const t = ctx.all.get(rel.to);
      if (t && t.type === 'ec2:instance') return t;
      if (t && t.type === 'ec2:eni') { const o = eniOwner(ctx, t); if (o) return o; }
    }
    const a = eip.attrs || {};
    if (a.instance_id) { const i = ctx.all.get(key(eip, 'ec2:instance', a.instance_id)); if (i) return i; }
    if (a.eni_id) { const o = eniOwner(ctx, ctx.all.get(key(eip, 'ec2:eni', a.eni_id))); if (o) return o; }
    for (const inc of ctx.allIncoming.get(eip.key) || []) if (inc.kind === 'uses-eip') return ctx.all.get(inc.from) || null;
    return null;
  }

  // =====================================================================================================================
  // 2. Resource-level flows (who sends requests to whom), overlays and the Internet
  // =====================================================================================================================
  function flowGraph(ctx) {
    const { res, byKey } = ctx;
    const flows = [];
    const overlays = [];
    const seen = new Set();
    const add = (from, to, kind, label, extra) => {
      const id = `${from}>${to}>${kind}`;
      if (seen.has(id) || from === to) return;
      seen.add(id);
      flows.push(Object.assign({ id, from, to, kind, label: label || '' }, extra || {}));
    };
    for (const r of res) {
      if (r.type === 'ec2:subnet') continue;          // egress is expanded below
      for (const rel of r.relations || []) {
        const spec = C.KINDS[rel.kind];
        if (!spec || !byKey.has(rel.to) || rel.to === r.key) continue;
        const [a, b] = spec.dir === 'rev' ? [rel.to, r.key] : [r.key, rel.to];
        if (spec.show === 'road' || spec.show === 'internal') add(a, b, rel.kind, rel.label);
        else overlays.push({ id: `${a}>${b}>${rel.kind}`, from: a, to: b, kind: rel.kind, label: rel.label || '' });
      }
    }
    // private buildings drive out through the NAT of their subnet
    const natOfSubnet = new Map();
    for (const r of ctx.all.values()) {
      if (r.type !== 'ec2:subnet') continue;
      const nat = (r.relations || []).find((x) => x.kind === 'egress-via' && byKey.has(x.to));
      if (nat) natOfSubnet.set(`${r.account}:${r.region}:${r.rid}`, nat.to);
    }
    const usedNats = new Set();
    if (natOfSubnet.size) {
      for (const r of res) {
        const a = r.attrs || {};
        if (r.type === 'ec2:instance' && r.state !== 'running') continue;
        if (!['ec2:instance', 'lambda:function', 'ecs:service', 'eks:nodegroup'].includes(r.type)) continue;
        const subs = a.subnet ? [a.subnet] : a.subnet_ids || [];
        const nat = subs.map((s) => natOfSubnet.get(`${r.account}:${r.region}:${s}`)).find(Boolean);
        if (nat) { add(r.key, nat, 'egress-via'); usedNats.add(nat); }
      }
    }
    // a private NAT gateway only reaches other private networks, never the Internet
    for (const r of res) if (r.type === 'ec2:nat-gateway' && r.state !== 'deleted' && (r.attrs || {}).connectivity !== 'private') add(r.key, 'internet', 'internet-out');

    // visitors from the Internet
    const hasEip = (r) => (ctx.allIncoming.get(r.key) || []).some((x) => x.kind === 'associated-with');
    for (const r of res) {
      const a = r.attrs || {};
      let entry = false;
      if (r.type === 'elbv2:lb' || r.type === 'elb:clb') entry = a.scheme === 'internet-facing';
      else if (r.type === 'cloudfront:distribution') entry = r.state !== 'disabled';
      else if (r.type.startsWith('apigw:')) entry = ![].concat(a.endpoint_types || [], a.endpoint_type || []).some((t) => /private/i.test(t));
      else if (r.type === 'ec2:instance') entry = r.state === 'running' && (!!a.public_ip || hasEip(r));
      else if (/^(rds|docdb|neptune):instance$/.test(r.type)) entry = !!a.public;
      if (!entry) continue;
      const door = openDoor(ctx, r);
      const edge = /^(elbv2:lb|elb:clb|cloudfront|apigw)/.test(r.type);
      add('internet', r.key, 'internet', '', { danger: !!door && !edge, door });
    }

    if (ctx.opts.likely) overlays.push(...likely(ctx, flows, overlays));
    const busy = new Set();
    for (const f of flows) { busy.add(f.from); busy.add(f.to); }
    for (const o of overlays) if (o.kind !== 'uses-role') { busy.add(o.from); busy.add(o.to); }
    rates(ctx, flows);
    return { flows, overlays, busy };
  }

  /** Senders into `k` (in the direction requests travel) that the scan knows about but this view filters out. */
  function sendersOutside(ctx, k) {
    const road = (s) => s && (s.show === 'road' || s.show === 'internal');
    let n = 0;
    for (const inc of ctx.allIncoming.get(k) || []) {
      const s = C.KINDS[inc.kind];
      if (road(s) && s.dir === 'fwd' && inc.kind !== 'egress-via' && inc.label !== 'disabled' && !ctx.byKey.has(inc.from)) n++;
    }
    const r = ctx.all.get(k);
    for (const rel of (r && r.relations) || []) {
      const s = C.KINDS[rel.kind];
      if (road(s) && s.dir === 'rev' && rel.label !== 'disabled' && !ctx.byKey.has(rel.to)) n++;
    }
    return n;
  }

  /** Fills rate/unit/status on every flow. Unknown stays unknown; "measured" only when the sender's own metric counts
      exactly that road's traffic; "zero" only when a measurement says nothing passed. */
  function rates(ctx, flows) {
    const meas = new Map();
    for (const r of ctx.res) { const d = daily(r); if (d) meas.set(r.key, d); }
    const off = (f) => f.label === 'disabled';                                // a switched-off trigger carries nothing
    const countable = (f) => f.kind !== 'dead-letter-to' && f.kind !== 'replica-of' && !off(f);
    // roads the sender's own metric does not measure: egress through a NAT (an instance's NetworkIn counts everything it
    // receives, a function's metric counts calls) and a DynamoDB stream (read/write capacity units are not stream records)
    const blind = (f) => f.kind === 'egress-via' || (f.kind === 'consumes' && (ctx.byKey.get(f.from) || {}).type === 'dynamodb:table');
    const splitOut = new Map();
    for (const f of flows) {
      if (countable(f) && !blind(f) && C.KINDS[f.kind].fan !== 'copy') splitOut.set(f.from, (splitOut.get(f.from) || 0) + 1);
    }
    const est = new Map([...meas].map(([k, v]) => [k, Object.assign({ status: 'measured' }, v)]));
    const order = flows.slice().sort((a, b) => cmp(a.id, b.id));
    for (let pass = 0; pass < 4; pass++) {
      const late = [];
      for (const f of order) {
        const src = blind(f) ? null : est.get(f.from);
        if (!src && meas.get(f.to) && countable(f)) { late.push(f); continue; }   // after the senders we know
        f.rate = null; f.unit = null; f.status = 'unknown'; f.basis = null;
        if (f.kind === 'dead-letter-to') {
          const q = ctx.byKey.get(f.to);
          const waiting = q && q.attrs ? q.attrs.messages : null;
          if (typeof waiting === 'number') { f.status = 'parked'; f.parked = waiting; }
          continue;
        }
        if (f.kind === 'replica-of') continue;
        if (off(f)) { f.basis = 'the trigger is switched off (disabled)'; continue; }
        if (!src) continue;
        const spec = C.KINDS[f.kind];
        const n = spec.fan === 'copy' ? 1 : Math.max(1, splitOut.get(f.from) || 1);
        f.rate = src.perDay / n; f.unit = src.unit;
        f.status = src.status === 'measured' && n === 1 ? 'measured' : 'estimated';
        f.basis = n === 1 ? `${src.status} at ${f.from === 'internet' ? 'the Internet' : 'the sender'}` : `${src.status} at the sender, shared between ${n} destinations`;
        if (f.kind === 'origin') {
          // a CDN counts viewer requests; cache hits never reach the origin, so this is only an upper bound
          const tgt = meas.get(f.to);
          const capped = !!tgt && tgt.unit === f.unit && tgt.perDay < f.rate;
          if (capped) f.rate = tgt.perDay;
          f.status = 'estimated';
          f.basis = `viewer requests counted by the CDN${n > 1 ? `, shared between ${n} origins` : ''}; cache hits never reach the origin, so it gets at most this much` +
            (capped ? ' (capped at what the origin itself counted)' : '');
        }
        if (f.rate === 0) f.status = 'zero';
      }
      // receivers we measured: what the known senders do not explain is shared by the unknown ones (e.g. the Internet).
      // That is an inference, never a measurement: other senders may be filtered out, switched off or invisible to the scan.
      for (const f of late) {
        const tgt = meas.get(f.to);
        const others = order.filter((g) => g.to === f.to && g !== f && !late.includes(g) && countable(g) && g.rate != null);
        if (others.some((g) => g.unit !== tgt.unit && g.rate > 0)) {
          // e.g. a load balancer's requests into a server measured in bytes: they cannot be subtracted
          f.rate = null; f.unit = null; f.status = 'unknown';
          f.basis = 'its receiver’s measurement also covers traffic counted in other units from other senders, so it cannot be split';
          continue;
        }
        const known = others.filter((g) => g.unit === tgt.unit).reduce((t, g) => t + g.rate, 0);
        const unknownSenders = late.filter((g) => g.to === f.to).length;
        const hidden = sendersOutside(ctx, f.to);
        f.rate = Math.max(0, tgt.perDay - known) / unknownSenders; f.unit = tgt.unit;
        f.status = tgt.perDay === 0 ? 'zero' : 'estimated';
        f.basis = (known ? 'measured at the receiver, minus what its other senders account for'
          : unknownSenders === 1 ? 'measured at the receiver: all it received, assumed to come from here'
            : `measured at the receiver, shared between ${unknownSenders} senders`) +
          (hidden ? `; ${hidden} sender${hidden === 1 ? '' : 's'} outside this view ${hidden === 1 ? 'is' : 'are'} not subtracted` : '');
      }
      // nodes without their own measurement inherit what flows into them (e.g. a target group)
      const inflow = new Map();
      for (const f of order) {
        if (f.rate == null || meas.has(f.to) || f.to === 'internet') continue;   // outbound bytes are not visitors
        const cur = inflow.get(f.to) || { perDay: 0, unit: f.unit, status: 'estimated' };
        if (cur.unit === f.unit) cur.perDay += f.rate;
        inflow.set(f.to, cur);
      }
      inflow.forEach((v, k) => est.set(k, v));
    }
  }

  /** "Likely connections": guesses from names and networks, never persisted, always labelled as guesses. */
  function likely(ctx, flows, overlays) {
    const CONSUMER = new Set(['ec2:instance', 'ecs:service', 'eks:cluster', 'eks:nodegroup', 'lambda:function']);
    const PROVIDER = /^(rds:instance|rds:cluster|docdb:|neptune:|elasticache:|dynamodb:table)/;
    const known = new Set();
    for (const f of [...flows, ...overlays]) { known.add(f.from + '|' + f.to); known.add(f.to + '|' + f.from); }
    const vpcOf = (r) => {
      const a = r.attrs || {};
      if (a.vpc) return a.vpc;
      const sub = a.subnet || (a.subnet_ids || [])[0];
      const s = sub && ctx.all.get(key(r, 'ec2:subnet', sub));
      if (s) return s.attrs.vpc;
      if (r.type === 'eks:nodegroup') { const c = ctx.all.get(key(r, 'eks:cluster', a.cluster)); return c && c.attrs.vpc; }
      return null;
    };
    const GENERIC = new Set(['prod', 'production', 'dev', 'test', 'stage', 'staging', 'qa', 'app', 'api', 'web', 'db', 'database', 'service', 'svc', 'task', 'server', 'backend', 'frontend', 'main', 'default', 'cluster', 'instance', 'aws', 'the', 'and', 'lambda', 'function', 'bucket', 'table', 'queue', 'cache', 'redis', 'postgres', 'mysql', 'rds']);
    const tokens = (r) => new Set(String(nameOf(r)).toLowerCase().split(/[^a-z0-9]+/).filter((t) => t.length >= 3 && !GENERIC.has(t)));
    const real = (p) => p && !p.startsWith('(') && p !== 'Unassigned';
    const isProvider = (r) => PROVIDER.test(r.type) && r.state !== 'stopped';
    const providers = ctx.res.filter(isProvider);
    const dbsInVpc = new Map();                  // counted over everything, not the filtered view ("the only database there")
    for (const p of ctx.all.values()) { if (!isProvider(p)) continue; const v = vpcOf(p); if (v) dbsInVpc.set(v, (dbsInVpc.get(v) || 0) + 1); }
    const out = [];
    for (const c of ctx.res) {
      if (!CONSUMER.has(c.type) || (c.type === 'ec2:instance' && c.state !== 'running')) continue;
      const cv = vpcOf(c);
      const ct = tokens(c);
      const cand = [];
      for (const p of providers) {
        if (p.account !== c.account || p.region !== c.region || known.has(c.key + '|' + p.key)) continue;
        const pv = vpcOf(p);
        const why = [];
        let s = 0;
        if (pv && cv && pv === cv) { s += 2; why.push('same private network'); }
        else if (pv && !(p.attrs || {}).public) continue;                 // a private database outside the network is unreachable
        if (real(c.project) && c.project === p.project) { s += 2; why.push('same project'); }
        if (pv && pv === cv && dbsInVpc.get(pv) === 1) { s += 1; why.push('the only database there'); }
        if (c.env && c.env === p.env) { s += 1; why.push('same environment'); }
        const shared = [...tokens(p)].filter((t) => ct.has(t));
        if (shared.length) { s += 1; why.push(`names share "${shared[0]}"`); }
        if (s >= 3) cand.push({ p, s, why });
      }
      cand.sort((a, b) => b.s - a.s || cmp(a.p.key, b.p.key));
      for (const { p, s, why } of cand.slice(0, 3)) {
        out.push({ id: `${c.key}>${p.key}>likely`, from: c.key, to: p.key, kind: 'likely', score: s, label: 'Guess, not from AWS data: ' + why.join(', ') });
      }
    }
    return out;
  }

  // =====================================================================================================================
  // 3. Entities: buildings, satellites, hub pieces; placement into city / column / row cells
  // =====================================================================================================================
  function newEnt(id, kind, archetype, extra) {
    return Object.assign({ id, kind, archetype, key: null, res: null, members: [], sats: [], name: '', cost: 0,
      sev: null, vacant: false, coin: 0, lit: false, h: 1, y0: 0, rot: 0, cx: 0, cz: 0, w: 1, d: 1 }, extra || {});
  }
  function decorate(ent, rs, opts, ctx) {
    let cost = 0, coin = 0;
    const fs = [];
    let unused = 0;
    for (const r of rs) {
      cost += r.est_monthly_usd || 0;
      const f = findingsOf(r);
      fs.push(...f);
      const u = f.filter((x) => x.category === 'unused');
      if (u.length) unused++;
      for (const x of u) coin = Math.max(coin, (x.breakdown || {})[r.key] || 0);
    }
    ent.cost = cost;
    ent.findings = fs;
    ent.sev = worst(fs);
    ent.vacant = rs.length > 0 && unused === rs.length;
    ent.coin = ent.vacant ? coin : 0;
    const r = rs[0];
    if (r && rs.length === 1) {
      const s = (r.state || '').toLowerCase();
      if (r.type === 'ec2:instance') ent.lit = s === 'running';
      else if (r.type === 'lambda:function') ent.lit = ((r.metrics || {}).invocations || 0) > 0;
      else ent.lit = !['stopped', 'disabled', 'inactive', 'failed'].includes(s);
      ent.stopped = ['stopped', 'disabled', 'inactive'].includes(s);
      ent.door = openDoor(ctx, r);
    } else ent.lit = true;
    ent.h = heightOf(ent, rs, opts);
  }
  function sizeMetric(rs) {
    let s = 0, any = false;
    for (const r of rs) {
      const a = r.attrs || {}, m = r.metrics || {};
      let v = null;
      if (r.type === 's3:bucket') v = Object.keys(m).filter((k) => k.startsWith('bytes_')).reduce((t, k) => t + (m[k] || 0), 0) / 1e9;
      else if (r.type === 'dynamodb:table') v = (a.size_bytes || 0) / 1e9;
      else if (a.storage_gb != null) v = a.storage_gb;
      else if (a.size_gb != null) v = a.size_gb;
      else if (r.type === 'ecr:repository') v = (a.size_bytes || 0) / 1e9;
      if (v != null) { s += v; any = true; }
    }
    return any ? s : null;
  }
  function heightOf(ent, rs, opts) {
    const ar = C.ARCHETYPES[ent.archetype] || C.ARCHETYPES.unknown;
    let h = ar.h + ar.k * lg(ent.cost);
    if (opts.height === 'size') {
      // one scale only: without a stored-data size a building keeps its base height (never its cost height)
      const s = sizeMetric(rs);
      ent.sizeless = s == null;
      h = s == null ? ar.h : ar.h + ar.k * 1.2 * lg(s);
    }
    if (ent.kind === 'stack') h = ar.h + 1.5 * Math.log2(1 + rs.length);
    return clamp(h, ar.h, 40);
  }
  function footprint(ent) {
    const ar = C.ARCHETYPES[ent.archetype] || C.ARCHETYPES.unknown;
    let w = ar.w, d = ar.d;
    if (ent.kind === 'stack') { w = d = clamp(8 + Math.sqrt(ent.members.length) * 1.6, 9, 18); }
    if (ent.kind === 'yard') { w = d = clamp(7 + Math.sqrt(ent.members.length) * 1.2, 8, 14); }
    ent.bw = w; ent.bd = d;
    const sheds = ent.sats.filter((s) => s.kind === 'shed').length;
    const posts = ent.sats.filter((s) => s.kind === 'signpost').length;
    ent.lw = w + (posts ? 3.5 : 0);
    ent.ld = d + (sheds ? SAT + 0.8 : 0);
  }

  function visible(r, opts) {
    if (C.TERRAIN.has(r.type)) return false;
    if (r.type === 'logs:log-group') return !!opts.logs;
    if (r.type.startsWith('other:')) return !!opts.other;
    if (r.type.startsWith('iam:')) return opts.iam !== false;
    return true;
  }

  // =====================================================================================================================
  // 4. Layout: cities -> columns -> rows -> lines -> lots, a street tree, the hub and the ring
  // =====================================================================================================================
  function build(resources, options) {
    const opts = Object.assign({ mode: 'project', height: 'cost', ghosts: false, logs: false, other: false, iam: true, likely: false, expanded: [] }, options || {});
    const expanded = new Set(opts.expanded || []);
    const ctx = makeCtx(resources, opts);
    const graph = flowGraph(ctx);
    const world = { mode: opts.mode, opts, ents: [], islands: [], plates: [], walls: [], gates: [], streets: [], flows: [], overlays: [],
      labels: [], directory: [], byId: new Map(), entOfKey: new Map(), nodes: new Map(), stats: {}, ghosts: [] };
    const entOfKey = world.entOfKey;
    const addEnt = (e) => {
      world.ents.push(e);
      world.byId.set(e.id, e);
      if (e.key) entOfKey.set(e.key, e.id);
      for (const m of e.members) if (!entOfKey.has(m)) entOfKey.set(m, e.id);
      for (const s of e.sats || []) entOfKey.set(s.key, e.id);          // traffic to a satellite drives to its host
      return e;
    };

    // ---- satellites: volumes behind their tower, address signs in front of their building, kiosks on their plaza
    const vis = ctx.res.filter((r) => visible(r, opts));
    const visKeys = new Set(vis.map((r) => r.key));
    const isHostable = (r) => r && visKeys.has(r.key) && !C.HUB_TYPES.has(r.type) && !(opts.mode === 'network' && r.type === 'cloudfront:distribution');
    const satOf = new Map();       // sat resource key -> host key
    for (const r of vis) {
      let host = null, kind = null;
      if (r.type === 'ec2:volume') {
        const rel = (r.relations || []).find((x) => x.kind === 'attached-to');
        host = rel && ctx.byKey.get(rel.to); kind = 'shed';
      } else if (r.type === 'ec2:eip') { host = eipHost(ctx, r); kind = 'signpost'; }
      else if (r.type === 'elbv2:target-group') {
        const rel = (r.relations || []).filter((x) => x.kind === 'behind').map((x) => x.to).sort()[0];
        host = rel && ctx.byKey.get(rel); kind = 'kiosk';
      }
      if (host && isHostable(host) && host.key !== r.key && !satOf.has(host.key)) satOf.set(r.key, { host: host.key, kind });
    }

    // ---- hub pieces
    const hub = { items: [] };
    const internet = addEnt(newEnt('internet', 'internet', 'internet', { name: 'The Internet', lit: true, h: 10 }));
    hub.items.push(internet);
    const roles = vis.filter((r) => r.type === 'iam:role').sort((a, b) => cmp(nameOf(a).toLowerCase(), nameOf(b).toLowerCase()) || cmp(a.key, b.key));
    const users = vis.filter((r) => r.type === 'iam:user').sort((a, b) => cmp(nameOf(a), nameOf(b)) || cmp(a.key, b.key));
    for (let t = 0; t * MAX_FLOORS < roles.length; t++) {
      const chunk = roles.slice(t * MAX_FLOORS, (t + 1) * MAX_FLOORS);
      const hq = newEnt(`hq:${t}`, 'hq', 'hq', { name: t ? `Identity HQ annex ${t}` : 'Identity HQ', members: chunk.map((r) => r.key), lit: true });
      hq.floors = chunk.map((r, i) => {
        const f = newEnt('floor:' + r.key, 'floor', 'floor', { key: r.key, res: r, name: nameOf(r), parent: hq.id, level: i });
        decorate(f, [r], opts, ctx);
        const last = Date.parse((r.attrs || {}).last_used || '') || null;
        f.lit = !!last && (!ctx.scanned || ctx.scanned - last < 90 * 864e5);
        f.dormant = !f.lit;
        return f;
      });
      hq.h = 3 + chunk.length * C.ARCHETYPES.floor.h + 2;
      hq.cost = 0; hq.findings = []; hq.sev = worst(hq.floors.flatMap((f) => f.findings || []));
      addEnt(hq); hq.floors.forEach(addEnt);
      hub.items.push(hq);
    }
    if (users.length) {
      const bo = newEnt('badges', 'badges', 'badges', { name: 'Badge office (IAM users)', members: users.map((r) => r.key), lit: true });
      bo.people = users.map((r, i) => {
        const p = newEnt('person:' + r.key, 'person', 'badges', { key: r.key, res: r, name: nameOf(r), parent: bo.id, idx: i });
        decorate(p, [r], opts, ctx);
        return p;
      });
      bo.h = 4; bo.findings = []; bo.sev = worst(bo.people.flatMap((p) => p.findings || []));
      addEnt(bo); bo.people.forEach(addEnt);
      hub.items.push(bo);
    }
    for (const r of vis.filter((x) => x.type === 'route53:hosted-zone' || (opts.mode === 'network' && x.type === 'cloudfront:distribution'))) {
      const e = newEnt(r.key, 'building', C.info(r.type).archetype, { key: r.key, res: r, name: nameOf(r), group: groupOf(r.type) });
      e.sats = [];
      decorate(e, [r], opts, ctx);
      addEnt(e);
      hub.items.push(e);
    }

    // ---- placement of everything else into cells
    const cities = new Map();
    const realProject = (p) => p && !p.startsWith('(') && p !== 'Unassigned';
    const subnetOf = new Map(), vpcOf = new Map(), igwOf = new Map();
    for (const r of ctx.all.values()) {
      if (r.type === 'ec2:subnet') subnetOf.set(`${r.account}:${r.region}:${r.rid}`, r);
      if (r.type === 'ec2:vpc') vpcOf.set(`${r.account}:${r.region}:${r.rid}`, r);
      if (r.type === 'ec2:igw') for (const v of (r.attrs || {}).vpcs || []) igwOf.set(`${r.account}:${r.region}:${v}`, r);
    }
    const accounts = new Set(ctx.res.map((r) => r.account));
    const regionCityId = (r) => 'r:' + (accounts.size > 1 ? r.account + ':' : '') + r.region;
    const regionCityName = (r) => (accounts.size > 1 ? `${r.account} · ${r.region}` : r.region);

    function city(id, name, kind) {
      if (!cities.has(id)) cities.set(id, { id, name, kind, columns: new Map(), cost: 0, nres: 0 });
      return cities.get(id);
    }
    function cell(ci, colId, colLabel, colKind, rowId, rowLabel, rowKind, extra) {
      if (!ci.columns.has(colId)) ci.columns.set(colId, Object.assign({ id: colId, label: colLabel, kind: colKind, rows: new Map() }, extra || {}));
      const col = ci.columns.get(colId);
      if (!col.rows.has(rowId)) col.rows.set(rowId, { id: rowId, label: rowLabel, kind: rowKind, items: [], plots: [] });
      return col.rows.get(rowId);
    }
    function netPlace(r) {
      const a = r.attrs || {};
      const sk = (s) => `${r.account}:${r.region}:${s}`;
      let subnet = a.subnet || null;
      let vpc = a.vpc || null;
      if (r.type === 'ec2:eip' && a.eni_id) {
        const eni = ctx.all.get(key(r, 'ec2:eni', a.eni_id));
        if (eni) { subnet = eni.attrs.subnet || null; vpc = eni.attrs.vpc || null; }
      }
      if (r.type === 'eks:nodegroup' && a.cluster) { const c = ctx.all.get(key(r, 'eks:cluster', a.cluster)); if (c) vpc = c.attrs.vpc || vpc; }
      if (!vpc && subnet && subnetOf.get(sk(subnet))) vpc = subnetOf.get(sk(subnet)).attrs.vpc;
      if (!vpc && (a.subnet_ids || []).length && subnetOf.get(sk(a.subnet_ids[0]))) vpc = subnetOf.get(sk(a.subnet_ids[0])).attrs.vpc;
      if (vpc && vpcOf.has(sk(vpc))) {
        const sub = subnet && subnetOf.get(sk(subnet));
        return { col: 'vpc:' + vpc, vpc, row: sub ? 'subnet:' + subnet : 'commons', sub };
      }
      return { col: 'downtown', row: 'tier:' + C.info(r.type).tier };
    }
    const vpcColumn = (ci, r, vpcId) => {
      const v = vpcOf.get(`${r.account}:${r.region}:${vpcId}`);
      const igw = igwOf.get(`${r.account}:${r.region}:${vpcId}`);
      return { label: v ? (v.name && v.name !== v.rid ? `${v.name}` : vpcId) + (v.attrs.is_default ? ' (default network)' : '') : vpcId,
        kind: 'vpc', vpc: v, igw, dashed: !!(v && v.attrs.is_default) };
    };
    const tierLabel = (t) => (C.TIERS.find((x) => x.id === t) || { label: t }).label;

    const placed = [];
    for (const r of vis) {
      if (satOf.has(r.key) || C.HUB_TYPES.has(r.type)) continue;
      if (opts.mode === 'network' && r.type === 'cloudfront:distribution') continue;
      let ci, row;
      const info = C.info(r.type);
      if (opts.mode === 'network') {
        ci = city(regionCityId(r), regionCityName(r), 'region');
        const p = netPlace(r);
        if (p.col === 'downtown') row = cell(ci, 'downtown', 'Downtown (outside private networks)', 'downtown', p.row, tierLabel(info.tier), 'band');
        else {
          const vc = vpcColumn(ci, r, p.vpc);
          if (p.row === 'commons') row = cell(ci, p.col, vc.label, 'vpc', 'commons', 'Shared by the whole network', 'commons', vc);
          else row = cell(ci, p.col, vc.label, 'vpc', p.row, p.sub.name && p.sub.name !== p.sub.rid ? p.sub.name : p.sub.rid, 'block', vc);
          if (p.sub) row.sub = p.sub;
        }
      } else {
        const pk = r.project === '(shared infrastructure)' ? 'utilities' : r.project === 'Unassigned' ? 'outskirts' : 'project';
        ci = city('p:' + (r.project || 'Unassigned'), pk === 'utilities' ? 'Utilities (shared infrastructure)' : pk === 'outskirts' ? 'Outskirts (no project)' : r.project, pk);
        const reg = r.region || 'global';
        row = cell(ci, 'reg:' + reg, reg === 'global' ? 'Global' : reg, 'region', 'tier:' + info.tier, tierLabel(info.tier), 'band');
      }
      ci.cost += r.est_monthly_usd || 0;
      ci.nres++;
      row.items.push(r);
      placed.push(r);
    }
    // network mode: every scoped VPC and subnet exists as land, even when empty
    if (opts.mode === 'network') {
      for (const r of ctx.res) {
        if (r.type === 'ec2:vpc') {
          const ci = city(regionCityId(r), regionCityName(r), 'region');
          const vc = vpcColumn(ci, r, r.rid);
          cell(ci, 'vpc:' + r.rid, vc.label, 'vpc', 'commons', 'Shared by the whole network', 'commons', vc);
        }
      }
      for (const r of ctx.res) {
        if (r.type !== 'ec2:subnet') continue;
        const ci = cities.get(regionCityId(r));
        const col = ci && ci.columns.get('vpc:' + (r.attrs || {}).vpc);
        if (!col) continue;
        const row = col.rows.get('subnet:' + r.rid);
        if (!row) {
          if (!col.rows.has('empty')) col.rows.set('empty', { id: 'empty', label: 'Empty subnets', kind: 'empty', items: [], plots: [] });
          col.rows.get('empty').plots.push(r);
        }
      }
    }

    // ---- turn cell items into lots (entities), collapsing big groups of quiet look-alikes
    const cityList = [...cities.values()];
    for (const ci of cityList) {
      for (const col of ci.columns.values()) {
        for (const row of col.rows.values()) {
          const lots = [];
          const yard = row.items.filter((r) => C.YARD_TYPES.has(r.type));
          const rest = row.items.filter((r) => !C.YARD_TYPES.has(r.type));
          const byType = new Map();
          for (const r of rest) { if (!byType.has(r.type)) byType.set(r.type, []); byType.get(r.type).push(r); }
          for (const [type, rs] of [...byType].sort((a, b) => cmp(a[0], b[0]))) {
            const quiet = rs.filter((r) => !graph.busy.has(r.key) && !findingsOf(r).length && ![...satOf.values()].some((s) => s.host === r.key));
            const stackId = `stack:${ci.id}:${col.id}:${row.id}:${type}`;
            const collapse = quiet.length > COLLAPSE_OVER && !expanded.has(stackId);
            for (const r of rs) {
              if (collapse && quiet.includes(r)) continue;
              const e = newEnt(r.key, 'building', C.info(r.type).archetype, { key: r.key, res: r, name: nameOf(r), group: groupOf(r.type) });
              lots.push(e);
            }
            if (collapse) {
              const e = newEnt(stackId, 'stack', 'stack', { name: `${quiet.length} × ${typeLabel(type)}`, members: quiet.map((r) => r.key), group: groupOf(type), memberType: type });
              lots.push(e);
              decorate(e, quiet, opts, ctx);
            }
          }
          if (yard.length) {
            const e = newEnt(`yard:${ci.id}:${col.id}:${row.id}`, 'yard', 'yard', { name: `Archive yard (${yard.length} backup${yard.length > 1 ? 's' : ''} / image${yard.length > 1 ? 's' : ''})`,
              members: yard.map((r) => r.key), group: 'data' });
            decorate(e, yard, opts, ctx);
            lots.push(e);
          }
          for (const s of row.plots) {
            lots.push(newEnt('plot:' + s.key, 'plot', 'plot', { key: s.key, res: s, name: nameOf(s), group: 'network', findings: findingsOf(s), sev: worst(findingsOf(s)), h: 0.3 }));
          }
          // satellites ride along with their host
          for (const e of lots) {
            if (e.kind !== 'building') continue;
            for (const [sk, s] of satOf) {
              if (s.host !== e.key) continue;
              const sr = ctx.byKey.get(sk);
              const sat = { kind: s.kind, key: sk, res: sr, name: nameOf(sr) };
              const f = findingsOf(sr);
              sat.sev = worst(f); sat.findings = f;
              sat.vacant = f.some((x) => x.category === 'unused');
              e.sats.push(sat);
            }
            e.sats.sort((a, b) => cmp(a.kind, b.kind) || cmp(a.key, b.key));
            if (e.kind === 'building') decorate(e, [e.res], opts, ctx);
            e.satCost = e.sats.reduce((t, s) => t + (s.res.est_monthly_usd || 0), 0);
            const all = [...(e.findings || []), ...e.sats.flatMap((s) => s.findings || [])];
            e.sev = worst(all);
          }
          lots.forEach(footprint);
          lots.sort((a, b) => (ARCH_ORDER[a.archetype] - ARCH_ORDER[b.archetype]) || ((b.cost || 0) - (a.cost || 0)) || cmp((a.name || '').toLowerCase(), (b.name || '').toLowerCase()) || cmp(a.id, b.id));
          row.lots = lots;
        }
      }
    }

    // ---- order: cities, columns, rows
    const cityRank = (c) => (c.kind === 'project' || c.kind === 'region' ? 0 : c.kind === 'utilities' ? 1 : 2);
    let shown = cityList.filter((c) => [...c.columns.values()].some((col) => [...col.rows.values()].some((r) => r.lots.some((l) => l.kind !== 'plot'))));
    const ghosts = cityList.filter((c) => !shown.includes(c));
    if (opts.mode === 'network' && opts.ghosts) shown = cityList.slice();
    shown.sort((a, b) => cityRank(a) - cityRank(b) || b.cost - a.cost || b.nres - a.nres || cmp(a.name, b.name));
    world.ghosts = opts.mode === 'network' && !opts.ghosts ? ghosts.sort((a, b) => cmp(a.name, b.name)) : [];

    const colRank = (col) => (col.kind === 'downtown' ? 0 : col.kind === 'vpc' ? (col.dashed ? 2 : 1) : 0);
    const rowRank = (row) => {
      if (row.kind === 'band') return C.tierIndex[row.id.slice(5)] || 0;
      if (row.kind === 'commons') return -1;
      if (row.kind === 'empty') return 99;
      return row.sub && row.sub.attrs.public_on_launch ? 0 : 1;
    };
    const buildingsIn = (col) => [...col.rows.values()].reduce((t, r) => t + r.lots.filter((l) => l.kind !== 'plot').length, 0);
    for (const ci of shown) {
      ci.cols = [...ci.columns.values()].sort((a, b) => colRank(a) - colRank(b) || (a.id.startsWith('reg:global') ? -1 : b.id.startsWith('reg:global') ? 1 : 0) ||
        buildingsIn(b) - buildingsIn(a) || cmp(a.label, b.label));
      for (const col of ci.cols) {
        col.rowList = [...col.rows.values()].filter((r) => r.lots.length || r.kind === 'commons')
          .sort((a, b) => rowRank(a) - rowRank(b) || cmp((a.sub && a.sub.attrs.az) || '', (b.sub && b.sub.attrs.az) || '') || cmp(a.label, b.label));
        if (!col.rowList.length) col.rowList = [{ id: 'none', label: '', kind: 'empty', lots: [], items: [], plots: [] }];
      }
    }
    const nBuildings = shown.reduce((t, c) => t + c.cols.reduce((u, col) => u + buildingsIn(col), 0), 0);
    world.stats.buildings = nBuildings;
    if (nBuildings > M.MAX_BUILDINGS) { world.tooBig = true; return world; }

    // ---- local layout of each city
    for (const ci of shown) layoutCity(ci);

    // ---- hub geometry, ring placement of cities, ghosts
    const hubItems = hub.items.filter((e) => e.kind !== 'internet');
    hubItems.forEach((e) => { const ar = C.ARCHETYPES[e.archetype]; e.bw = e.w = ar.w; e.bd = e.d = ar.d; if (e.kind === 'building') { e.lw = ar.w; e.ld = ar.d; } });
    // hub pieces sit on a circle in the gaps between the city spokes; grow the circle until they all fit
    const span = (e) => Math.hypot(e.w, e.d) + 4;              // footprint diagonal + clearance, whatever its rotation
    const GAP = 30;
    const sumW = shown.reduce((t, c) => t + c.W + GAP, 0);
    let rItem = Math.max(26, (hubItems.reduce((t, e) => t + span(e), 0) + shown.length * 14) / (2 * Math.PI));
    let R_HUB, R0, free;
    for (let tries = 0; tries < 12; tries++) {
      R_HUB = rItem + hubItems.reduce((m, e) => Math.max(m, span(e) / 2), 6) + 6;
      R0 = Math.max(R_HUB + 34, sumW / (2 * Math.PI));
      let ang = Math.PI / 2;
      shown.forEach((ci, i) => {
        if (i) ang += ((shown[i - 1].W + GAP) / 2 + (ci.W + GAP) / 2) / R0;
        ci.angle = ang;
      });
      free = fitBetweenSpokes(hubItems.map((e) => span(e) / rItem), shown.map((c) => c.angle), 9 / rItem);
      if (free) break;
      rItem *= 1.2;
    }
    world.R_HUB = R_HUB; world.R0 = R0;
    world.nodes.set('hub', { id: 'hub', x: 0, z: 0, parent: null });
    world.islands.push({ id: 'island:hub', kind: 'hub', shape: 'disc', cx: 0, cz: 0, r: R_HUB, rot: 0, label: 'The capital' });
    free = free || hubItems.map((e, i) => (i * 2 * Math.PI) / Math.max(1, hubItems.length));
    hubItems.forEach((e, i) => {
      const a = free[i];
      const ux = Math.cos(a), uz = Math.sin(a);
      e.cx = ux * rItem; e.cz = uz * rItem;
      e.rot = Math.atan2(-ux, -uz);                    // front faces the centre
      e.cityId = 'hub';
      const acc = `acc:${e.id}`;
      const ra = rItem - Math.max(e.bd || e.d, 6) / 2 - 3;
      world.nodes.set(acc, { id: acc, x: ux * ra, z: uz * ra, parent: 'hub', kind: 'drive', width: 2.5 });
      e.access = acc; e.front = [ux * (rItem - (e.bd || e.d) / 2), uz * (rItem - (e.bd || e.d) / 2)];
      if (e.floors) e.floors.forEach((f, j) => { Object.assign(f, { cx: e.cx, cz: e.cz, rot: e.rot, w: 13, d: 13, h: C.ARCHETYPES.floor.h * 0.92, y0: 3 + j * C.ARCHETYPES.floor.h, access: acc, front: e.front, cityId: 'hub' }); });
      if (e.people) {
        const per = Math.ceil(Math.sqrt(e.people.length));
        e.people.forEach((p, j) => {
          const lx = ((j % per) - (per - 1) / 2) * 1.6, lz = -(e.bd / 2) - 1.5 - Math.floor(j / per) * 1.6;
          const c = Math.cos(e.rot), s = Math.sin(e.rot);
          Object.assign(p, { cx: e.cx + lx * c + lz * s, cz: e.cz - lx * s + lz * c, rot: e.rot, w: 0.9, d: 0.9, h: 1.8, access: acc, front: e.front, cityId: 'hub' });
        });
      }
    });
    internet.cx = 0; internet.cz = 0; internet.access = 'hub'; internet.front = [0, 0]; internet.cityId = 'hub'; internet.w = internet.d = 16;
    world.labels.push({ id: 'lbl:hub', text: 'The capital', sub: 'Internet · identity · directory', x: 0, y: 2, z: -R_HUB + 6, kind: 'city', pri: 2, entId: 'internet' });

    for (const ci of shown) placeCity(world, ci, R0, addEnt);

    // ghost towns on an outer arc on the left
    if (world.ghosts.length) {
      const maxD = shown.reduce((m, c) => Math.max(m, c.D), 0);
      const Rg = R0 + maxD + 46;
      const step = 20 / Rg;
      let allDefault = true;
      world.ghosts.forEach((g, i) => {
        const a = Math.PI + (i - (world.ghosts.length - 1) / 2) * step;
        const here = ctx.res.filter((r) => regionCityId(r) === g.id);
        const terrain = here.filter((r) => C.TERRAIN.has(r.type));
        const vpcs = terrain.filter((r) => r.type === 'ec2:vpc');
        const hidden = here.filter((r) => !C.TERRAIN.has(r.type) && !visible(r, opts)).length;
        // "only the default network" is a claim: every network is a default one, no network card is in use, no layer hides anything
        const defaultOnly = vpcs.length > 0 && vpcs.every((v) => (v.attrs || {}).is_default) && !terrain.some((r) => r.type === 'ec2:eni') && !hidden;
        allDefault = allDefault && defaultOnly;
        const fs = terrain.flatMap(findingsOf);
        const e = newEnt('ghost:' + g.id, 'ghost', 'plot', { name: g.name, cx: Math.cos(a) * Rg, cz: Math.sin(a) * Rg, w: 13, d: 13, h: 0.6,
          rot: Math.atan2(-Math.cos(a), -Math.sin(a)), cityId: g.id, members: terrain.map((r) => r.key), findings: fs, sev: worst(fs),
          vpcs: vpcs.length, subnets: terrain.filter((r) => r.type === 'ec2:subnet').length, defaultOnly, hidden,
          custom: vpcs.filter((v) => !(v.attrs || {}).is_default).length });
        world.islands.push({ id: 'island:' + g.id, kind: 'ghost', shape: 'rect', cx: e.cx, cz: e.cz, w: 15, d: 15, rot: e.rot });
        addEnt(e);
      });
      const a0 = Math.PI;
      world.labels.push({ id: 'lbl:ghosts', text: `${world.ghosts.length} quiet region${world.ghosts.length > 1 ? 's' : ''}`, sub: allDefault ? 'only the default network, nothing running' : 'no buildings in this view',
        x: Math.cos(a0) * (Rg + 16), y: 1, z: Math.sin(a0) * (Rg + 16), kind: 'district', pri: 3 });
    }

    // ---- streets as world segments
    for (const nd of world.nodes.values()) {
      if (!nd.parent) continue;
      const p = world.nodes.get(nd.parent);
      world.streets.push({ id: nd.id, x1: nd.x, z1: nd.z, x2: p.x, z2: p.z, width: nd.width || 3.5, kind: nd.kind || 'street' });
    }

    routeAll(world, graph, ctx);
    bounds(world, shown);
    world.cities = shown;
    world.stats.cities = shown.length;
    world.stats.ghosts = world.ghosts.length;
    world.stats.flows = world.flows.length;
    world.stats.cars = world.flows.reduce((t, f) => t + f.cars, 0);
    world.stats.unknown = world.flows.filter((f) => f.status === 'unknown').length;
    world.hiddenSummary = hiddenSummary(ctx, opts);
    return world;
  }

  /** Angles for items of the given angular widths in the gaps between spokes (each spoke keeps `margin` on both sides).
      Items fill the gaps in order, starting from the gap opposite the first spoke. Returns null when they do not fit. */
  function fitBetweenSpokes(widths, spokes, margin) {
    const TWO = 2 * Math.PI;
    const norm = (a) => ((a % TWO) + TWO) % TWO;
    const s = spokes.map(norm).sort((a, b) => a - b);
    const gaps = [];
    if (!s.length) gaps.push([norm(-Math.PI / 2 + Math.PI / 4), norm(-Math.PI / 2 + Math.PI / 4) + TWO]);
    else s.forEach((a, i) => gaps.push([a + margin, (i + 1 < s.length ? s[i + 1] : s[0] + TWO) - margin]));
    // start in the widest gap, then go round
    let first = 0;
    gaps.forEach((g, i) => { if (g[1] - g[0] > gaps[first][1] - gaps[first][0]) first = i; });
    const order = gaps.slice(first).concat(gaps.slice(0, first));
    const out = [];
    let gi = 0, cur = order.length ? order[0][0] : 0;
    for (const w of widths) {
      while (gi < order.length && cur + w > order[gi][1]) { gi++; if (gi < order.length) cur = order[gi][0]; }
      if (gi >= order.length) return null;
      out.push(cur + w / 2);
      cur += w;
    }
    // spread what is left of each gap evenly so pieces do not huddle at one end
    return out;
  }

  function hiddenSummary(ctx, opts) {
    const out = {};
    for (const r of ctx.res) {
      if (C.TERRAIN.has(r.type) || visible(r, opts)) continue;
      const k = r.type === 'logs:log-group' ? 'logs' : r.type.startsWith('other:') ? 'other' : r.type.startsWith('iam:') ? 'iam' : 'other';
      out[k] = (out[k] || 0) + 1;
    }
    return out;
  }

  function layoutCity(ci) {
    let x = MARGIN;
    let maxD = 0;
    for (const col of ci.cols) {
      const lots = col.rowList.flatMap((r) => r.lots);
      const area = lots.reduce((t, l) => t + (l.lw + LOT_GAP) * (l.ld + STREET + 2), 0);
      const maxW = lots.reduce((m, l) => Math.max(m, l.lw), 0);
      const inner = Math.max(maxW, 22, Math.min(170, Math.ceil(1.2 * Math.sqrt(area))));
      col.x = x; col.inner = inner; col.w = AVENUE + 1.5 + inner + 1.5;
      let z = BOULEVARD + 2;
      for (const row of col.rowList) {
        row.z = z;
        row.lines = [];
        let cur = [], cx = 0;
        for (const l of row.lots) {
          if (cur.length && cx + l.lw > inner) { row.lines.push(cur); cur = []; cx = 0; }
          cur.push(l); cx += l.lw + LOT_GAP;
        }
        if (cur.length || !row.lines.length) row.lines.push(cur);
        row.lineGeo = row.lines.map((ls) => {
          const g = { z, street: z + STREET / 2, lots: ls };
          const d = STREET + 0.8 + (ls.length ? Math.max(...ls.map((l) => l.ld)) : 6) + LINE_GAP;
          let lx = col.x + AVENUE + 1.5;
          for (const l of ls) { l.x0 = lx; l.z0 = z + STREET + 0.8; lx += l.lw + LOT_GAP; }
          z += d;
          return g;
        });
        row.d = z - row.z;
        z += ROW_GAP;
      }
      col.d = z - (BOULEVARD + 2);
      maxD = Math.max(maxD, col.d);
      x += col.w + COL_GAP;
    }
    ci.W = Math.max(x - COL_GAP + MARGIN, 40);
    ci.D = BOULEVARD + 2 + maxD + MARGIN;
  }

  /** Place a city on the ring: local (x, z) -> world, with its front (z = 0) facing the hub. */
  function placeCity(world, ci, R0, addEnt) {
    const a = ci.angle, ux = Math.cos(a), uz = Math.sin(a), tx = Math.sin(a), tz = -Math.cos(a);
    const rot = Math.atan2(Math.cos(a), Math.sin(a));
    const W = ci.W;
    const P = (x, z) => [ux * (R0 + z) + tx * (x - W / 2), uz * (R0 + z) + tz * (x - W / 2)];
    const node = (id, x, z, parent, kind, width) => { const [wx, wz] = P(x, z); world.nodes.set(id, { id, x: wx, z: wz, parent, kind, width, cityId: ci.id }); return id; };
    const id = ci.id;
    ci.rot = rot; ci.P = P;
    const [cx, cz] = P(W / 2, ci.D / 2);
    world.islands.push({ id: 'island:' + id, kind: ci.kind, shape: 'rect', cx, cz, w: W + 6, d: ci.D + 6, rot, cityId: id, label: ci.name });
    // spoke from the hub to the city gate (a bridge over the water)
    const spoke = `${id}:spoke`;
    world.nodes.set(spoke, { id: spoke, x: ux * (world.R_HUB - 4), z: uz * (world.R_HUB - 4), parent: 'hub', kind: 'spoke', width: 6 });
    const gate = node(`${id}:gate`, W / 2, -1, spoke, 'bridge', 6);
    const bmid = node(`${id}:bmid`, W / 2, BOULEVARD / 2, gate, 'boulevard', 6);
    const [lx, lz] = P(W / 2, -4);
    world.labels.push({ id: 'lbl:' + id, text: ci.name, sub: cityKindText(ci), x: lx, y: 3, z: lz, kind: 'city', pri: 1, cityId: id });
    const dirCity = { id, label: ci.name, kind: ci.kind, children: [] };
    world.directory.push(dirCity);

    // boulevard nodes at each column's avenue, chained towards the middle
    const bnodes = ci.cols.map((col) => ({ col, x: col.x + AVENUE / 2 }));
    const left = bnodes.filter((b) => b.x < W / 2).sort((p, q) => q.x - p.x);
    const right = bnodes.filter((b) => b.x >= W / 2).sort((p, q) => p.x - q.x);
    for (const side of [left, right]) {
      let parent = bmid;
      for (const b of side) { b.id = node(`${id}:bv:${b.col.id}`, b.x, BOULEVARD / 2, parent, 'boulevard', 6); parent = b.id; }
    }
    world.plates.push(plate(P, rot, 'blvd:' + id, null, 'boulevard', W / 2, BOULEVARD / 2, W - 2, BOULEVARD, 0.06));

    for (const col of ci.cols) {
      const bv = bnodes.find((b) => b.col === col).id;
      const avX = col.x + AVENUE / 2;
      const dirCol = { id: `${id}:${col.id}`, label: col.label, kind: col.kind, children: [] };
      dirCity.children.push(dirCol);
      // district plate (+ wall and gate for private networks)
      const px = col.x + col.w / 2, pz = BOULEVARD + 2 + col.d / 2;
      const dp = plate(P, rot, `district:${id}:${col.id}`, col.vpc ? col.vpc.key : null, col.kind === 'vpc' ? 'district' : col.kind === 'downtown' ? 'downtown' : 'band-col', px, pz, col.w, col.d, 0.12);
      dp.label = col.label; dp.dashed = !!col.dashed; dp.cityId = id;
      world.plates.push(dp);
      if (col.kind === 'vpc') {
        const z0 = BOULEVARD + 2 - 0.6, z1 = BOULEVARD + 2 + col.d + 0.6, x0 = col.x - 0.6, x1 = col.x + col.w + 0.6;
        const gx0 = col.x - 0.2, gx1 = col.x + AVENUE + 0.6;
        const seg = (ax, az, bx, bz) => { const [p1x, p1z] = P(ax, az), [p2x, p2z] = P(bx, bz); world.walls.push({ x1: p1x, z1: p1z, x2: p2x, z2: p2z, h: col.dashed ? 0.7 : 1.6, dashed: !!col.dashed, cityId: id }); };
        seg(gx1, z0, x1, z0); seg(x1, z0, x1, z1); seg(x1, z1, x0, z1); seg(x0, z1, x0, z0);
        if (gx0 > x0) seg(x0, z0, gx0, z0);
        const [gcx, gcz] = P((gx0 + gx1) / 2, z0);
        world.gates.push({ id: `gate:${id}:${col.id}`, cx: gcx, cz: gcz, rot, w: gx1 - gx0, kind: col.igw ? 'igw' : 'door', key: col.igw ? col.igw.key : null, cityId: id });
        const [lbx, lbz] = P(col.x + 1, BOULEVARD + 2 + 0.5);
        world.labels.push({ id: 'lbl:' + dp.id, text: col.label, sub: col.igw ? 'private network · gate to the Internet' : 'private network · no Internet gate', x: lbx, y: 2.5, z: lbz, kind: 'district', pri: 3, cityId: id });
      } else {
        const [lbx, lbz] = P(col.x + 1, BOULEVARD + 2 + 0.5);
        world.labels.push({ id: 'lbl:' + dp.id, text: col.label, sub: '', x: lbx, y: 2, z: lbz, kind: 'district', pri: 3, cityId: id });
      }
      let parent = bv;
      for (const row of col.rowList) {
        const dirRow = { id: `${id}:${col.id}:${row.id}`, label: row.label, kind: row.kind, children: [] };
        if (row.kind !== 'band' || ci.cols.length > 0) dirCol.children.push(dirRow);
        if (row.kind === 'band' && row.lots.length) {
          const bp = plate(P, rot, `band:${id}:${col.id}:${row.id}`, null, 'band', col.x + AVENUE + 1.5 + col.inner / 2, row.z + row.d / 2 - 0.5, col.inner + 1, row.d - 0.6, 0.2);
          bp.cityId = id;
          world.plates.push(bp);
        } else if (row.kind === 'block' || row.kind === 'commons' || row.kind === 'empty') {
          const bp = plate(P, rot, `block:${id}:${col.id}:${row.id}`, row.sub ? row.sub.key : null, row.kind === 'block' ? (row.sub && row.sub.attrs.public_on_launch ? 'block-public' : 'block') : row.kind,
            col.x + AVENUE + 1.5 + col.inner / 2, row.z + row.d / 2 - 0.5, col.inner + 1, row.d - 0.6, 0.2);
          bp.label = row.label; bp.cityId = id;
          world.plates.push(bp);
        }
        if (row.lots.length && row.kind !== 'empty') {
          const [rlx, rlz] = P(col.x + AVENUE + 1.5, row.z + 0.2);
          world.labels.push({ id: `lbl:row:${id}:${col.id}:${row.id}`, text: row.label, sub: row.kind === 'block' ? (row.sub && row.sub.attrs.public_on_launch ? 'public block' : 'private block') + (row.sub && row.sub.attrs.az ? ' · ' + row.sub.attrs.az : '') : '',
            x: rlx, y: 1.2, z: rlz, kind: 'band', pri: 5, cityId: id });
        }
        for (const line of row.lineGeo) {
          const av = node(`${id}:av:${col.id}:${line.z.toFixed(2)}`, avX, line.street, parent, 'avenue', 4.5);
          parent = av;
          let lp = av;
          for (const l of line.lots) {
            const bx = l.x0 + l.bw / 2;
            const acc = node(`${id}:acc:${l.id}`, bx, line.street, lp, 'street', 3.5);
            lp = acc;
            placeLot(world, l, P, rot, acc, id);
            if (l.kind !== 'plot') node(`${id}:drive:${l.id}`, bx, l.z0 - 0.2, acc, 'drive', 1.8);
            addEnt(l);
            l.floors && l.floors.forEach(addEnt);
            dirRow.children.push({ id: l.id, label: l.name, kind: l.kind, archetype: l.archetype });
          }
        }
      }
    }
  }

  function cityKindText(ci) {
    if (ci.kind === 'project') return 'project city';
    if (ci.kind === 'utilities') return 'shared infrastructure';
    if (ci.kind === 'outskirts') return 'resources without a project';
    return 'AWS region';
  }

  function plate(P, rot, id, key, kind, lx, lz, w, d, y) {
    const [cx, cz] = P(lx, lz);
    return { id, key, kind, cx, cz, w, d, rot, y };
  }

  function placeLot(world, l, P, rot, acc, cityId) {
    const bx = l.x0 + l.bw / 2, bz = l.z0 + l.bd / 2;
    [l.cx, l.cz] = P(bx, bz);
    l.rot = rot; l.w = l.bw; l.d = l.bd; l.access = acc; l.cityId = cityId;
    l.front = P(bx, l.z0 - 0.2);
    let si = 0, pi = 0;
    for (const s of l.sats) {
      let sx, sz, w, d, h;
      if (s.kind === 'shed') { w = d = SAT - 0.6; h = 2.2; sx = l.x0 + 1 + (si % 4) * (SAT - 0.3) + w / 2 - 0.5; sz = l.z0 + l.bd + 0.8 + d / 2; si++; }
      else if (s.kind === 'signpost') { w = d = 1.2; h = 3.5; sx = l.x0 + l.bw + 1.6; sz = l.z0 + 1 + pi * 1.8; pi++; }
      else { w = d = 2.4; h = 1.8; const k = (s.idx = (s.idx == null ? l.sats.indexOf(s) : s.idx)); sx = l.x0 + 2 + (k % 2) * (l.bw - 4); sz = l.z0 + 2 + Math.floor(k / 2) % 2 * (l.bd - 4); }
      [s.cx, s.cz] = P(sx, sz);
      s.w = w; s.d = d; s.h = h; s.rot = rot;
    }
    if (l.kind === 'plot') { l.h = 0.3; }
  }

  // =====================================================================================================================
  // 5. Routing on the street tree, traffic, overlays
  // =====================================================================================================================
  function pathNodes(world, a, b) {
    const up = (id) => { const out = []; let n = id; let guard = 0; while (n && guard++ < 4000) { out.push(n); n = world.nodes.get(n) ? world.nodes.get(n).parent : null; } return out; };
    const pa = up(a), pb = up(b);
    const ia = new Map(pa.map((n, i) => [n, i]));
    let j = 0;
    while (j < pb.length && !ia.has(pb[j])) j++;
    if (j >= pb.length) return null;
    return pa.slice(0, ia.get(pb[j]) + 1).concat(pb.slice(0, j).reverse());
  }
  M.pathNodes = pathNodes;

  function routeBetween(world, ea, eb) {
    const ids = pathNodes(world, ea.access, eb.access);
    if (!ids) return null;
    const pts = [ea.front.slice()];
    for (const id of ids) { const n = world.nodes.get(id); pts.push([n.x, n.z]); }
    pts.push(eb.front.slice());
    const clean = [];
    for (const p of pts) { const q = clean[clean.length - 1]; if (!q || Math.hypot(p[0] - q[0], p[1] - q[1]) > 0.05) clean.push(p); }
    let len = 0;
    for (let i = 1; i < clean.length; i++) len += Math.hypot(clean[i][0] - clean[i - 1][0], clean[i][1] - clean[i - 1][1]);
    // segment ids used (child node ids along the path), for asphalt
    const used = [];
    for (let i = 0; i < ids.length - 1; i++) {
      const n = world.nodes.get(ids[i]), m = world.nodes.get(ids[i + 1]);
      used.push(n.parent === m.id ? n.id : m.id);
    }
    return { pts: clean, len, used };
  }

  function routeAll(world, graph, ctx) {
    const entFor = (k) => { const id = k === 'internet' ? 'internet' : world.entOfKey.get(k); return id ? world.byId.get(id) : null; };
    const merged = new Map();
    for (const f of graph.flows) {
      const ea = entFor(f.from), eb = entFor(f.to);
      if (!ea || !eb || ea === eb || !ea.access || !eb.access) continue;
      const spec = C.KINDS[f.kind];
      const car = spec.car || 'car';
      const mk = `${ea.id}>${eb.id}>${car}`;
      if (merged.has(mk)) {
        const m = merged.get(mk);
        m.parts.push(f);
        if (f.rate != null && m.unit === f.unit) { m.rate = (m.rate || 0) + f.rate; if (m.status === 'unknown' || m.status === 'zero') m.status = f.status; }
        m.danger = m.danger || !!f.danger;
        continue;
      }
      merged.set(mk, { id: 'flow:' + mk, from: ea.id, to: eb.id, kind: f.kind, car, rate: f.rate, unit: f.unit, status: f.status, basis: f.basis,
        danger: !!f.danger, door: f.door, parked: f.parked, label: f.label, parts: [f] });
    }
    const usedSeg = new Map();
    for (const fl of [...merged.values()].sort((a, b) => cmp(a.id, b.id))) {
      const r = routeBetween(world, world.byId.get(fl.from), world.byId.get(fl.to));
      if (!r) continue;
      Object.assign(fl, r);
      const moving = (fl.status === 'measured' || fl.status === 'estimated') && fl.rate > 0;
      fl.cps = moving ? M.carsPerSecond(fl.rate, fl.unit) : fl.status === 'unknown' ? 0.03 : 0;
      fl.cars = moving ? Math.max(1, Math.round(fl.cps * fl.len / CAR_SPEED)) : fl.status === 'unknown' ? 1 : 0;
      for (const s of fl.used) usedSeg.set(s, (usedSeg.get(s) || 0) + (moving ? reqEq(fl.rate, fl.unit) : 0) + 1e-6);
      world.flows.push(fl);
    }
    // global car budget
    let total = world.flows.reduce((t, f) => t + f.cars, 0);
    if (total > M.MAX_CARS) {
      const k = M.MAX_CARS / total;
      world.flows.forEach((f) => { if (f.cars) f.cars = Math.max(1, Math.floor(f.cars * k)); });
      total = world.flows.reduce((t, f) => t + f.cars, 0);
      world.carsScaled = true;
    }
    world.streets.forEach((s) => { const u = usedSeg.get(s.id); s.used = u != null; s.load = u || 0; });

    // overlays (footpaths, badge beams, firewall permissions, guesses)
    const seen = new Set();
    for (const o of graph.overlays) {
      const ea = entFor(o.from), eb = entFor(o.to);
      if (!ea || !eb || ea === eb) continue;
      const id = `ov:${ea.id}>${eb.id}>${o.kind}`;
      if (seen.has(id)) continue;
      seen.add(id);
      world.overlays.push({ id, from: ea.id, to: eb.id, kind: o.kind, label: o.label, score: o.score });
    }
  }

  function bounds(world, shown) {
    let x0 = -world.R_HUB, x1 = world.R_HUB, z0 = -world.R_HUB, z1 = world.R_HUB;
    const grow = (x, z, r) => { x0 = Math.min(x0, x - r); x1 = Math.max(x1, x + r); z0 = Math.min(z0, z - r); z1 = Math.max(z1, z + r); };
    for (const i of world.islands) grow(i.cx, i.cz, i.shape === 'disc' ? i.r : Math.hypot(i.w, i.d) / 2);
    world.bounds = { x0, x1, z0, z1, cx: (x0 + x1) / 2, cz: (z0 + z1) / 2, r: Math.hypot(x1 - x0, z1 - z0) / 2 };
    const first = shown[0];
    if (first) {
      // start between the capital and the first city, looking at the city's front over the capital
      const [fx, fz] = first.P(first.W / 2, first.D * 0.4);
      const tx = fx * 0.72, tz = fz * 0.72;
      const r = Math.max(world.R_HUB + 10, Math.max(first.W, first.D) * 0.55 + world.R_HUB * 0.35);
      world.view0 = { x: tx, z: tz, r, azimuth: Math.atan2(-Math.cos(first.angle), -Math.sin(first.angle)) };
    } else world.view0 = { x: 0, z: 0, r: world.R_HUB + 30, azimuth: Math.PI };
  }

  // =====================================================================================================================
  // 6. Stories: plain-language explanations, connections as sentences, "follow a request"
  // =====================================================================================================================
  const fmtRate = (rate, unit) => {
    if (rate == null) return 'unknown traffic';
    if (unit === 'bytes') {
      const u = ['B', 'kB', 'MB', 'GB', 'TB'];
      let v = rate, i = 0;
      while (v >= 1000 && i < u.length - 1) { v /= 1000; i++; }
      return `≈ ${v >= 10 ? Math.round(v) : v.toFixed(1)} ${u[i]}/day`;
    }
    const v = rate >= 1e6 ? (rate / 1e6).toFixed(rate >= 1e7 ? 0 : 1) + 'M' : rate >= 1e3 ? (rate / 1e3).toFixed(rate >= 1e4 ? 0 : 1) + 'k' : rate >= 10 ? Math.round(rate) : rate.toFixed(1);
    return `≈ ${v} ${unit || ''}/day`.replace(' /day', '/day');
  };
  M.fmtRate = fmtRate;
  const STATUS_TEXT = { measured: 'measured', estimated: 'estimated', zero: 'measured: nothing passed', unknown: 'not measured', parked: 'waiting' };
  M.STATUS_TEXT = STATUS_TEXT;

  function entTitle(world, id) { const e = world.byId.get(id); return e ? (e.kind === 'internet' ? 'the Internet' : `“${e.name}”`) : id; }
  function archName(e) { return (C.ARCHETYPES[e.archetype] || C.ARCHETYPES.unknown).name; }

  M.story = function story(world, id) {
    const e = world.byId.get(id);
    if (!e) return null;
    const ar = C.ARCHETYPES[e.archetype] || C.ARCHETYPES.unknown;
    const out = { id, title: e.name, city: archName(e), what: ar.what, lines: [], warnings: [], key: e.key, kind: e.kind };
    if (e.kind === 'internet') { out.what = ar.what; }
    if (e.kind === 'ghost') {
      out.city = 'Quiet region';
      const net = `${e.vpcs} network${e.vpcs === 1 ? '' : 's'}, ${e.subnets} subnet${e.subnets === 1 ? '' : 's'}`;
      out.what = e.defaultOnly ? `AWS region ${e.name}: only the default network AWS creates for you (${net}). Nothing is running here. Default networks are free.`
        : `AWS region ${e.name}: no buildings in this view (${net}).` +
          (e.custom ? ` ${e.custom === 1 ? 'One network was' : `${e.custom} networks were`} created by someone (not the default one).` : '') +
          (e.hidden ? ` ${e.hidden} resource${e.hidden === 1 ? ' is' : 's are'} hidden by the layers (see Layers).` : '');
    }
    if (world.opts.height === 'size' && e.sizeless && e.kind === 'building') out.lines.push('Height: this kind of resource has no stored-data size, so it keeps its base height.');
    if (e.kind === 'hq') out.lines.push(`${e.floors.length} office${e.floors.length === 1 ? '' : 's'} (IAM roles); ${e.floors.filter((f) => f.dormant).length} dark (not used in 90 days).`);
    if (e.kind === 'badges') out.lines.push(`${e.people.length} badge holder${e.people.length === 1 ? '' : 's'} (IAM users).`);
    if (e.kind === 'stack' || e.kind === 'yard') out.members = e.members.slice();
    if (e.res) {
      const r = e.res;
      out.aws = { type: typeLabel(r.type), name: nameOf(r), region: r.region, project: r.project, state: r.state, cost: r.est_monthly_usd || 0 };
    }
    if (e.cost && !e.res) out.aws = { type: archName(e), cost: e.cost };
    if (e.floors) out.aws = { type: 'IAM', cost: 0 };
    for (const s of e.sats || []) {
      const label = s.kind === 'shed' ? 'Storage shed (disk)' : s.kind === 'signpost' ? 'Street address (Elastic IP)' : 'Dispatch kiosk (target group)';
      out.lines.push(`${label}: “${s.name}”${s.vacant ? ' — unused' : ''}.`);
    }
    if (e.door) out.warnings.push(`Its firewall (security group) lets the whole Internet in on ${e.door}.`);
    if (e.stopped) out.lines.push('Stopped: the lights are off, but disks and addresses still cost money.');
    if (e.vacant) out.warnings.push(`Flagged as unused${e.coin ? `: about $${e.coin.toFixed(0)}/month could be saved` : ''}.`);
    for (const f of world.flows) {
      if (f.from !== id && f.to !== id) continue;
      const other = entTitle(world, f.from === id ? f.to : f.from);
      const spec = C.KINDS[f.kind] || {};
      const rate = f.status === 'parked' ? `${f.parked} waiting` : f.status === 'unknown' ? 'traffic not measured' : f.status === 'zero' ? 'no traffic in the measured period' : `${fmtRate(f.rate, f.unit)}, ${STATUS_TEXT[f.status]}`;
      if (f.from === id) out.lines.push(`${cap(spec.text || 'connects to')} ${other} (${rate}).`);
      else out.lines.push(`${f.from === 'internet' ? 'Visitors arrive from the Internet' : `${other} ${spec.text || 'connects to'} it`} (${rate}).${f.danger ? ' ⚠ open to everyone.' : ''}`);
    }
    for (const o of world.overlays) {
      if (o.from !== id && o.to !== id) continue;
      const other = entTitle(world, o.from === id ? o.to : o.from);
      if (o.kind === 'uses-role') out.lines.push(o.from === id ? `Borrows the badge (IAM role) ${other}.` : `Its badge is used by ${other}.`);
      else if (o.kind === 'dns') out.lines.push(o.from === id ? `Directory entry${o.label ? ` “${o.label}”` : ''} points to ${other}.` : `Listed in the directory ${other}${o.label ? ` as “${o.label}”` : ''}.`);
      else if (o.kind === 'may-connect') out.lines.push(o.from === id ? `Its firewall lets it reach ${other}${o.label ? ` on ${o.label}` : ''} (allowed, not observed).` : `${cap(other)} is allowed through its firewall${o.label ? ` on ${o.label}` : ''} (allowed, not observed).`);
      else if (o.kind === 'likely') out.lines.push(`${o.from === id ? `Probably talks to ${other}` : `${cap(other)} probably talks to it`}. ${o.label}.`);
    }
    if (e.floors) {
      const users = new Map();
      for (const o of world.overlays) if (o.kind === 'uses-role') { const f = world.byId.get(o.to); if (f && f.parent === e.id) users.set(o.to, (users.get(o.to) || 0) + 1); }
      out.lines.push(`${users.size} of its offices are borrowed by buildings in this view.`);
    }
    return out;
  };
  const cap = (s) => (s ? s.charAt(0).toUpperCase() + s.slice(1) : s);

  /** The path of one visitor through the city to (and beyond) a building: steps + polyline. */
  M.requestPath = function requestPath(world, id) {
    const target = world.byId.get(id);
    if (!target) return null;
    const into = new Map(), outOf = new Map();
    for (const f of world.flows) {
      if (f.status === 'parked') continue;
      if (!into.has(f.to)) into.set(f.to, []);
      into.get(f.to).push(f);
      if (!outOf.has(f.from)) outOf.set(f.from, []);
      outOf.get(f.from).push(f);
    }
    const better = (a, b) => (b.rate || 0) - (a.rate || 0) || cmp(a.id, b.id);
    // backwards BFS to the Internet (or the furthest upstream node)
    const prev = new Map([[id, null]]);
    const q = [id];
    let found = null, last = id;
    while (q.length && !found) {
      const n = q.shift();
      last = n;
      for (const f of (into.get(n) || []).slice().sort(better)) {
        if (prev.has(f.from)) continue;
        prev.set(f.from, f);
        if (f.from === 'internet') { found = f.from; break; }
        q.push(f.from);
      }
    }
    const back = [];
    let cur = found || last;
    while (cur && cur !== id) { const f = prev.get(cur); if (!f) break; back.push(f); cur = f.to; }
    const steps = back.slice(0, 8);
    // forward along the busiest road
    const seen = new Set([id, ...steps.map((f) => f.from)]);
    let n = id;
    while (steps.length < 8) {
      const next = (outOf.get(n) || []).filter((f) => !seen.has(f.to) && f.kind !== 'internet-out' && (f.kind !== 'egress-via' || n === id)).sort(better)[0];
      if (!next) break;
      steps.push(next); seen.add(next.to); n = next.to;
    }
    if (!steps.length) return { steps: [], pts: [], text: [`Nothing in this view sends traffic to ${entTitle(world, id)}.`] };
    const pts = [];
    const text = [];
    steps.forEach((f, i) => {
      const spec = C.KINDS[f.kind] || {};
      const r = f.status === 'unknown' ? 'not measured' : f.status === 'zero' ? 'none measured' : `${fmtRate(f.rate, f.unit)}, ${STATUS_TEXT[f.status]}`;
      const head = i === 0 ? (f.from === 'internet' ? 'A visitor arrives from the Internet' : `It starts at ${entTitle(world, f.from)}`) : `${cap(entTitle(world, f.from))}`;
      text.push(`${head} → ${spec.text || 'goes to'} ${archName(world.byId.get(f.to)).toLowerCase()} ${entTitle(world, f.to)} (${r}).`);
      for (const p of f.pts) { const q2 = pts[pts.length - 1]; if (!q2 || q2[0] !== p[0] || q2[1] !== p[1]) pts.push(p); }
    });
    return { steps: steps.map((f) => ({ flow: f.id, from: f.from, to: f.to })), pts, text, reachedInternet: !!found };
  };

  /** Where to show a resource: {id} (a building, or the building it belongs to), {plate} (a district or block of land),
      each with an optional `note` saying what was shown instead, or only {note, layer?, mode?} when it is not on the map. */
  M.locate = function locate(world, k) {
    const ctx = makeCtx([], {});
    const r = ctx.all.get(k);
    const own = world.entOfKey.get(k);
    if (own) return { id: own };
    if (!r) return { note: 'This resource is not part of the current analysis.' };
    const nm = `“${nameOf(r)}”`;
    const plate = world.plates.find((p) => p.key === k);
    if (plate) return { plate };
    if (r.type === 'logs:log-group' && !world.opts.logs) return { note: `${nm} is a log group, hidden by default.`, layer: 'logs' };
    if (r.type.startsWith('other:') && !world.opts.other) return { note: `${nm} is known only from its tags, hidden by default.`, layer: 'other' };
    if (r.type.startsWith('iam:') && world.opts.iam === false) return { note: `${nm} is an IAM identity, hidden by the layers.`, layer: 'iam' };
    if (r.type === 'ec2:eni') {
      const o = eniOwner(ctx, r);
      const id = o && world.entOfKey.get(o.key);
      if (id) return { id, note: `${nm} is a network card of “${nameOf(o)}”; showing that building.` };
    }
    if (r.type === 'ec2:security-group') {
      const ids = [...new Set([...ctx.all.values()].filter((x) => sgsOf(ctx, x).includes(r)).map((x) => world.entOfKey.get(x.key)).filter(Boolean))].sort();
      if (ids.length) {
        return { id: ids[0], note: `${nm} is a firewall (security group), not a building. It protects ${ids.length} building${ids.length === 1 ? '' : 's'} in this view` +
          (ids.length === 1 ? '; showing it.' : `; showing “${world.byId.get(ids[0]).name}”. The Security layer draws what it allows.`) };
      }
      return { note: `${nm} is a firewall (security group); nothing in this view uses it.` };
    }
    if (r.type === 'ec2:igw') {
      for (const v of (r.attrs || {}).vpcs || []) {
        const p = world.plates.find((x) => x.key === key(r, 'ec2:vpc', v));
        if (p) return { plate: p, note: `${nm} is the gate of this private network.` };
      }
    }
    if (C.TERRAIN.has(r.type)) {
      return world.mode === 'network' ? { note: `${nm} is part of the land (network), not a building, and has no place in this view.` }
        : { note: `${nm} is part of the land (network), not a building.`, mode: 'network' };
    }
    return { note: `${nm} is not drawn in this view.` };
  };

  M.build = build;
  M.const = { STREET, AVENUE, BOULEVARD, SAT };
})();
