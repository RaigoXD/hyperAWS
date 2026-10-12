// Invariants of the pure 3D-map model (viewer/js/city-model.js), run by tests/test_city_model.py.
// Reads the demo analysis JSON on stdin and prints {"failures": [...], "stats": {...}} on stdout.
'use strict';
const { load } = require('./load.js');

const failures = [];
const check = (cond, msg) => { if (!cond) failures.push(msg); };
let realLikeData = null;

// ---- geometry helpers --------------------------------------------------------------------------------------------------
function corners(cx, cz, w, d, rot) {
  const c = Math.cos(rot), s = Math.sin(rot);
  return [[-w / 2, -d / 2], [w / 2, -d / 2], [w / 2, d / 2], [-w / 2, d / 2]].map(([x, z]) => [cx + x * c + z * s, cz - x * s + z * c]);
}
function overlap(a, b) {        // separating axis test for two rotated rectangles (corner lists)
  for (const poly of [a, b]) {
    for (let i = 0; i < 4; i++) {
      const p = poly[i], q = poly[(i + 1) % 4];
      const nx = -(q[1] - p[1]), nz = q[0] - p[0];
      const pa = a.map((v) => v[0] * nx + v[1] * nz), pb = b.map((v) => v[0] * nx + v[1] * nz);
      if (Math.max(...pa) <= Math.min(...pb) + 1e-6 || Math.max(...pb) <= Math.min(...pa) + 1e-6) return false;
    }
  }
  return true;
}
const shrink = (e, k) => corners(e.cx, e.cz, e.w * k, e.d * k, e.rot || 0);
const project = (w) => JSON.stringify({
  ents: w.ents.map((e) => [e.id, +e.cx.toFixed(3), +e.cz.toFixed(3), +(e.h || 0).toFixed(3)]).sort(),
  flows: w.flows.map((f) => [f.id, f.status, f.cars, f.rate == null ? null : +f.rate.toFixed(3)]).sort(),
  overlays: w.overlays.map((o) => o.id).sort(),
});

function invariants(A, label, res, opts) {
  const w = A.city.build(res, opts);
  const tag = `${label}/${opts.mode}`;
  check(!w.tooBig, `${tag}: unexpectedly too big`);
  // determinism, also with the input shuffled
  const again = A.city.build(res.slice().reverse(), opts);
  check(project(w) === project(again), `${tag}: build is not deterministic (input order changed the world)`);
  // every visible resource is somewhere (building, satellite, block member, office...)
  const C = A.cityCatalog;
  for (const r of res) {
    if (C.TERRAIN.has(r.type)) continue;
    if (r.type === 'logs:log-group' && !opts.logs) continue;
    if (r.type.startsWith('other:') && !opts.other) continue;
    check(w.entOfKey.has(r.key), `${tag}: ${r.key} is missing from the city`);
  }
  // buildings never overlap each other (lots are shrunk a little: neighbours may touch)
  const solids = w.ents.filter((e) => ['building', 'stack', 'yard', 'plot', 'hq', 'badges'].includes(e.kind));
  for (let i = 0; i < solids.length; i++) {
    for (let j = i + 1; j < solids.length; j++) {
      if (overlap(shrink(solids[i], 0.95), shrink(solids[j], 0.95))) failures.push(`${tag}: ${solids[i].id} overlaps ${solids[j].id}`);
    }
  }
  // islands (cities, the capital, quiet regions) never overlap
  const isl = w.islands.map((i) => (i.shape === 'disc' ? corners(i.cx, i.cz, i.r * 1.6, i.r * 1.6, 0) : corners(i.cx, i.cz, i.w, i.d, i.rot)));
  for (let i = 0; i < isl.length; i++) for (let j = i + 1; j < isl.length; j++) check(!overlap(isl[i], isl[j]), `${tag}: islands ${w.islands[i].id} and ${w.islands[j].id} overlap`);
  // routes are real polylines; traffic states are the four honest ones; the car budget holds
  for (const f of w.flows) {
    check(f.pts && f.pts.length >= 2 && f.pts.every((p) => Number.isFinite(p[0]) && Number.isFinite(p[1])), `${tag}: bad route ${f.id}`);
    check(f.len > 0, `${tag}: zero-length route ${f.id}`);
    check(['measured', 'estimated', 'zero', 'unknown', 'parked'].includes(f.status), `${tag}: odd status ${f.status}`);
    if (f.status === 'unknown') check(f.rate == null, `${tag}: unknown traffic with a rate ${f.id}`);
    if (f.status === 'zero') check(f.rate === 0 && f.cars === 0, `${tag}: zero traffic with cars ${f.id}`);
  }
  check(w.flows.reduce((t, f) => t + f.cars, 0) <= A.city.MAX_CARS, `${tag}: car budget exceeded`);
  for (const e of w.ents) check(Number.isFinite(e.cx) && Number.isFinite(e.cz), `${tag}: ${e.id} has no position`);
  return w;
}

// ---- a small account shaped like the user's real one: one workload + 16 regions with only the default network -------------
function realLike() {
  const acct = '111122223333';
  const res = [];
  const R = (region, type, rid, extra) => {
    const r = Object.assign({ key: `${acct}:${region}:${type}:${rid}`, rid, type, account: acct, region, name: rid, state: '', tags: {}, attrs: {}, relations: [], metrics: {},
      project: 'Unassigned', env: '', est_monthly_usd: 0, findings: [] }, extra || {});
    res.push(r);
    return r;
  };
  const regions = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ca-central-1', 'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1', 'eu-north-1',
    'ap-south-1', 'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3', 'ap-southeast-1', 'ap-southeast-2', 'sa-east-1'];
  for (const reg of regions) {
    R(reg, 'ec2:vpc', `vpc-${reg}`, { attrs: { is_default: true }, project: '(shared infrastructure)' });
    for (const az of ['a', 'b', 'c']) R(reg, 'ec2:subnet', `subnet-${reg}-${az}`, { attrs: { vpc: `vpc-${reg}`, az: reg + az, public_on_launch: true }, project: '(shared infrastructure)' });
    R(reg, 'ec2:igw', `igw-${reg}`, { attrs: { vpcs: [`vpc-${reg}`] }, project: '(shared infrastructure)' });
  }
  const reg = 'us-east-1', V = `vpc-${reg}`, S = `subnet-${reg}-a`;
  R(reg, 'ec2:security-group', 'sg-db', { attrs: { vpc: V, world_open: [['tcp', 5432, 5432]] }, project: '(shared infrastructure)' });
  R(reg, 'ec2:security-group', 'sg-alb', { attrs: { vpc: V, world_open: [['-1', null, null]] }, project: '(shared infrastructure)' });
  R(reg, 'elbv2:lb', 'shop-alb', { attrs: { scheme: 'internet-facing', vpc: V, subnet_ids: [S], sg_ids: ['sg-alb'] }, metrics: { requests: 140, _days: { requests: 14 } }, project: 'shop', est_monthly_usd: 16 });
  R(reg, 'elbv2:target-group', 'shop-tg', { attrs: { vpc: V }, relations: [{ to: `${acct}:${reg}:elbv2:lb:shop-alb`, kind: 'behind' }], project: 'shop' });
  R(reg, 'ecs:cluster', 'shop', { project: 'shop' });
  R(reg, 'ecs:service', 'shop-backend', { attrs: { subnet_ids: [S], sg_ids: [], running: 1 }, project: 'shop', est_monthly_usd: 9, env: 'prod',
    relations: [{ to: `${acct}:${reg}:elbv2:target-group:shop-tg`, kind: 'serves' }, { to: `${acct}:${reg}:ecs:cluster:shop`, kind: 'in-cluster' }] });
  R(reg, 'rds:instance', 'shop-database', { attrs: { vpc: V, public: true, sg_ids: ['sg-db'] }, project: 'Unassigned', env: 'prod', est_monthly_usd: 15, state: 'available',
    relations: [{ to: `${acct}:${reg}:ec2:security-group:sg-db`, kind: 'uses-sg' }] });
  R(reg, 'ec2:instance', 'i-vision', { name: 'vision-server', attrs: { subnet: S, vpc: V, public_ip: '3.3.3.3' }, state: 'running', metrics: { net_in: 1.4e9, _days: { net_in: 14 } }, est_monthly_usd: 30 });
  R(reg, 'ec2:eip', 'eipalloc-1', { state: 'associated', attrs: { instance_id: 'i-vision', public_ip: '3.3.3.3' }, relations: [{ to: `${acct}:${reg}:ec2:instance:i-vision`, kind: 'associated-with' }] });
  R(reg, 'ec2:volume', 'vol-1', { state: 'in-use', relations: [{ to: `${acct}:${reg}:ec2:instance:i-vision`, kind: 'attached-to' }] });
  R('global', 'cloudfront:distribution', 'E1', { state: 'enabled', metrics: { requests: 0, _days: { requests: 30 } } });
  R('global', 'iam:role', 'shop-task-role', { attrs: { last_used: null }, project: '(shared infrastructure)' });
  return { analyzed_at: 'x', scanned_at: '2026-10-10T00:00:00Z', resources: res, findings: [], projects: [], summary: {}, accounts: [{ account: acct }] };
}

// ---- small accounts for the honesty rules of the traffic model ------------------------------------------------------------
const H = '777788889999';
function account(list) {
  const res = list.map(([region, type, rid, extra]) => Object.assign({ key: `${H}:${region}:${type}:${rid}`, rid, type, account: H, region, name: rid, state: '',
    tags: {}, attrs: {}, relations: [], metrics: {}, project: 'Unassigned', env: '', est_monthly_usd: 0, findings: [] }, extra || {}));
  return { analyzed_at: 'h', scanned_at: '2026-10-10T00:00:00Z', resources: res, findings: [], projects: [], summary: {}, accounts: [{ account: H }] };
}
const hk = (region, type, rid) => `${H}:${region}:${type}:${rid}`;
const per = (n, metric, days) => ({ [metric]: n, _days: { [metric]: days } });
function road(w, from, to) { return w.flows.find((f) => f.from === from && f.to === to) || null; }

function honesty() {
  const E = 'us-east-1';
  let A = load(account([
    [E, 'apigw:rest-api', 'privapi', { attrs: { endpoint_types: ['PRIVATE'] }, metrics: per(3000, 'requests', 30) }],
    [E, 'apigw:rest-api', 'pubapi', { attrs: { endpoint_types: ['REGIONAL'] }, metrics: per(3000, 'requests', 30) }],
    [E, 'ec2:nat-gateway', 'nat-priv', { state: 'available', attrs: { connectivity: 'private' }, metrics: { bytes_in: 14e9, bytes_return: 14e9, _days: { bytes_in: 14, bytes_return: 14 } } }],
  ]));
  let w = A.city.build(A.res, { mode: 'project' });
  check(!road(w, 'internet', hk(E, 'apigw:rest-api', 'privapi')), 'honesty: a PRIVATE REST API must not get a road from the Internet');
  check(!!road(w, 'internet', hk(E, 'apigw:rest-api', 'pubapi')), 'honesty: a REGIONAL REST API keeps its road from the Internet');
  check(!w.flows.some((f) => f.kind === 'internet-out'), 'honesty: a private NAT gateway has no road to the Internet');

  // egress roads never take the sender's own metric; an idle NAT means nothing drove out through it
  const sub = (rid, nat) => [E, 'ec2:subnet', rid, { attrs: { vpc: 'vpc-1' }, relations: [{ to: hk(E, 'ec2:nat-gateway', nat), kind: 'egress-via' }] }];
  A = load(account([
    [E, 'ec2:vpc', 'vpc-1', {}], sub('sub-a', 'nat-idle'), sub('sub-b', 'nat-busy'),
    [E, 'ec2:nat-gateway', 'nat-idle', { state: 'available', metrics: { bytes_in: 0, bytes_return: 0, _days: { bytes_in: 14, bytes_return: 14 } } }],
    [E, 'ec2:nat-gateway', 'nat-busy', { state: 'available', metrics: { bytes_in: 10e9, bytes_return: 4e9, _days: { bytes_in: 14, bytes_return: 14 } } }],
    [E, 'ec2:instance', 'i-idle', { state: 'running', attrs: { subnet: 'sub-a', vpc: 'vpc-1' }, metrics: per(7e9, 'net_in', 14) }],
    [E, 'lambda:function', 'fn', { attrs: { subnet_ids: ['sub-b'] }, metrics: per(50e3 * 30, 'invocations', 30) }],
    [E, 'ec2:instance', 'i-busy', { state: 'running', attrs: { subnet: 'sub-b', vpc: 'vpc-1' }, metrics: per(7e9, 'net_in', 14) }],
  ]));
  w = A.city.build(A.res, { mode: 'project' });
  const idle = road(w, hk(E, 'ec2:instance', 'i-idle'), hk(E, 'ec2:nat-gateway', 'nat-idle'));
  check(idle && idle.status === 'zero' && idle.rate === 0, `honesty: egress into a NAT that measured nothing must be zero, got ${idle && idle.status} ${idle && idle.rate}`);
  for (const s of [hk(E, 'lambda:function', 'fn'), hk(E, 'ec2:instance', 'i-busy')]) {
    const f = road(w, s, hk(E, 'ec2:nat-gateway', 'nat-busy'));
    check(f && f.status === 'estimated' && f.unit === 'bytes' && Math.abs(f.rate - 0.5e9) < 1, `honesty: egress ${s} must share the NAT's own bytes as an estimate, got ${f && f.status} ${f && f.rate} ${f && f.unit}`);
  }

  // a DynamoDB stream is not measured by the table's read/write capacity; a disabled trigger carries nothing
  A = load(account([
    [E, 'dynamodb:table', 'carts', { metrics: { read_units: 4e7, write_units: 9e6, _days: { read_units: 30, write_units: 30 } } }],
    [E, 'lambda:function', 'export', { metrics: per(400, 'invocations', 30), relations: [{ to: hk(E, 'dynamodb:table', 'carts'), kind: 'consumes', label: 'batch 100' }] }],
    [E, 'sqs:queue', 'jobs', { metrics: per(9000, 'sent', 30) }],
    [E, 'lambda:function', 'cron', { metrics: per(720, 'invocations', 30), relations: [{ to: hk(E, 'sqs:queue', 'jobs'), kind: 'consumes', label: 'disabled' }] }],
  ]));
  w = A.city.build(A.res, { mode: 'project' });
  const stream = road(w, hk(E, 'dynamodb:table', 'carts'), hk(E, 'lambda:function', 'export'));
  check(stream && stream.status !== 'measured' && stream.unit !== 'reads/writes', `honesty: a stream road must not reuse the table's capacity units, got ${stream && stream.status} ${stream && stream.unit}`);
  const off = road(w, hk(E, 'sqs:queue', 'jobs'), hk(E, 'lambda:function', 'cron'));
  check(off && off.status === 'unknown' && off.rate == null, `honesty: a disabled trigger must not inherit the function's calls, got ${off && off.status} ${off && off.rate}`);

  // a CDN's viewer requests are not origin fetches: estimated at most, capped by the origin; what is left is never "zero"
  A = load(account([
    ['global', 'cloudfront:distribution', 'E1', { state: 'enabled', metrics: per(300000, 'requests', 30), relations: [{ to: hk(E, 'elbv2:lb', 'alb'), kind: 'origin' }] }],
    [E, 'elbv2:lb', 'alb', { attrs: { scheme: 'internet-facing' }, metrics: per(150000, 'requests', 30) }],
  ]));
  w = A.city.build(A.res, { mode: 'project' });
  const origin = road(w, hk('global', 'cloudfront:distribution', 'E1'), hk(E, 'elbv2:lb', 'alb'));
  check(origin && origin.status === 'estimated' && origin.rate <= 5000 + 1e-9, `honesty: CDN -> origin must be estimated and capped at the origin's own 5000/day, got ${origin && origin.status} ${origin && origin.rate}`);
  const rest = road(w, 'internet', hk(E, 'elbv2:lb', 'alb'));
  check(rest && rest.status === 'estimated', `honesty: a remainder of 0 is an estimate, not a measured zero, got ${rest && rest.status}`);
  // with the CDN filtered out, the Internet road is still an estimate and says what it could not subtract
  w = A.city.build(A.res.filter((r) => r.region === E), { mode: 'project' });
  const alone = road(w, 'internet', hk(E, 'elbv2:lb', 'alb'));
  check(alone && alone.status === 'estimated' && /outside this view/.test(alone.basis || ''), `honesty: a road inferred from the receiver is never measured, got ${alone && alone.status} (${alone && alone.basis})`);

  // senders in another unit cannot be subtracted: the Internet does not get the ALB's bytes
  A = load(account([
    [E, 'elbv2:lb', 'alb', { attrs: { scheme: 'internet-facing' }, metrics: per(14e6, 'requests', 14) }],
    [E, 'elbv2:target-group', 'tg', { relations: [{ to: hk(E, 'elbv2:lb', 'alb'), kind: 'behind' }, { to: hk(E, 'ec2:instance', 'i-web'), kind: 'targets' }] }],
    [E, 'ec2:instance', 'i-web', { state: 'running', attrs: { public_ip: '1.2.3.4' }, metrics: per(280e9, 'net_in', 14) }],
  ]));
  w = A.city.build(A.res, { mode: 'project' });
  const direct = road(w, 'internet', hk(E, 'ec2:instance', 'i-web'));
  check(direct && direct.status === 'unknown' && direct.rate == null, `honesty: Internet -> server must stay unknown when an ALB in requests also feeds it, got ${direct && direct.status} ${direct && direct.rate}`);

  // "the only database there" counts the whole network, not the filtered view
  A = load(account([
    [E, 'ec2:vpc', 'vpc-1', {}],
    [E, 'ec2:instance', 'billing-api', { state: 'running', attrs: { vpc: 'vpc-1' }, project: 'billing' }],
    [E, 'rds:instance', 'billing-db', { state: 'available', attrs: { vpc: 'vpc-1' }, project: 'billing' }],
    [E, 'rds:instance', 'shop-db', { state: 'available', attrs: { vpc: 'vpc-1' }, project: 'shop' }],
  ]));
  w = A.city.build(A.res.filter((r) => r.project === 'billing'), { mode: 'project', likely: true });
  const guess = w.overlays.find((o) => o.kind === 'likely');
  check(guess && !/only database/.test(guess.label), `honesty: a filter must not make a database "the only one there": ${guess && guess.label}`);

  // quiet regions: "only the default network" only when that is what is there
  A = load(account([
    ['us-east-1', 'lambda:function', 'fn', {}],
    ['ap-south-1', 'ec2:vpc', 'vpc-legacy', { name: 'legacy-prod', attrs: { is_default: false } }],
    ['ap-south-1', 'ec2:subnet', 'sub-1', { attrs: { vpc: 'vpc-legacy' } }],
    ['eu-west-1', 'ec2:vpc', 'vpc-def', { attrs: { is_default: true } }],
    ['eu-west-1', 'other:kinesis:stream', 'clicks', { est_monthly_usd: 400 }],
    ['sa-east-1', 'ec2:vpc', 'vpc-def2', { attrs: { is_default: true } }],
  ]));
  w = A.city.build(A.res, { mode: 'network' });
  const ghost = (reg) => A.city.story(w, w.ents.find((e) => e.kind === 'ghost' && e.name === reg).id).what;
  check(!/default network|Nothing is running/.test(ghost('ap-south-1')), `honesty: a region with a custom network is not "only the default network": ${ghost('ap-south-1')}`);
  check(!/Nothing is running/.test(ghost('eu-west-1')) && /hidden/.test(ghost('eu-west-1')), `honesty: a region with hidden resources is not "nothing running": ${ghost('eu-west-1')}`);
  check(/only the default network/.test(ghost('sa-east-1')), `honesty: a default-only region keeps its plain wording: ${ghost('sa-east-1')}`);

  // size view: one scale only (no cost heights mixed in)
  A = load(account([
    [E, 'ec2:instance', 'pricey', { state: 'running', est_monthly_usd: 900 }],
    [E, 'ec2:instance', 'cheap', { state: 'running', est_monthly_usd: 5 }],
  ]));
  w = A.city.build(A.res, { mode: 'project', height: 'size' });
  const hs = w.ents.filter((e) => e.res && e.res.type === 'ec2:instance').map((e) => e.h);
  check(hs.length === 2 && hs[0] === hs[1], `honesty: in size view buildings without a size share one base height, got ${hs}`);

  // "Show in 3D" finds a place (or says why not) for resources that are not buildings
  A = load(JSON.parse(JSON.stringify(realLikeData)));
  w = A.city.build(A.res, { mode: 'network' });
  const loc = (rid, type) => A.city.locate(w, `111122223333:us-east-1:${type}:${rid}`);
  check(loc('vpc-us-east-1', 'ec2:vpc').plate, 'locate: a VPC is its district in network view');
  check(loc('sg-db', 'ec2:security-group').id === w.entOfKey.get('111122223333:us-east-1:rds:instance:shop-database'), 'locate: a security group shows the building it protects');
  const wp = A.city.build(A.res, { mode: 'project' });
  check(A.city.locate(wp, '111122223333:us-east-1:ec2:vpc:vpc-us-east-1').mode === 'network', 'locate: in project view a VPC suggests the network view');
}

function synthetic(n) {
  const acct = '444455556666';
  const res = [];
  for (let i = 0; i < n; i++) {
    const reg = ['us-east-1', 'eu-west-1', 'ap-south-1'][i % 3];
    const type = ['ec2:instance', 's3:bucket', 'lambda:function', 'sqs:queue', 'dynamodb:table'][i % 5];
    res.push({ key: `${acct}:${reg}:${type}:r${i}`, rid: `r${i}`, type, account: acct, region: reg, name: `svc-${i % 37}-r${i}`, state: 'running', tags: {}, attrs: {},
      relations: i % 5 === 2 ? [{ to: `${acct}:${reg}:sqs:queue:r${i + 1}`, kind: 'consumes' }] : [], metrics: i % 5 === 3 ? { sent: i * 10, _days: { sent: 30 } } : {},
      project: `p${i % 9}`, env: '', est_monthly_usd: i % 13, findings: [] });
  }
  return { analyzed_at: 'y', resources: res, findings: [], projects: [], summary: {}, accounts: [{ account: acct }] };
}

// ---- run ------------------------------------------------------------------------------------------------------------------
let input = '';
process.stdin.on('data', (d) => { input += d; });
process.stdin.on('end', () => {
  const stats = {};
  const demo = JSON.parse(input);
  let A = load(demo);
  for (const mode of ['project', 'network']) {
    const w = invariants(A, 'demo', A.res, { mode });
    stats[`demo_${mode}`] = w.stats;
    check(w.flows.some((f) => f.status === 'measured'), `demo/${mode}: no measured traffic at all`);
    check(w.overlays.some((o) => o.kind === 'may-connect'), `demo/${mode}: firewall permissions missing`);
    const lb = w.ents.find((e) => e.res && e.res.type === 'elbv2:lb' && e.res.attrs.scheme === 'internet-facing');
    if (lb) {
      const p = A.city.requestPath(w, lb.id);
      check(p.reachedInternet && p.steps.length >= 2, `demo/${mode}: follow-a-request from the load balancer does not start at the Internet`);
      const story = A.city.story(w, lb.id);
      check(story.lines.length > 0 && /load balancer/i.test(story.what), `demo/${mode}: empty story for the load balancer`);
    }
  }
  invariants(A, 'demo+layers', A.res, { mode: 'network', logs: true, other: true, likely: true, ghosts: true });

  realLikeData = realLike();
  A = load(JSON.parse(JSON.stringify(realLikeData)));
  const net = invariants(A, 'real-like', A.res, { mode: 'network' });
  check(net.cities.length === 1 && net.ghosts.length === 16, `real-like/network: expected 1 city + 16 quiet regions, got ${net.cities.length} + ${net.ghosts.length}`);
  const db = net.ents.find((e) => e.res && e.res.type === 'rds:instance');
  const danger = net.flows.find((f) => f.from === 'internet' && f.to === db.id);
  check(danger && danger.danger && danger.status === 'unknown', 'real-like: the public database road must be flagged as dangerous (and unmeasured)');
  check(db.door === 'tcp 5432', `real-like: open door on the database should be tcp 5432, got ${db.door}`);
  const cf = net.flows.find((f) => f.from === 'internet' && net.byId.get(f.to).archetype === 'airport');
  check(cf && cf.status === 'zero' && cf.cars === 0, 'real-like: a CloudFront with 0 requests must be a measured-zero road');
  const lbf = net.flows.find((f) => f.from === 'internet' && net.byId.get(f.to).archetype === 'plaza');
  // the load balancer counted 10/day; that they all came from the Internet is an inference, so "estimated", never "measured"
  check(lbf && lbf.status === 'estimated' && Math.abs(lbf.rate - 10) < 1e-9, 'real-like: 140 requests over 14 days = 10/day, estimated from the receiver');
  const tower = net.ents.find((e) => e.res && e.res.type === 'ec2:instance');
  check(tower.sats.some((s) => s.kind === 'signpost') && tower.sats.some((s) => s.kind === 'shed'), 'real-like: the instance must carry its address sign and its disk shed');
  check(!net.overlays.some((o) => o.kind === 'likely'), 'real-like: guesses must be off by default');
  const guess = A.city.build(A.res, { mode: 'network', likely: true });
  const svc = guess.ents.find((e) => e.res && e.res.type === 'ecs:service');
  const g = guess.overlays.find((o) => o.kind === 'likely' && o.from === svc.id && o.to === db.id);
  check(g && /^Guess/.test(g.label), 'real-like: ECS service -> database should be suggested as a labelled guess when the layer is on');
  const p = A.city.requestPath(guess, db.id);
  check(p.reachedInternet, 'real-like: a path from the Internet to the public database must exist');
  const proj = invariants(A, 'real-like', A.res, { mode: 'project' });
  stats.real_network = net.stats; stats.real_project = proj.stats;

  honesty();

  A = load(synthetic(2000));
  const t0 = Date.now();
  const big = A.city.build(A.res, { mode: 'project' });
  stats.synthetic_ms = Date.now() - t0;
  check(!big.tooBig, 'synthetic: 2000 resources should still build');
  check(stats.synthetic_ms < 1500, `synthetic: building 2000 resources took ${stats.synthetic_ms} ms`);

  process.stdout.write(JSON.stringify({ failures: failures.slice(0, 40), count: failures.length, stats }));
});
