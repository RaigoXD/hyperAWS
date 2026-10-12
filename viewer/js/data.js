/* Data model: indexes, filters, scoping, shared metadata. */
(function () {
  'use strict';
  const A = (window.AWSA = window.AWSA || {});

  // ---- service groups: identity colour = categorical slots 1..6 (fixed order, never recoloured) ----
  A.GROUPS = [
    { id: 'compute', label: 'Compute', color: 'var(--series-1)' },
    { id: 'network', label: 'Network & edge', color: 'var(--series-2)' },
    { id: 'data', label: 'Storage & data', color: 'var(--series-3)' },
    { id: 'serverless', label: 'Serverless & messaging', color: 'var(--series-4)' },
    { id: 'containers', label: 'Containers', color: 'var(--series-5)' },
    { id: 'security', label: 'Security & identity', color: 'var(--series-6)' },
    { id: 'ops', label: 'Ops & other', color: 'var(--text-muted)' },
  ];
  A.groupById = Object.fromEntries(A.GROUPS.map((g) => [g.id, g]));

  const T = (label, abbr, group) => ({ label, abbr, group });
  A.TYPES = {
    'ec2:instance': T('EC2 instance', 'EC2', 'compute'),
    'ec2:volume': T('EBS volume', 'EBS', 'data'),
    'ec2:snapshot': T('EBS snapshot', 'Snap', 'data'),
    'ec2:ami': T('AMI', 'AMI', 'data'),
    'ec2:eip': T('Elastic IP', 'EIP', 'network'),
    'ec2:eni': T('Network interface', 'ENI', 'network'),
    'ec2:nat-gateway': T('NAT gateway', 'NAT', 'network'),
    'ec2:vpc': T('VPC', 'VPC', 'network'),
    'ec2:subnet': T('Subnet', 'Subnet', 'network'),
    'ec2:igw': T('Internet gateway', 'IGW', 'network'),
    'ec2:vpc-endpoint': T('VPC endpoint', 'VPCE', 'network'),
    'ec2:security-group': T('Security group', 'SG', 'network'),
    'elbv2:lb': T('Load balancer', 'ALB/NLB', 'network'),
    'elbv2:target-group': T('Target group', 'TG', 'network'),
    'elb:clb': T('Classic load balancer', 'CLB', 'network'),
    'cloudfront:distribution': T('CloudFront distribution', 'CDN', 'network'),
    'route53:hosted-zone': T('Route 53 zone', 'R53', 'network'),
    'rds:instance': T('RDS instance', 'RDS', 'data'),
    'rds:cluster': T('Aurora cluster', 'Aurora', 'data'),
    'rds:snapshot': T('RDS snapshot', 'RDS snap', 'data'),
    'rds:cluster-snapshot': T('Aurora snapshot', 'Aurora snap', 'data'),
    'dynamodb:table': T('DynamoDB table', 'DDB', 'data'),
    's3:bucket': T('S3 bucket', 'S3', 'data'),
    'elasticache:cluster': T('ElastiCache node group', 'Cache', 'data'),
    'elasticache:replication-group': T('ElastiCache replication group', 'Cache RG', 'data'),
    'lambda:function': T('Lambda function', 'Lambda', 'serverless'),
    'apigw:rest-api': T('API Gateway REST API', 'API GW', 'serverless'),
    'apigw:http-api': T('API Gateway HTTP API', 'API GW', 'serverless'),
    'apigw:websocket-api': T('API Gateway WebSocket API', 'WS API', 'serverless'),
    'neptune:instance': T('Neptune instance', 'Neptune', 'data'),
    'neptune:cluster': T('Neptune cluster', 'Neptune', 'data'),
    'docdb:instance': T('DocumentDB instance', 'DocDB', 'data'),
    'docdb:cluster': T('DocumentDB cluster', 'DocDB', 'data'),
    'sqs:queue': T('SQS queue', 'SQS', 'serverless'),
    'sns:topic': T('SNS topic', 'SNS', 'serverless'),
    'sfn:state-machine': T('Step Functions', 'SFN', 'serverless'),
    'ecs:cluster': T('ECS cluster', 'ECS', 'containers'),
    'ecs:service': T('ECS service', 'ECS svc', 'containers'),
    'ecr:repository': T('ECR repository', 'ECR', 'containers'),
    'eks:cluster': T('EKS cluster', 'EKS', 'containers'),
    'eks:nodegroup': T('EKS node group', 'Nodes', 'containers'),
    'kms:key': T('KMS key', 'KMS', 'security'),
    'iam:user': T('IAM user', 'IAM user', 'security'),
    'iam:role': T('IAM role', 'IAM role', 'security'),
    'logs:log-group': T('CloudWatch log group', 'Logs', 'ops'),
  };
  A.typeInfo = function typeInfo(type) {
    const t = A.TYPES[type];
    if (t) return t;
    if (type.startsWith('other:')) {
      const [, svc, rt] = type.split(':');
      return { label: `${svc} ${rt}`, abbr: svc.slice(0, 8), group: 'ops' };
    }
    return { label: type, abbr: type.split(':')[0], group: 'ops' };
  };
  A.SHARED_TYPES = new Set(['ec2:vpc', 'ec2:subnet', 'ec2:security-group', 'ec2:igw']);

  // ---- relation kinds in plain words: [seen from the resource that has the relation, seen from its target] ----
  // Arrows point from the dependent resource to what it uses (volume -attached-to-> instance).
  A.REL_TEXT = {
    'in-subnet': ['In subnet', 'Contains'],
    'in-vpc': ['In VPC', 'Contains'],
    'egress-via': ['Reaches the internet via', 'Internet egress for'],
    'uses-sg': ['Protected by security group', 'Protects'],
    'attached-to': ['Attached to', 'Has attached'],
    'associated-with': ['Associated with', 'Has associated'],
    'snapshot-of': ['Snapshot of', 'Has snapshot'],
    'backed-by': ['Backed by snapshot', 'Backs AMI'],
    'uses-eip': ['Uses Elastic IP', 'Elastic IP of'],
    behind: ['Behind load balancer', 'Forwards to target group'],
    targets: ['Sends traffic to', 'Receives traffic from'],
    serves: ['Registers tasks in target group', 'Served by'],
    'member-of': ['Member of', 'Has member'],
    'in-cluster': ['Runs in cluster', 'Runs'],
    'node-of': ['Node of cluster', 'Has node'],
    'logs-of': ['Holds the logs of', 'Writes logs to'],
    'replica-of': ['Read replica of', 'Has read replica'],
    origin: ['Serves content from', 'Origin of'],
    dns: ['DNS record points to', 'Named by DNS zone'],
    consumes: ['Reads messages from', 'Read by'],
    'delivers-to': ['Delivers messages to', 'Receives messages from'],
    'dead-letter-to': ['Sends failed messages to', 'Dead-letter target of'],
    'uses-role': ['Runs as IAM role', 'Role used by'],
    'may-connect': ['Allowed to connect to (security group rule)', 'Accepts connections from (security group rule)'],
  };
  A.relText = function relText(kind, incoming) {
    const t = A.REL_TEXT[kind];
    return t ? t[incoming ? 1 : 0] : kind;
  };

  // ---- severity: status palette (icon + label always; colour never alone) ----------
  A.SEV = {
    high: { label: 'High', icon: '▲', color: 'var(--critical)', rank: 0 },
    medium: { label: 'Medium', icon: '◆', color: 'var(--serious)', rank: 1 },
    low: { label: 'Low', icon: '●', color: 'var(--text-muted)', rank: 2 },
    info: { label: 'Info', icon: '○', color: 'var(--text-muted)', rank: 3 },
  };
  A.CATEGORIES = {
    unused: 'Unused',
    rightsizing: 'Rightsizing',
    'cost-insight': 'Cost insight',
    security: 'Security',
    hygiene: 'Hygiene',
  };
  const CONF_RANK = { high: 3, medium: 2, low: 1 };
  A.confRank = (c) => CONF_RANK[c] || 1;

  /** Status tone of a resource state: good | warn | bad | '' (none) */
  A.stateTone = function stateTone(r) {
    const s = (r.state || '').toLowerCase();
    if (!s) return '';
    if (['running', 'available', 'active', 'attached', 'associated', 'enabled', 'in-use', 'completed', 'incoming'].includes(s)) {
      if (r.type === 'ec2:volume' && s === 'available') return 'warn';
      if (r.type === 'ec2:eni' && s === 'available') return 'warn';
      return 'good';
    }
    if (['stopped', 'unassociated', 'detached', 'disabled', 'stopping', 'pending', 'creating', 'deleting', 'pendingdeletion'].includes(s)) return 'warn';
    if (['failed', 'error', 'deleted', 'impaired', 'inactive', 'incompatible-network'].includes(s)) return 'bad';
    return '';
  };

  // ---- loading + indexes ------------------------------------------------------------------
  A.data = null;
  A.filters = { account: '', region: '', project: '', env: '', q: '' };

  A.init = function init(data) {
    A.data = data;
    A.res = data.resources || [];
    A.findings = data.findings || [];
    A.byKey = new Map(A.res.map((r) => [r.key, r]));
    A.findingById = new Map(A.findings.map((f) => [f.id, f]));
    A.incoming = new Map();
    for (const r of A.res) {
      for (const rel of r.relations || []) {
        if (!A.incoming.has(rel.to)) A.incoming.set(rel.to, []);
        A.incoming.get(rel.to).push({ from: r.key, kind: rel.kind, label: rel.label });
      }
    }
    A.invalidate();
  };

  let scopeCache = null;
  A.invalidate = function () { scopeCache = null; };

  A.setFilters = function setFilters(patch) {
    Object.assign(A.filters, patch);
    A.invalidate();
    A.emit('filters');
  };

  /** Resources/findings that pass the global filter row (memoised). */
  A.scope = function scope() {
    if (scopeCache) return scopeCache;
    const f = A.filters;
    const q = f.q.trim().toLowerCase();
    const res = A.res.filter((r) =>
      (!f.account || r.account === f.account) && (!f.region || r.region === f.region) &&
      (!f.project || r.project === f.project) && (!f.env || (r.env || 'unknown') === f.env) &&
      (!q || A.searchText(r).includes(q)));
    const keys = new Set(res.map((r) => r.key));
    const hasResFilter = !!(f.region || f.project || f.env || q);
    const findings = A.findings.filter((x) => {
      if (x.resources.length) return x.resources.some((k) => keys.has(k));
      return !hasResFilter && (!f.account || x.account === f.account);   // account-level findings
    });
    scopeCache = { res, keys, findings };
    return scopeCache;
  };

  A.searchText = function searchText(r) {
    if (r._s) return r._s;
    const tagText = Object.entries(r.tags || {}).map(([k, v]) => `${k}=${v}`).join(' ');
    r._s = [r.name, r.rid, r.type, r.project, r.env, r.region, r.state, r.arn, tagText].join(' ').toLowerCase();
    return r._s;
  };

  /** Savings of a finding restricted to the scoped resources. */
  A.scopedSavings = function scopedSavings(f, keys) {
    const ks = Object.keys(f.breakdown || {});
    if (!ks.length) {
      // no per-resource breakdown (e.g. a commitment insight): scale by the share of its resources in scope
      if (!keys || !f.resources.length) return f.savings_usd;
      return f.savings_usd * (f.resources.filter((k) => keys.has(k)).length / f.resources.length);
    }
    return ks.reduce((s, k) => s + (!keys || keys.has(k) ? f.breakdown[k] : 0), 0);
  };

  /** Non-overlapping total: per resource only its largest single saving counts. */
  A.potential = function potential(findings, keys, minConf) {
    const floor = A.confRank(minConf || 'low');
    const best = new Map();
    for (const f of findings) {
      if (!f.in_total || A.confRank(f.confidence) < floor) continue;
      for (const [k, v] of Object.entries(f.breakdown || {})) {
        if (keys && !keys.has(k)) continue;
        if (v > (best.get(k) || 0)) best.set(k, v);
      }
    }
    let t = 0;
    best.forEach((v) => { t += v; });
    return t;
  };

  A.facets = function facets() {
    const uniq = (fn) => [...new Set(A.res.map(fn))].filter((x) => x != null && x !== '').sort((a, b) => String(a).localeCompare(String(b)));
    return {
      accounts: uniq((r) => r.account),
      regions: uniq((r) => r.region),
      projects: (A.data.projects || []).map((p) => p.name),
      envs: uniq((r) => r.env || 'unknown'),
    };
  };

  A.findingsOf = function findingsOf(r) {
    return (r.findings || []).map((id) => A.findingById.get(id)).filter(Boolean)
      .sort((a, b) => A.SEV[a.severity].rank - A.SEV[b.severity].rank);
  };
  A.worstSeverity = function worstSeverity(fs) {
    return fs.reduce((w, f) => (w == null || A.SEV[f.severity].rank < A.SEV[w].rank ? f.severity : w), null);
  };

  A.isUntagged = (r) => !Object.keys(r.tags || {}).some((k) => !k.startsWith('aws:'));
})();
