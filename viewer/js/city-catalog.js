/* 3D map ("Cloud City"): the metaphor catalogue. Pure data, no DOM and no three.js.
   Every AWS type maps to an archetype (what it looks like), a tier (which street band it lives on), a footprint and a
   plain-language explanation for people who do not know AWS. Relation kinds map to how they appear (road with cars,
   footpath, beam, fence...) and in which direction requests travel on them. */
(function () {
  'use strict';
  const A = (window.AWSA = window.AWSA || {});
  const C = (A.cityCatalog = {});

  // Tier bands: front (facing the hub/gate) to back. Request traffic flows front -> back.
  C.TIERS = [
    { id: 'edge', label: 'Front door', hint: 'where visitors arrive' },
    { id: 'work', label: 'Workers', hint: 'where the work is done' },
    { id: 'messaging', label: 'Mail & messaging', hint: 'where messages wait and are passed on' },
    { id: 'data', label: 'Storage & vaults', hint: 'where data is kept' },
    { id: 'back', label: 'Back office', hint: 'support services' },
  ];
  C.tierIndex = Object.fromEntries(C.TIERS.map((t, i) => [t.id, i]));

  // archetype: { w, d, h (min height), k (height per log10 $), name, what (city words), why (AWS words) }
  const AR = (w, d, h, k, name, what) => ({ w, d, h, k, name, what });
  C.ARCHETYPES = {
    tower: AR(8, 8, 6, 6, 'Office tower', 'A server you rent by the hour. Lit windows mean it is running; dark windows mean it is stopped (you still pay for its disks).'),
    shed: AR(4, 4, 2.2, 0.8, 'Storage shed', 'A disk. It sits behind the server it is plugged into; a shed on its own lot is a disk nobody uses but you still pay for.'),
    yard: AR(8, 8, 2.5, 1, 'Archive yard', 'Backups and machine images (snapshots, AMIs), stacked like crates. Old crates cost money every month.'),
    signpost: AR(3, 3, 3.5, 0, 'Street-address sign', 'A reserved public address (Elastic IP). Visitors from the Internet find a building by this address. A sign on an empty lot is an address you pay for but do not use.'),
    plaza: AR(14, 14, 1, 1, 'Roundabout plaza', 'A load balancer: visitors arrive here and are sent on to whichever building is free.'),
    kiosk: AR(4, 4, 2, 0, 'Dispatch kiosk', 'A target group: the list of buildings the plaza sends visitors to.'),
    factory: AR(12, 9, 5, 3, 'Factory', 'A container service (ECS): the same program running in several copies (the stacked containers).'),
    park: AR(9, 8, 3.5, 1, 'Industrial park office', 'A container cluster (ECS): the estate where container factories run.'),
    port: AR(16, 12, 4, 2, 'Container port', 'A Kubernetes cluster (EKS): a port where containers are loaded onto worker machines.'),
    warehouse: AR(10, 8, 4, 2, 'Port warehouse', 'A group of Kubernetes worker machines (node group).'),
    truck: AR(6, 4, 3, 0, 'Food truck', 'A serverless function (Lambda): it only opens when someone calls it and you pay per visit, not per hour.'),
    reception: AR(9, 6, 4, 1.5, 'Reception', 'An API Gateway: the front desk that checks incoming requests and forwards them.'),
    vault: AR(12, 10, 4, 3, 'Bank vault', 'A managed database (RDS/Aurora): where the important records are stored and guarded.'),
    cabinet: AR(7, 7, 4, 2, 'Filing-cabinet silo', 'A DynamoDB table: a giant filing cabinet that finds any record instantly.'),
    corner: AR(5, 5, 3, 1, 'Corner kiosk', 'A cache (ElastiCache): a small fast shop next door that keeps copies of popular items.'),
    silo: AR(7, 7, 3, 2.5, 'Grain silo', 'An S3 bucket: bulk storage for files. Taller silos hold more data.'),
    postoffice: AR(10, 8, 4, 1, 'Post office', 'A message queue (SQS): letters wait in line here until a worker picks them up.'),
    radio: AR(6, 6, 14, 0, 'Radio tower', 'A notification topic (SNS): one message broadcast to every subscriber at once.'),
    control: AR(9, 9, 6, 1, 'Traffic control centre', 'A workflow (Step Functions): it tells other buildings what to do, step by step.'),
    depot: AR(12, 8, 4, 1, 'Container depot', 'An image registry (ECR): where the container blueprints are stored.'),
    locksmith: AR(4, 4, 3, 0, 'Locksmith', 'An encryption key (KMS): it locks and unlocks data for other buildings.'),
    records: AR(5, 5, 3, 0.5, 'Records office', 'A log group (CloudWatch Logs): the diary where buildings write what happened.'),
    toll: AR(6, 5, 3, 1, 'Toll booth', 'A NAT gateway: private buildings drive out to the Internet through here (one way: the Internet cannot drive in). Charged per hour and per GB.'),
    tunnel: AR(5, 4, 2, 0, 'Private tunnel', 'A VPC endpoint: a private tunnel to an AWS service, so traffic never leaves AWS.'),
    airport: AR(18, 12, 3, 1, 'Airport', 'A CDN (CloudFront): planes fly copies of your content to the whole world so visitors get it fast.'),
    directory: AR(6, 6, 12, 0, 'Directory tower', 'A DNS zone (Route 53): the phone book that turns a name like example.com into an address.'),
    hq: AR(14, 14, 3, 0, 'Identity HQ', 'IAM: the city hall where badges are issued. Every floor is an office (an IAM role) that buildings borrow to get permissions.'),
    floor: AR(14, 14, 1.6, 0, 'Office (IAM role)', 'An IAM role: a set of permissions a building borrows. A dark floor is a role nobody has used for a long time.'),
    badges: AR(7, 6, 4, 0, 'Badge office', 'IAM users: people (or programs) with their own permanent badge and keys.'),
    unknown: AR(6, 6, 4, 1, 'Other building', 'A resource of a service this tool does not inventory; it is only known because it carries tags.'),
    stack: AR(10, 10, 5, 1, 'Block of identical buildings', 'Many similar resources shown as one block to keep the city readable. Select it to see the list.'),
    plot: AR(8, 8, 0.3, 0, 'Empty plot', 'An empty subnet: land reserved for buildings, with nothing on it.'),
    internet: AR(16, 16, 10, 0, 'The Internet', 'Everything outside your AWS account: visitors arrive from here.'),
  };

  // type -> archetype + tier. Types not listed fall back to 'unknown'/'back'.
  const T = (archetype, tier) => ({ archetype, tier });
  C.TYPES = {
    'ec2:instance': T('tower', 'work'),
    'ec2:volume': T('shed', 'data'),
    'ec2:snapshot': T('yard', 'data'),
    'ec2:ami': T('yard', 'data'),
    'rds:snapshot': T('yard', 'data'),
    'rds:cluster-snapshot': T('yard', 'data'),
    'ec2:eip': T('signpost', 'edge'),
    'ec2:nat-gateway': T('toll', 'edge'),
    'ec2:vpc-endpoint': T('tunnel', 'back'),
    'elbv2:lb': T('plaza', 'edge'),
    'elb:clb': T('plaza', 'edge'),
    'elbv2:target-group': T('kiosk', 'edge'),
    'cloudfront:distribution': T('airport', 'edge'),
    'apigw:rest-api': T('reception', 'edge'),
    'apigw:http-api': T('reception', 'edge'),
    'apigw:websocket-api': T('reception', 'edge'),
    'ecs:cluster': T('park', 'work'),
    'ecs:service': T('factory', 'work'),
    'eks:cluster': T('port', 'work'),
    'eks:nodegroup': T('warehouse', 'work'),
    'lambda:function': T('truck', 'work'),
    'sfn:state-machine': T('control', 'work'),
    'sqs:queue': T('postoffice', 'messaging'),
    'sns:topic': T('radio', 'messaging'),
    'rds:instance': T('vault', 'data'),
    'rds:cluster': T('vault', 'data'),
    'neptune:instance': T('vault', 'data'),
    'neptune:cluster': T('vault', 'data'),
    'docdb:instance': T('vault', 'data'),
    'docdb:cluster': T('vault', 'data'),
    'dynamodb:table': T('cabinet', 'data'),
    'elasticache:cluster': T('corner', 'data'),
    'elasticache:replication-group': T('corner', 'data'),
    's3:bucket': T('silo', 'data'),
    'ecr:repository': T('depot', 'back'),
    'kms:key': T('locksmith', 'back'),
    'logs:log-group': T('records', 'back'),
    'route53:hosted-zone': T('directory', 'hub'),
    'iam:role': T('floor', 'hub'),
    'iam:user': T('badges', 'hub'),
  };
  // Never buildings: the land itself, or layers.
  C.TERRAIN = new Set(['ec2:vpc', 'ec2:subnet', 'ec2:igw', 'ec2:security-group', 'ec2:eni']);
  C.HUB_TYPES = new Set(['iam:role', 'iam:user', 'route53:hosted-zone']);
  C.YARD_TYPES = new Set(['ec2:snapshot', 'ec2:ami', 'rds:snapshot', 'rds:cluster-snapshot']);

  C.info = function info(type) {
    const t = C.TYPES[type];
    if (t) return t;
    return { archetype: 'unknown', tier: 'back' };
  };

  // ---- relations: how each kind is shown and which way requests travel --------------------------------------------
  // dir: 'fwd' = requests go from the resource that owns the relation to its target; 'rev' = the other way.
  // show: 'road' (cars), 'internal' (same lot), 'footpath' (on selection), 'beam' (on selection), 'security' (layer).
  // fan: 'split' (traffic is shared out), 'copy' (every target gets everything).
  const K = (dir, show, car, fan, text) => ({ dir, show, car, fan, text });
  C.KINDS = {
    behind: K('rev', 'internal', 'car', 'split', 'sends visitors to'),
    targets: K('fwd', 'road', 'car', 'split', 'sends visitors to'),
    serves: K('rev', 'road', 'car', 'split', 'sends visitors to'),
    origin: K('fwd', 'road', 'van', 'split', 'fetches content from'),
    'replica-of': K('rev', 'road', 'truck', 'copy', 'copies its data to'),
    'egress-via': K('fwd', 'road', 'truck', 'split', 'drives out through'),
    consumes: K('rev', 'road', 'van', 'split', 'hands messages to'),
    'delivers-to': K('fwd', 'road', 'van', 'copy', 'broadcasts to'),
    'dead-letter-to': K('fwd', 'road', 'van', 'split', 'sends failed messages to'),
    internet: K('fwd', 'road', 'car', 'split', 'sends visitors to'),
    'internet-out': K('fwd', 'road', 'truck', 'split', 'drives out to'),
    dns: K('fwd', 'footpath', null, null, 'points visitors to'),
    'uses-role': K('fwd', 'beam', null, null, 'borrows the badge of'),
    'may-connect': K('fwd', 'security', null, null, 'is allowed through the fence to'),
    likely: K('fwd', 'guess', null, null, 'probably talks to'),
  };

  // Daily traffic of a resource: which metric, its unit and the car type it produces.
  C.TRAFFIC = {
    'elbv2:lb': [['requests', 'requests'], ['flows', 'connections']],
    'elb:clb': [['requests', 'requests']],
    'cloudfront:distribution': [['requests', 'requests']],
    'apigw:rest-api': [['requests', 'requests']],
    'apigw:http-api': [['requests', 'requests']],
    'lambda:function': [['invocations', 'calls']],
    'sqs:queue': [['sent', 'messages']],
    'sns:topic': [['published', 'messages']],
    'sfn:state-machine': [['executions', 'runs']],
    'dynamodb:table': [['read_units+write_units', 'reads/writes']],
    'ec2:instance': [['net_in', 'bytes']],
    'ec2:nat-gateway': [['bytes_in+bytes_return', 'bytes']],
  };

  C.LEGEND = [
    { icon: 'island', title: 'Islands are cities', text: 'In "Project" view every project is a city; in "Network" view every AWS region is a city and every private network (VPC) is a walled district.' },
    { icon: 'hub', title: 'The capital in the middle', text: 'The Internet portal, the identity headquarters (IAM roles are its floors) and the address directory (DNS) live in the centre. Visitors arrive from the portal.' },
    { icon: 'road', title: 'Roads and cars are connections', text: 'A road joins two components that talk to each other. Cars show requests, vans show messages, trucks show bulk data. More cars = busier (each step is about 10x more).' },
    { icon: 'ghost', title: 'Grey cars: traffic unknown', text: 'The scan had no measurement for that road. Cones on an empty road mean it was measured and nothing passed.' },
    { icon: 'dashed', title: 'Dashed lines are not roads', text: 'Orange dashes: the firewall would allow it (security layer). Grey dashes: a guess from names and networks (likely connections). When you select a building: blue dashes lead to its address in the directory (DNS), green dashes to the IAM role (badge) it borrows. None of them is observed traffic.' },
    { icon: 'height', title: 'Height is cost', text: 'Taller buildings cost more per month. With the height set to Size, taller buildings hold more data instead; buildings without a stored-data size (servers, functions…) then keep their base height.' },
    { icon: 'vacant', title: 'For rent = unused', text: 'Faded buildings with a "For rent" sign are flagged as unused. A gold coin shows what you could save each month.' },
    { icon: 'pin', title: 'Pins are findings', text: '▲ high, ◆ medium, ● low severity. A red arch means a door open to the whole Internet on a sensitive port.' },
  ];
})();
