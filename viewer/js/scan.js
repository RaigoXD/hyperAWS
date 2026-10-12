/* Scan info tab: what ran, proof it was read-only, coverage gaps, audit log. */
(function () {
  'use strict';
  const A = (window.AWSA = window.AWSA || {});
  const h = A.h;
  A.tabs = A.tabs || {};

  const READ_VERB = /^(describe|list|get|batch-get)-[a-z0-9-]+$/;
  const GAP_HELP = {
    AccessDenied: 'The profile is not allowed to make this call. Attach the generated read-only policy (python3 -m analyzer policy) or accept the gap.',
    AccessDeniedException: 'The profile is not allowed to make this call. Attach the generated read-only policy or accept the gap.',
    UnauthorizedOperation: 'The profile is not allowed to make this call. Attach the generated read-only policy or accept the gap.',
    OptInRequired: 'The service or region is not enabled for this account. Usually harmless.',
    SubscriptionRequiredException: 'The service is not subscribed in this account. Usually harmless.',
    UnrecognizedClientException: 'The region is not enabled for these credentials. Usually harmless.',
    InvalidClientTokenId: 'The region is not enabled for these credentials. Usually harmless.',
    CollectorError: 'A collector hit an unexpected response. Results for that service/region may be incomplete.',
    UnsafeArgument: 'A value AWS returned (such as a resource name) would have made the AWS CLI read a local file, or was malformed, so this one call was skipped before any process started. Nothing was sent.',
    Throttling: 'AWS throttled the calls even after retries. Re-run with fewer --workers.',
  };

  A.tabs.scan = {
    id: 'scan', title: 'Scan info',
    render(root) {
      const d = A.data;
      const audit = d.audit || [];
      const refused = audit.filter((c) => c.status === 'refused');   // stopped by the guard: no process, nothing sent
      const sent = audit.length - refused.length;
      const nonRead = audit.filter((c) => !READ_VERB.test(c.op) && c.status !== 'planned');
      const byStatus = audit.reduce((m, c) => { m[c.status] = (m[c.status] || 0) + 1; return m; }, {});
      const gaps = d.gaps || [];

      root.appendChild(h('div', { class: 'notice ' + (nonRead.length ? 'bad' : 'good'), role: 'status' },
        nonRead.length
          ? [h('strong', null, `${nonRead.length} call(s) were not describe/list/get operations: `), nonRead.slice(0, 5).map((c) => `${c.service} ${c.op}`).join(', ')]
          : [h('strong', null, `✓ All ${A.fmt.num(sent)} AWS API calls were read-only (describe / list / get). `),
            refused.length ? `${A.fmt.plural(refused.length, 'more call was', 'more calls were')} refused by the tool's guard before anything was sent. ` : '',
            'This log is recorded by the tool itself. For a guarantee that does not depend on the tool, run it with an IAM principal limited to the generated read-only policy.']));

      const accounts = d.accounts || [];
      root.appendChild(A.card('Scan', null, h('dl', { class: 'facts wide' },
        ...[
          ['Scanned at', d.scanned_at || '–'], ['Tool', `aws-analyzer ${d.version || ''}`],
          ['Accounts', accounts.map((a) => `${a.account} (profile ${a.profile || 'default'})`).join(', ') || '–'],
          ['Caller', accounts.map((a) => a.arn).join(', ') || '–'],
          ['Regions', accounts.map((a) => `${(a.regions || []).length}: ${(a.regions || []).join(', ')}`).join(' | ') || '–'],
          ['Options', Object.entries(d.scan_options || {}).map(([k, v]) => `${k}=${Array.isArray(v) ? v.join(',') : v}`).join('  ')],
          ['API calls', Object.entries(byStatus).map(([k, v]) => `${v} ${k}`).join(', ') || '0'],
          ['Pricing table', (d.pricing && d.pricing.as_of) || '–'],
        ].flatMap(([k, v]) => [h('dt', null, k), h('dd', null, v)]))));

      // ---- what is covered at all ---------------------------------------------------------------------------------------
      if (d.coverage) {
        root.appendChild(A.card('What this tool inventories', 'Everything else is invisible unless it carries tags (then it shows without cost or findings).',
          h('dl', { class: 'facts wide' }, ...d.coverage.collected.flatMap((c) => [h('dt', null, c.group), h('dd', null, c.what)])),
          h('p', { class: 'muted small', style: { marginTop: '10px' } }, 'Not inventoried: ' + d.coverage.not_inventoried.join(' · ')),
          h('p', { class: 'small' }, d.coverage.note)));
      }

      // ---- coverage gaps ---------------------------------------------------------------------------------------
      root.appendChild(A.card(`Coverage gaps (${gaps.length})`, 'Calls that did not succeed. Missing data here means “unknown”, never “none”.',
        gaps.length ? h('div', { class: 'table-wrap' }, h('table', { class: 'data' },
          h('thead', null, h('tr', null, ['Service / operation', 'Region', 'Error', 'Calls', 'What it means'].map((c, i) => h('th', { scope: 'col', class: i === 3 ? 'num' : '' }, c)))),
          h('tbody', null, gaps.map((g) => h('tr', null, h('th', { scope: 'row' }, `${g.service} ${g.op}`), h('td', null, g.region), h('td', null, h('span', { class: 'mono' }, g.code)),
            h('td', { class: 'num' }, A.fmt.num(g.count || 1)), h('td', { class: 'small' }, GAP_HELP[g.code] || g.message)))))) :
          h('p', { class: 'good-text' }, '✓ No gaps: every call succeeded.')));

      // ---- audit summary ----------------------------------------------------------------------------------------------
      const byOp = new Map();
      audit.forEach((c) => {
        const k = `${c.service} ${c.op}`;
        const e = byOp.get(k) || { k, n: 0, ms: 0, bad: 0, empty: 0 };
        e.n++; e.ms += c.ms || 0; if (['denied', 'unavailable', 'throttled', 'error', 'refused'].includes(c.status)) e.bad++; if (c.status === 'empty') e.empty++;
        byOp.set(k, e);
      });
      const rows = [...byOp.values()].sort((a, b) => b.n - a.n);
      root.appendChild(A.card(`API calls by operation (${rows.length})`, 'Every call the scan made, grouped. Each is a describe/list/get on the allowlist.',
        h('div', { class: 'toolbar' }, h('button', { class: 'btn', type: 'button', onClick: () => A.download('audit-log.json', JSON.stringify(audit, null, 1), 'application/json') }, 'Download full audit log (JSON)')),
        h('div', { class: 'table-wrap' }, h('table', { class: 'data' },
          h('thead', null, h('tr', null, ['Operation', 'Calls', 'Avg ms', 'Failed', 'Expected-empty'].map((c, i) => h('th', { scope: 'col', class: i ? 'num' : '' }, c)))),
          h('tbody', null, rows.map((e) => h('tr', null, h('th', { scope: 'row', class: 'mono' }, e.k), h('td', { class: 'num' }, A.fmt.num(e.n)), h('td', { class: 'num' }, A.fmt.num(e.ms / e.n)),
            h('td', { class: 'num' }, e.bad ? A.fmt.num(e.bad) : '–'), h('td', { class: 'num' }, e.empty ? A.fmt.num(e.empty) : '–'))))))));

      root.appendChild(h('p', { class: 'muted small foot' }, 'This report contains your infrastructure details (names, ids, tags). Treat the file as sensitive and keep it out of public places. It makes no network requests.'));
    },
  };
})();
