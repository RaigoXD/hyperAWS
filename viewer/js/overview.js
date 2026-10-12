/* Overview tab. */
(function () {
  'use strict';
  const A = (window.AWSA = window.AWSA || {});
  const h = A.h;
  A.tabs = A.tabs || {};

  const NOISE = new Set(['ec2:subnet', 'ec2:eni', 'ec2:security-group', 'ec2:igw']);

  function costBy(res, keyFn) {
    const m = new Map();
    res.forEach((r) => { const k = keyFn(r); m.set(k, (m.get(k) || 0) + r.est_monthly_usd); });
    return [...m.entries()].map(([label, value]) => ({ label, value })).sort((a, b) => b.value - a.value);
  }

  A.tabs.overview = {
    id: 'overview', title: 'Overview',
    render(root) {
      const { res, keys, findings } = A.scope();
      const cost = res.reduce((s, r) => s + r.est_monthly_usd, 0);
      const potAll = A.potential(findings, keys);
      const potSure = A.potential(findings, keys, 'medium');
      const highCount = findings.filter((f) => f.severity === 'high').length;
      const projects = new Set(res.map((r) => r.project).filter((p) => p && !p.startsWith('(') && p !== 'Unassigned'));
      const taggable = res.filter((r) => !r.type.startsWith('other:'));
      const projTagged = taggable.filter((r) => /^(tag|rule)/.test(r.project_source || '')).length;
      const gaps = (A.data.gaps || []).reduce((s, g) => s + (g.count || 1), 0);

      if (!res.length) { root.appendChild(A.empty('No resources match the current filters.')); return; }

      if (gaps) {
        root.appendChild(h('div', { class: 'notice warn', role: 'status' },
          h('strong', null, `${A.fmt.plural(gaps, 'API call')} could not be completed. `),
          'The inventory may be incomplete for those services/regions. ',
          A.link('See coverage gaps', () => A.goto('scan'))));
      }

      const unpriced = (A.data.summary.unpriced || {}).resources || 0;
      if (unpriced) {
        const types = Object.keys((A.data.summary.unpriced || {}).types || {}).join(', ');
        root.appendChild(h('div', { class: 'notice warn', role: 'status' },
          h('strong', null, `${A.fmt.plural(unpriced, 'resource')} could not be priced`),
          ` (${types}). Their price is not in the reference table, so the cost and savings above are understated for them: unpriced is not free. `,
          A.link('See them in the inventory', () => A.goto('inventory', { state: '' }))));
      }
      const cov = A.data.coverage;
      if (cov && cov.not_inventoried) {
        const more = h('details', { class: 'notice', style: { cursor: 'default' } },
          h('summary', { style: { cursor: 'pointer' } }, h('strong', null, 'What this report cannot see. '), 'Services without a collector are invisible unless tagged.'),
          h('p', { style: { marginTop: '8px' } }, cov.note),
          h('p', { class: 'muted small', style: { marginTop: '6px' } }, 'Not inventoried: ' + cov.not_inventoried.join(' · ')));
        root.appendChild(more);
      }

      root.appendChild(h('div', { class: 'hero-row' },
        h('div', { class: 'hero card' },
          h('div', { class: 'hero-label' }, 'Potential savings'),
          h('div', { class: 'hero-value' }, A.fmt.usd(potAll), h('span', { class: 'hero-unit' }, '/month')),
          h('p', { class: 'hero-sub' }, `${A.fmt.usd(potSure)}/month of it is high or medium confidence. `,
            'Each resource counts once, at its largest single saving. Figures are estimates from list prices; usage charges are not included.'),
          h('div', { class: 'row gap' }, h('button', { class: 'btn primary', type: 'button', onClick: () => A.goto('waste') }, 'Review findings'),
            h('button', { class: 'btn', type: 'button', onClick: () => A.goto('cost') }, 'Cost & optimization'))),
        h('div', { class: 'stat-grid' },
          A.stat({ label: 'Estimated cost', value: A.fmt.usdc(cost) + '/mo', sub: 'fixed/baseline charges only', onClick: () => A.goto('cost') }),
          A.stat({ label: 'Resources', value: A.fmt.num(res.length), sub: `${A.fmt.num(new Set(res.map((r) => r.region)).size)} regions`, onClick: () => A.goto('inventory') }),
          A.stat({ label: 'Projects', value: A.fmt.num(projects.size), sub: 'detected from tags and names', onClick: () => A.goto('map') }),
          A.stat({ label: 'High-severity findings', value: A.fmt.num(highCount), sub: `${A.fmt.num(findings.length)} findings in total`, tone: highCount ? 'bad' : null, onClick: () => A.goto('waste', { severity: 'high' }) }),
          A.stat({ label: 'Project tag coverage', value: A.fmt.pct(taggable.length ? (100 * projTagged) / taggable.length : 0), sub: 'resources with a project tag or rule', onClick: () => A.goto('tags') }))));

      const row1 = h('div', { class: 'grid-2' });
      const setProject = (name) => () => A.setFilters({ project: name });
      row1.appendChild(A.hbar({
        title: 'Estimated monthly cost by project', subtitle: 'Click a bar to filter everything to that project',
        rows: costBy(res, (r) => r.project || 'Unassigned').map((r) => ({ ...r, onClick: setProject(r.label), sub: 'estimate' })),
        fmt: A.fmt.usd, limit: 10,
      }));
      row1.appendChild(A.hbar({
        title: 'Estimated monthly cost by service', subtitle: 'Baseline charges; usage-based services show $0',
        rows: costBy(res, (r) => A.typeInfo(r.type).label).map((r) => ({ ...r, sub: 'estimate' })), fmt: A.fmt.usd, limit: 10,
      }));
      root.appendChild(row1);

      const byCat = new Map();
      findings.filter((f) => f.in_total).forEach((f) => byCat.set(f.category, (byCat.get(f.category) || 0) + A.scopedSavings(f, keys)));
      const row2 = h('div', { class: 'grid-2' });
      row2.appendChild(A.hbar({
        title: 'Potential savings by category', subtitle: 'Sum of finding estimates; categories can overlap, the headline total does not',
        rows: [...byCat.entries()].map(([k, v]) => ({ label: A.CATEGORIES[k] || k, value: v, onClick: () => A.goto('waste', { category: k }) })).sort((a, b) => b.value - a.value),
        fmt: A.fmt.usd, empty: 'No savings found in this scope.',
      }));
      const sev = ['high', 'medium', 'low', 'info'].map((s) => ({
        id: s, label: A.SEV[s].label, value: findings.filter((f) => f.severity === s).length, color: A.SEV[s].color, onClick: () => A.goto('waste', { severity: s }),
      }));
      row2.appendChild(A.hbar({
        title: 'Findings by severity', subtitle: 'Severity is about risk or waste size, not certainty',
        rows: sev, fmt: A.fmt.num, empty: 'No findings in this scope.',
        labelFor: (r) => A.sevBadge(r.id),
      }));
      root.appendChild(row2);

      const regions = [...new Set(res.map((r) => r.region))].sort();
      const cols = A.GROUPS.map((g) => g.id);
      const counts = new Map();
      res.forEach((r) => {
        if (NOISE.has(r.type)) return;
        const k = r.region + '|' + A.typeInfo(r.type).group;
        counts.set(k, (counts.get(k) || 0) + 1);
      });
      root.appendChild(A.heatmap({
        title: 'Footprint: where resources live', subtitle: 'Resource count by region and service group (subnets, network interfaces, security groups and gateways excluded)',
        rows: regions.map((r) => (r === 'global' ? 'global' : r)), cols,
        colLabel: (c) => A.groupById[c].label,
        value: (r, c) => counts.get(r + '|' + c) || 0,
        onCell: (r, c) => A.goto('inventory', { group: c, region: r }),
      }));

      const top = findings.filter((f) => f.in_total && A.scopedSavings(f, keys) > 0).sort((a, b) => A.scopedSavings(b, keys) - A.scopedSavings(a, keys)).slice(0, 6);
      if (top.length) {
        root.appendChild(A.card('Biggest opportunities', 'Highest estimated monthly savings in this scope',
          h('ol', { class: 'top-list' }, top.map((f) => h('li', null,
            h('button', { class: 'top-row', type: 'button', onClick: () => A.goto('waste', { open: f.id }) },
              h('span', { class: 'top-title' }, A.sevBadge(f.severity), f.title),
              h('span', { class: 'top-meta' }, [f.project && f.project !== 'multiple' ? f.project : null, f.region && f.region !== 'multiple' ? f.region : null, A.CATEGORIES[f.category]].filter(Boolean).join(' · ')),
              h('span', { class: 'top-save' }, A.fmt.usd(A.scopedSavings(f, keys)) + '/mo')))))));
      }
    },
  };
})();
