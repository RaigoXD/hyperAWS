/* Tags & governance tab: coverage, how projects were inferred, inconsistent keys, unassigned resources. */
(function () {
  'use strict';
  const A = (window.AWSA = window.AWSA || {});
  const h = A.h;
  A.tabs = A.tabs || {};

  const SOURCE_LABEL = {
    rule: 'Matched a rule in analyzer.toml', tag: 'Project tag', stack: 'CloudFormation stack name', 'name-match': 'Name starts with a known project',
    inherited: 'Inherited from a related resource', 'name-prefix': 'Shared name prefix (inferred)', shared: 'Shared infrastructure', none: 'Unassigned: no signal found',
  };
  const norm = (k) => k.toLowerCase().replace(/[-_ :./]/g, '');

  A.tabs.tags = {
    id: 'tags', title: 'Tags & governance',
    render(root) {
      const { res } = A.scope();
      const taggable = res.filter((r) => !r.type.startsWith('other:'));
      const untagged = taggable.filter(A.isUntagged);
      const projTagged = taggable.filter((r) => /^(tag|rule)/.test(r.project_source || ''));
      const unassigned = res.filter((r) => r.project === 'Unassigned');
      if (!res.length) { root.appendChild(A.empty('No resources match the current filters.')); return; }

      // key variants (Project / project / PROJECT ...)
      const variants = new Map();
      res.forEach((r) => Object.keys(r.tags || {}).filter((k) => !k.startsWith('aws:')).forEach((k) => {
        const n = norm(k);
        if (!variants.has(n)) variants.set(n, new Map());
        variants.get(n).set(k, (variants.get(n).get(k) || 0) + 1);
      }));
      const inconsistent = [...variants.values()].filter((m) => m.size > 1);
      const keyCounts = [...variants.values()].flatMap((m) => [...m.entries()]).sort((a, b) => b[1] - a[1]);

      root.appendChild(h('div', { class: 'stat-grid wide' },
        A.stat({ label: 'Resources with any tag', value: A.fmt.pct(taggable.length ? (100 * (taggable.length - untagged.length)) / taggable.length : 0), sub: `${A.fmt.num(untagged.length)} have none` }),
        A.stat({ label: 'Project coverage', value: A.fmt.pct(taggable.length ? (100 * projTagged.length) / taggable.length : 0), sub: 'project tag or explicit rule' }),
        A.stat({ label: 'Unassigned resources', value: A.fmt.num(unassigned.length), sub: A.fmt.usd(unassigned.reduce((s, r) => s + r.est_monthly_usd, 0)) + '/mo with no owner', tone: unassigned.length ? 'bad' : null,
          onClick: () => A.goto('inventory', { project: 'Unassigned' }) }),
        A.stat({ label: 'Inconsistent tag keys', value: A.fmt.num(inconsistent.length), sub: 'same key spelled differently', tone: inconsistent.length ? 'bad' : null })));

      const grid = h('div', { class: 'grid-2' });
      const byType = new Map();
      untagged.forEach((r) => byType.set(r.type, (byType.get(r.type) || 0) + 1));
      grid.appendChild(A.hbar({ title: 'Untagged resources by type', subtitle: 'Click to see them in the inventory', fmt: A.fmt.num, limit: 10,
        rows: [...byType.entries()].map(([t, n]) => ({ label: A.typeInfo(t).label, value: n, onClick: () => A.goto('inventory', { type: t, untagged: true }) })).sort((a, b) => b.value - a.value),
        empty: 'Every resource carries at least one tag.' }));
      const bySource = new Map();
      res.forEach((r) => { const s = (r.project_source || 'none').split(':')[0] || 'none'; bySource.set(s, (bySource.get(s) || 0) + 1); });
      grid.appendChild(A.hbar({ title: 'How each resource got its project', subtitle: 'Tags and rules are reliable; the rest are inferred and shown with their reason in the details panel',
        rows: [...bySource.entries()].map(([s, n]) => ({ label: SOURCE_LABEL[s] || s, value: n })).sort((a, b) => b.value - a.value), fmt: A.fmt.num }));
      root.appendChild(grid);

      if (inconsistent.length) {
        root.appendChild(A.card('Inconsistent tag keys', 'These behave as different tags in AWS (cost allocation, IAM conditions, filters). Pick one spelling.',
          h('div', { class: 'table-wrap' }, h('table', { class: 'data' }, h('thead', null, h('tr', null, h('th', { scope: 'col' }, 'Variants found'), h('th', { scope: 'col', class: 'num' }, 'Resources'))),
            h('tbody', null, inconsistent.map((m) => h('tr', null, h('th', { scope: 'row' }, [...m.entries()].sort((a, b) => b[1] - a[1]).map(([k, n]) => `${k} (${n})`).join('   ')),
              h('td', { class: 'num' }, A.fmt.num([...m.values()].reduce((s, x) => s + x, 0))))))))));
      }

      root.appendChild(A.hbar({ title: 'Most used tag keys', subtitle: 'Excludes aws: system tags', rows: keyCounts.slice(0, 12).map(([k, n]) => ({ label: k, value: n })), fmt: A.fmt.num }));

      const top = unassigned.slice().sort((a, b) => b.est_monthly_usd - a.est_monthly_usd).slice(0, 25);
      root.appendChild(A.card('Unassigned resources', 'No project tag, rule or naming signal. Add a Project tag in AWS, or a rule in config/analyzer.toml (python3 -m analyzer suggest-projects prints a starting point).',
        top.length ? h('div', { class: 'table-wrap' }, h('table', { class: 'data' },
          h('thead', null, h('tr', null, ['Resource', 'Type', 'Region', 'Est. / month'].map((c, i) => h('th', { scope: 'col', class: i === 3 ? 'num' : '' }, c)))),
          h('tbody', null, top.map((r) => h('tr', { class: 'clickable', tabindex: '0', onClick: () => A.drawer.open(r.key), onKeydown: (e) => { if (e.key === 'Enter') A.drawer.open(r.key); } },
            h('th', { scope: 'row' }, r.name || r.rid), h('td', null, A.typeChip(r.type)), h('td', null, r.region), h('td', { class: 'num' }, r.est_monthly_usd ? A.fmt.usd(r.est_monthly_usd) : '–')))))) : A.empty('Everything has an owner.')));
    },
  };
})();
