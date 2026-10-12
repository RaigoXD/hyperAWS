/* Cost & optimization tab: ranked recommendations, per-project economics, biggest line items, Cost Explorer. */
(function () {
  'use strict';
  const A = (window.AWSA = window.AWSA || {});
  const h = A.h;
  A.tabs = A.tabs || {};

  const st = { mode: 'all', open: new Set() };

  A.tabs.cost = {
    id: 'cost', title: 'Cost & optimization',
    render(root) {
      const { res, keys, findings } = A.scope();
      const cost = res.reduce((s, r) => s + r.est_monthly_usd, 0);
      const pot = A.potential(findings, keys);
      const potSure = A.potential(findings, keys, 'medium');
      const pricing = A.data.pricing || {};

      root.appendChild(h('div', { class: 'stat-grid wide' },
        A.stat({ label: 'Estimated cost', value: A.fmt.usd(cost) + '/mo', sub: 'baseline charges from list prices' }),
        A.stat({ label: 'Potential savings', value: A.fmt.usd(pot) + '/mo', sub: `${cost ? Math.round((100 * pot) / cost) : 0}% of estimated cost` }),
        A.stat({ label: 'Of which solid', value: A.fmt.usd(potSure) + '/mo', sub: 'high or medium confidence' }),
        A.stat({ label: 'Annualised', value: A.fmt.usdc(potSure * 12) + '/yr', sub: 'solid savings × 12' })));
      root.appendChild(h('div', { class: 'notice' }, h('strong', null, 'These are estimates, not your bill. '),
        pricing.note || '', pricing.as_of ? ` Prices as of ${pricing.as_of}.` : '', ' Compare with Cost Explorer before committing to big changes.'));

      // ---- recommendations --------------------------------------------------------------------------
      let recs = findings.filter((f) => f.in_total || f.savings_usd > 0).map((f) => ({ f, sav: A.scopedSavings(f, keys) })).filter((x) => x.sav > 0);
      const quick = (x) => A.confRank(x.f.confidence) >= 2 && x.f.effort === 'low' && x.f.risk === 'low';
      if (st.mode === 'quick') recs = recs.filter(quick);
      else if (st.mode === 'effort') recs = recs.filter((x) => x.f.effort !== 'low');
      recs.sort((a, b) => (Number(b.f.in_total) - Number(a.f.in_total)) || b.sav - a.sav);   // headline-counted findings first

      const modeSeg = A.segmented([{ id: 'all', label: 'All' }, { id: 'quick', label: 'Quick wins' }, { id: 'effort', label: 'Needs effort' }], st.mode, (v) => { st.mode = v; A.rerender(); }, 'Filter recommendations');
      const table = h('table', { class: 'data recs' },
        h('thead', null, h('tr', null, ['#', 'Recommendation', 'Saves / month', 'Effort', 'Risk', 'Confidence'].map((c, i) => h('th', { scope: 'col', class: i === 2 ? 'num' : '' }, c)))),
        h('tbody', null, recs.slice(0, 60).flatMap(({ f, sav }, i) => {
          const open = st.open.has(f.id);
          const tr = h('tr', { class: 'clickable', tabindex: '0', 'aria-expanded': String(open),
            onClick() { open ? st.open.delete(f.id) : st.open.add(f.id); A.rerender(); },
            onKeydown(e) { if (e.key === 'Enter') { open ? st.open.delete(f.id) : st.open.add(f.id); A.rerender(); } } },
          h('td', { class: 'num muted' }, String(i + 1)),
          h('td', null, h('div', { class: 'rec-title' }, A.sevBadge(f.severity), f.title), h('div', { class: 'muted small' }, [f.project && f.project !== 'multiple' ? f.project : null, f.region && f.region !== 'multiple' ? f.region : null, f.in_total ? null : 'not in headline total'].filter(Boolean).join(' · '))),
          h('td', { class: 'num strong' }, A.fmt.usd(sav)),
          h('td', null, f.effort), h('td', null, f.risk), h('td', null, f.confidence));
          const rows = [tr];
          if (open) rows.push(h('tr', { class: 'rec-detail' }, h('td', null), h('td', { colspan: '5' },
            h('p', null, f.detail), h('p', { class: 'advice' }, h('strong', null, 'What to do: '), f.advice),
            f.basis ? h('p', { class: 'basis' }, h('strong', null, 'Estimate: '), f.basis) : null,
            A.link('Open in Waste & findings', () => A.goto('waste', { open: f.id })))));
          return rows;
        })));
      root.appendChild(A.card('Ranked recommendations', 'Biggest estimated monthly savings first. Click a row for the reasoning.',
        h('div', { class: 'toolbar' }, modeSeg, h('span', { class: 'grow' }), h('span', { class: 'muted' }, `${recs.length} shown${recs.length > 60 ? ' (top 60)' : ''}`)),
        recs.length ? h('div', { class: 'table-wrap' }, table) : A.empty('Nothing to recommend for this scope.')));

      // ---- effort chart + project economics ------------------------------------------------------------------
      const byEffort = ['low', 'medium', 'high'].map((e) => ({ label: e[0].toUpperCase() + e.slice(1) + ' effort', value: A.potential(findings.filter((f) => f.effort === e), keys) }));
      const grid = h('div', { class: 'grid-2' });
      grid.appendChild(A.hbar({ title: 'Savings by effort', subtitle: 'Where to start: the low-effort bar is your quick-win pile', rows: byEffort, fmt: A.fmt.usd }));
      const projects = new Map();
      res.forEach((r) => { const p = projects.get(r.project) || { name: r.project, cost: 0, n: 0 }; p.cost += r.est_monthly_usd; p.n++; projects.set(r.project, p); });
      const potBy = new Map();
      findings.filter((f) => f.in_total).forEach((f) => Object.entries(f.breakdown || {}).forEach(([k, v]) => { if (keys.has(k)) { const r = A.byKey.get(k); const cur = potBy.get(k) || 0; if (v > cur) potBy.set(k, v); } }));
      const projSave = new Map();
      potBy.forEach((v, k) => { const p = A.byKey.get(k).project; projSave.set(p, (projSave.get(p) || 0) + v); });
      const prows = [...projects.values()].sort((a, b) => b.cost - a.cost).slice(0, 12);
      grid.appendChild(A.card('Cost and savings by project', 'Click a project to focus everything on it',
        h('div', { class: 'table-wrap' }, h('table', { class: 'data' },
          h('thead', null, h('tr', null, ['Project', 'Resources', 'Est. cost', 'Savings', '%'].map((c, i) => h('th', { scope: 'col', class: i ? 'num' : '' }, c)))),
          h('tbody', null, prows.map((p) => h('tr', { class: 'clickable', tabindex: '0', onClick: () => A.setFilters({ project: p.name }), onKeydown: (e) => { if (e.key === 'Enter') A.setFilters({ project: p.name }); } },
            h('th', { scope: 'row' }, p.name), h('td', { class: 'num' }, A.fmt.num(p.n)), h('td', { class: 'num' }, A.fmt.usd(p.cost)),
            h('td', { class: 'num strong' }, A.fmt.usd(projSave.get(p.name) || 0)), h('td', { class: 'num muted' }, p.cost ? Math.round((100 * (projSave.get(p.name) || 0)) / p.cost) + '%' : '–'))))))));
      root.appendChild(grid);

      // ---- biggest line items -------------------------------------------------------------------------------------------
      const big = res.filter((r) => r.est_monthly_usd > 0).sort((a, b) => b.est_monthly_usd - a.est_monthly_usd).slice(0, 15);
      root.appendChild(A.card('Biggest line items', 'The most expensive individual resources by estimate',
        h('div', { class: 'table-wrap' }, h('table', { class: 'data' },
          h('thead', null, h('tr', null, ['Resource', 'Type', 'Project', 'Est. / month', 'How it is estimated'].map((c, i) => h('th', { scope: 'col', class: i === 3 ? 'num' : '' }, c)))),
          h('tbody', null, big.map((r) => h('tr', { class: 'clickable', tabindex: '0', onClick: () => A.drawer.open(r.key), onKeydown: (e) => { if (e.key === 'Enter') A.drawer.open(r.key); } },
            h('th', { scope: 'row' }, r.name || r.rid), h('td', null, A.typeChip(r.type)), h('td', null, r.project), h('td', { class: 'num strong' }, A.fmt.usd(r.est_monthly_usd)),
            h('td', { class: 'muted small' }, r.cost_basis))))))));

      // ---- Cost Explorer (only when the scan was run with --cost-explorer) -------------------------------------------------
      (A.data.cost_explorer || []).forEach((ce) => {
        if (!ce || ce.error) { root.appendChild(A.card('Cost Explorer', null, h('p', { class: 'muted' }, 'Cost Explorer data was requested but could not be read: ' + (ce && ce.error || 'unknown error')))); return; }
        const sec = h('div', { class: 'grid-2' });
        sec.appendChild(A.hbar({ title: `Actual spend by service (${ce.period.start} → ${ce.period.end})`, subtitle: `Account ${ce.account}: real billed cost from Cost Explorer, total ${A.fmt.usd(ce.total)}`,
          rows: (ce.by_service || []).map((x) => ({ label: x.name, value: x.usd })), fmt: A.fmt.usd, limit: 12 }));
        if (ce.by_tag && ce.by_tag.groups && ce.by_tag.groups.length) {
          sec.appendChild(A.hbar({ title: `Actual spend by tag “${ce.by_tag.key}”`, subtitle: 'Only resources with cost-allocation tags activated are attributed',
            rows: ce.by_tag.groups.map((x) => ({ label: x.name || '(untagged)', value: x.usd })), fmt: A.fmt.usd, limit: 12 }));
        }
        root.appendChild(sec);
        if ((ce.rightsizing || []).length) {
          root.appendChild(A.card('AWS rightsizing recommendations (Cost Explorer)', 'Straight from AWS: compare with the estimates above',
            h('div', { class: 'table-wrap' }, h('table', { class: 'data' },
              h('thead', null, h('tr', null, ['Instance', 'Action', 'Current', 'Recommended', 'Est. saving / mo'].map((c, i) => h('th', { scope: 'col', class: i === 4 ? 'num' : '' }, c)))),
              h('tbody', null, ce.rightsizing.slice(0, 25).map((x) => h('tr', null, h('th', { scope: 'row' }, x.id), h('td', null, x.action), h('td', null, x.current), h('td', null, x.recommended), h('td', { class: 'num strong' }, A.fmt.usd(x.saving)))))))));
        }
      });
    },
  };
})();
