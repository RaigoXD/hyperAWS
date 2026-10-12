/* Waste & findings tab: grouped list (with explanations) and a map of the flagged components. */
(function () {
  'use strict';
  const A = (window.AWSA = window.AWSA || {});
  const h = A.h;
  A.tabs = A.tabs || {};

  const ALL_CATS = Object.keys(A.CATEGORIES);
  const st = { cats: new Set(ALL_CATS), mapCats: new Set(['unused', 'hygiene']), severity: '', conf: '', q: '', view: 'list', open: new Set(), ctx: true, kinds: null, show: new Set(), expanded: new Set(), colorBy: 'group', mapQ: '' };

  function matches(f, cats) {
    if (!(cats || st.cats).has(f.category)) return false;
    if (st.severity && f.severity !== st.severity) return false;
    if (st.conf && f.confidence !== st.conf) return false;
    if (st.q) {
      const q = st.q.toLowerCase();
      if (!(f.title + ' ' + f.detail + ' ' + f.rule + ' ' + (f.project || '')).toLowerCase().includes(q)) return false;
    }
    return true;
  }

  function findingRow(f, keys) {
    const sav = A.scopedSavings(f, keys);
    const open = st.open.has(f.id);
    const head = h('button', { class: 'f-head', type: 'button', 'aria-expanded': String(open),
      onClick() { open ? st.open.delete(f.id) : st.open.add(f.id); A.rerender(); } },
    h('span', { class: 'f-sev' }, A.sevBadge(f.severity)),
    h('span', { class: 'f-title' }, f.title),
    h('span', { class: 'f-meta' }, [f.project && f.project !== 'multiple' ? f.project : null, f.region && f.region !== 'multiple' ? f.region : null,
      f.resources.length > 1 ? A.fmt.plural(f.resources.length, 'resource') : null].filter(Boolean).join(' · ')),
    h('span', { class: 'f-save' }, f.priced === false ? h('span', { class: 'pill', title: 'The price of this resource type is not in the reference table, so the saving is unknown (not zero)' }, 'unpriced')
      : sav ? A.fmt.usd(sav) + '/mo' : h('span', { class: 'muted' }, '–')),
    h('span', { class: 'chev', 'aria-hidden': 'true' }, open ? '▾' : '▸'));
    const row = h('li', { class: 'finding' + (open ? ' open' : ''), id: 'f-' + f.id.replace(/[^a-zA-Z0-9]/g, '_') }, head);
    if (open) {
      const rs = f.resources.map((k) => A.byKey.get(k)).filter(Boolean);
      row.appendChild(h('div', { class: 'f-body' },
        h('p', null, f.detail),
        h('p', { class: 'advice' }, h('strong', null, 'What to do: '), f.advice),
        f.basis ? h('p', { class: 'basis' }, h('strong', null, 'How the saving is estimated: '), f.basis) : null,
        h('div', { class: 'row gap wrap meta' }, A.pill('Confidence: ' + f.confidence), A.pill('Effort: ' + f.effort), A.pill('Risk: ' + f.risk), A.pill(A.CATEGORIES[f.category]), A.pill(f.rule, 'mono')),
        rs.length ? h('div', { class: 'f-res' }, h('h4', null, 'Affected resources'),
          h('ul', { class: 'res-chips' }, rs.slice(0, 14).map((r) => h('li', null, h('button', { class: 'linkbtn', type: 'button', onClick() { A.drawer.open(r.key); } }, A.groupKey(r.type), r.name || r.rid,
            f.breakdown[r.key] ? h('span', { class: 'muted' }, ' ' + A.fmt.usd(f.breakdown[r.key])) : null))),
          rs.length > 14 ? [h('li', { class: 'muted' }, `+ ${rs.length - 14} more`)] : []),
          h('button', { class: 'btn', type: 'button', onClick() { A.showOnMap(rs[0].key); } }, 'Show on map')) : null));
    }
    return row;
  }

  A.tabs.waste = {
    id: 'waste', title: 'Waste & findings',
    setState(s) {
      if (!s) return;
      if (s.category) { st.cats = new Set([s.category]); }
      if (s.severity !== undefined) { st.severity = s.severity; if (s.severity) st.cats = new Set(ALL_CATS); }
      if (s.open) { st.open.add(s.open); st.cats = new Set(ALL_CATS); st.severity = ''; st.conf = ''; st.q = ''; st.view = 'list'; st.scrollTo = s.open; }
      if (s.reset) { st.cats = new Set(ALL_CATS); st.severity = ''; st.conf = ''; st.q = ''; }
    },
    render(root) {
      const { keys, findings } = A.scope();
      const list = findings.filter((f) => matches(f));
      const unusedRes = new Set();
      findings.filter((f) => f.category === 'unused').forEach((f) => f.resources.forEach((k) => keys.has(k) && unusedRes.add(k)));
      const quick = findings.filter((f) => f.in_total && A.confRank(f.confidence) >= 2 && f.effort === 'low' && f.risk === 'low');
      root.appendChild(h('div', { class: 'stat-grid wide' },
        A.stat({ label: 'Potential savings', value: A.fmt.usd(A.potential(findings, keys)) + '/mo', sub: 'each resource counted once' }),
        A.stat({ label: 'Quick wins', value: A.fmt.usd(A.potential(quick, keys)) + '/mo', sub: `${quick.length} low-effort, low-risk, solid-confidence findings` }),
        A.stat({ label: 'Unused resources', value: A.fmt.num(unusedRes.size), sub: 'flagged as not being used' }),
        A.stat({ label: 'Security findings', value: A.fmt.num(findings.filter((f) => f.category === 'security').length), sub: `${findings.filter((f) => f.category === 'security' && f.severity === 'high').length} high severity` })));

      const catCount = (c) => findings.filter((f) => f.category === c).length;
      const key = st.view === 'map' ? 'mapCats' : 'cats';   // the map has its own category selection
      const tools = h('div', { class: 'toolbar wrap' },
        A.chips(ALL_CATS.map((c) => ({ id: c, label: A.CATEGORIES[c], count: catCount(c) })), st[key], (c) => {
          st[key].has(c) ? st[key].delete(c) : st[key].add(c);
          if (!st[key].size) st[key] = new Set(key === 'cats' ? ALL_CATS : ['unused']);
          A.rerender();
        }),
        h('select', { class: 'sel', 'aria-label': 'Severity', onChange: (e) => { st.severity = e.target.value; A.rerender(); } }, h('option', { value: '' }, 'Any severity'),
          Object.keys(A.SEV).map((s) => h('option', { value: s, selected: st.severity === s }, A.SEV[s].label))),
        h('select', { class: 'sel', 'aria-label': 'Confidence', onChange: (e) => { st.conf = e.target.value; A.rerender(); } }, h('option', { value: '' }, 'Any confidence'),
          ['high', 'medium', 'low'].map((s) => h('option', { value: s, selected: st.conf === s }, s[0].toUpperCase() + s.slice(1) + ' confidence'))),
        h('input', { class: 'inp', type: 'search', placeholder: 'Search findings…', 'aria-label': 'Search findings', value: st.q, dataset: { focusKey: 'waste-q' },
          onInput: A.debounce((e) => { st.q = e.target.value; A.rerender(); }, 200) }),
        h('span', { class: 'grow' }),
        A.segmented([{ id: 'list', label: 'List' }, { id: 'map', label: 'Map' }], st.view, (v) => { st.view = v; A.rerender(); }, 'View'));
      root.appendChild(A.card(null, null, tools));

      if (st.view === 'map') return mapView(root, list);
      if (!list.length) { root.appendChild(A.empty('No findings match. Clear a filter above.')); return; }
      for (const cat of ALL_CATS) {
        const fs = list.filter((f) => f.category === cat)
          .sort((a, b) => (A.scopedSavings(b, keys) - A.scopedSavings(a, keys)) || (A.SEV[a.severity].rank - A.SEV[b.severity].rank));
        if (!fs.length) continue;
        const total = A.potential(fs, keys);
        root.appendChild(h('section', { class: 'card' },
          h('header', { class: 'card-h row' }, h('div', null, h('h3', null, `${A.CATEGORIES[cat]} (${fs.length})`),
            h('p', { class: 'sub' }, CAT_HELP[cat])), total ? h('span', { class: 'pill good' }, `≈ ${A.fmt.usd(total)}/mo`) : null),
          h('ul', { class: 'findings' }, fs.map((f) => findingRow(f, keys)))));
      }
      if (st.scrollTo) {
        const id = 'f-' + st.scrollTo.replace(/[^a-zA-Z0-9]/g, '_');
        st.scrollTo = null;
        setTimeout(() => { const el = document.getElementById(id); if (el) el.scrollIntoView({ block: 'center' }); }, 30);
      }
    },
  };

  const CAT_HELP = {
    unused: 'Resources that are running, reserved or stored but not doing anything.',
    rightsizing: 'Things that are bigger, redundant or more provisioned than they need to be.',
    'cost-insight': 'Account-wide opportunities from typical discounts; estimates are approximate.',
    security: 'Risky configuration found while reading the inventory (read-only, no scanning).',
    hygiene: 'Clutter and leftovers: low or no cost, but worth cleaning.',
  };

  function mapView(root, list) {
    const { res } = A.scope();
    if (!st.kinds) st.kinds = new Set(A.EDGE_KINDS.filter((k) => k.on).map((k) => k.id));
    const host = h('div', { class: 'graph-wrap' });
    const gv = new A.GraphView(host, { mode: 'waste', project: A.filters.project, show: st.show, kinds: st.kinds, expanded: st.expanded, colorBy: st.colorBy,
      findingOk: (f) => matches(f, st.mapCats), context: st.ctx, onSelect: (k) => A.drawer.open(k) });
    const redraw = () => { gv.o.context = st.ctx; gv.render(res); gv.setQuery(st.mapQ); };
    const c = A.graphControls(gv, { q: st.mapQ }, redraw);
    c.search.addEventListener('input', () => { st.mapQ = c.search.value; });
    const ctx = h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: st.ctx, onChange(e) { st.ctx = e.target.checked; redraw(); } }), 'Show related resources');
    root.appendChild(A.card(null, null, h('div', { class: 'toolbar' }, c.search, ctx, c.kinds, h('span', { class: 'grow' }), c.zoom),
      h('p', { class: 'hint' }, 'Only components with the selected kinds of findings are drawn (default: unused and hygiene; change the chips above). Dashed outline = unused. Related resources appear dimmed for context.')));
    root.appendChild(h('div', { class: 'card flush graph-card' }, host, A.mapLegend()));
    redraw();
    A.cleanup(() => gv.destroy());
  }

  A.on('goto-finding', (id) => A.goto('waste', { open: id }));
})();
