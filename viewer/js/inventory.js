/* Inventory tab: virtualised, sortable, searchable table + column chooser + CSV export. */
(function () {
  'use strict';
  const A = (window.AWSA = window.AWSA || {});
  const h = A.h;
  A.tabs = A.tabs || {};
  const ROW_H = 36;

  const COLS = [
    { id: 'name', label: 'Name', w: 'minmax(190px,2.2fr)', get: (r) => r.name || r.rid, cell: (r) => h('span', { class: 'cell-name' }, A.groupKey(r.type), h('span', { class: 'ellip' }, r.name || r.rid)) },
    { id: 'type', label: 'Type', w: 'minmax(120px,1fr)', get: (r) => A.typeInfo(r.type).label },
    { id: 'project', label: 'Project', w: 'minmax(110px,1fr)', get: (r) => r.project || '' },
    { id: 'env', label: 'Env', w: '78px', get: (r) => r.env || '' },
    { id: 'region', label: 'Region', w: '104px', get: (r) => r.region },
    { id: 'state', label: 'State', w: '104px', get: (r) => r.state || '', cell: (r) => (r.state ? h('span', { class: 'state' }, A.dot(A.stateTone(r)), r.state) : '') },
    { id: 'cost', label: '$/mo', w: '86px', num: true, get: (r) => r.est_monthly_usd, cell: (r) => (r.est_monthly_usd ? A.fmt.usd(r.est_monthly_usd) : '–') },
    { id: 'findings', label: 'Findings', w: '92px', num: true, get: (r) => (r.findings || []).length, cell: (r) => findingsCell(r) },
    { id: 'age', label: 'Age', w: '64px', num: true, get: (r) => (r.created ? Date.parse(r.created) : 0) * -1, cell: (r) => A.fmt.age(r.created) },
    { id: 'tags', label: 'Tags', w: '60px', num: true, get: (r) => Object.keys(r.tags || {}).filter((k) => !k.startsWith('aws:')).length, cell: (r) => { const n = Object.keys(r.tags || {}).filter((k) => !k.startsWith('aws:')).length; return n || h('span', { class: 'muted' }, '0'); } },
    { id: 'id', label: 'ID', w: 'minmax(150px,1.2fr)', get: (r) => r.rid, cell: (r) => h('span', { class: 'mono ellip' }, r.rid) },
    { id: 'account', label: 'Account', w: '120px', get: (r) => r.account },
  ];
  const DEFAULT_COLS = ['name', 'type', 'project', 'env', 'region', 'state', 'cost', 'findings', 'age', 'tags'];

  function findingsCell(r) {
    const fs = A.findingsOf(r);
    if (!fs.length) return h('span', { class: 'muted' }, '–');
    const w = A.worstSeverity(fs);
    return h('span', { class: 'sev', style: { '--sev': A.SEV[w].color }, title: fs.map((f) => f.title).join('\n') },
      h('span', { class: 'sev-icon', 'aria-hidden': 'true' }, A.SEV[w].icon), String(fs.length));
  }

  const st = { sort: 'cost', dir: -1, cols: null, type: '', state: '', group: '', onlyFindings: false, untagged: false };

  A.tabs.inventory = {
    id: 'inventory', title: 'Inventory',
    setState(s) {
      if (!s) return;
      Object.assign(st, { type: '', state: '', group: '', onlyFindings: false, untagged: false }, s);
      // global filters carried by a drill-down link (e.g. "Unassigned resources" from the Tags tab)
      const patch = {};
      for (const k of ['region', 'project']) { if (s[k]) patch[k] = s[k]; delete st[k]; }
      if (Object.keys(patch).length) A.setFilters(patch);
    },
    render(root) {
      if (!st.cols) st.cols = A.store.get('invcols', DEFAULT_COLS);
      const { res } = A.scope();
      let rows = res.filter((r) => (!st.type || r.type === st.type) && (!st.state || r.state === st.state) &&
        (!st.group || A.typeInfo(r.type).group === st.group) && (!st.onlyFindings || (r.findings || []).length) && (!st.untagged || A.isUntagged(r)));
      const col = COLS.find((c) => c.id === st.sort) || COLS[0];
      rows = rows.slice().sort((a, b) => {
        const x = col.get(a), y = col.get(b);
        const c = typeof x === 'number' && typeof y === 'number' ? x - y : String(x).localeCompare(String(y));
        return c * st.dir || String(a.name).localeCompare(String(b.name));
      });

      const types = [...new Set(res.map((r) => r.type))].sort((a, b) => A.typeInfo(a).label.localeCompare(A.typeInfo(b).label));
      const states = [...new Set(res.map((r) => r.state).filter(Boolean))].sort();
      const sel = (opts, val, on, all) => h('select', { class: 'sel', onChange: (e) => on(e.target.value), 'aria-label': all },
        h('option', { value: '' }, all), opts.map(([v, l]) => h('option', { value: v, selected: v === val }, l)));

      const count = h('span', { class: 'muted', 'aria-live': 'polite' }, `${A.fmt.num(rows.length)} of ${A.fmt.num(res.length)} resources`);
      const rerender = () => A.rerender();
      const tools = h('div', { class: 'toolbar' },
        sel(A.GROUPS.map((g) => [g.id, g.label]), st.group, (v) => { st.group = v; rerender(); }, 'All service groups'),
        sel(types.map((t) => [t, A.typeInfo(t).label]), st.type, (v) => { st.type = v; rerender(); }, 'All types'),
        sel(states.map((s) => [s, s]), st.state, (v) => { st.state = v; rerender(); }, 'Any state'),
        h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: st.onlyFindings, onChange: (e) => { st.onlyFindings = e.target.checked; rerender(); } }), 'With findings'),
        h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: st.untagged, onChange: (e) => { st.untagged = e.target.checked; rerender(); } }), 'Untagged only'),
        h('span', { class: 'grow' }), count,
        colChooser(rerender),
        h('button', { class: 'btn', type: 'button', onClick() {
          const cs = st.cols.map((id) => COLS.find((c) => c.id === id)).filter(Boolean);
          A.download('aws-inventory.csv', A.csv([cs.map((c) => c.label), ...rows.map((r) => cs.map((c) => (c.id === 'age' ? r.created || '' : c.get(r))))]), 'text/csv');
        } }, 'Export CSV'));
      root.appendChild(A.card(null, null, tools));
      if (!rows.length) { root.appendChild(A.empty('No resources match. Clear a filter above.')); return; }
      root.appendChild(vtable(rows, st.cols.map((id) => COLS.find((c) => c.id === id)).filter(Boolean)));
    },
  };

  function colChooser(rerender) {
    const wrap = h('details', { class: 'menu' }, h('summary', { class: 'btn' }, 'Columns'));
    const body = h('div', { class: 'menu-body' });
    COLS.forEach((c) => body.appendChild(h('label', { class: 'check' }, h('input', {
      type: 'checkbox', checked: st.cols.includes(c.id), disabled: c.id === 'name',
      onChange(e) {
        st.cols = COLS.map((x) => x.id).filter((id) => (id === c.id ? e.target.checked : st.cols.includes(id)));
        A.store.set('invcols', st.cols);
        rerender();
      },
    }), c.label)));
    wrap.appendChild(body);
    return wrap;
  }

  function vtable(rows, cols) {
    const tmpl = cols.map((c) => c.w).join(' ');
    const head = h('div', { class: 'vt-head', role: 'row', style: { gridTemplateColumns: tmpl } }, cols.map((c) => h('button', {
      class: 'vt-th' + (c.num ? ' num' : '') + (st.sort === c.id ? ' sorted' : ''), type: 'button', role: 'columnheader',
      'aria-sort': st.sort === c.id ? (st.dir > 0 ? 'ascending' : 'descending') : 'none',
      onClick() { if (st.sort === c.id) st.dir = -st.dir; else { st.sort = c.id; st.dir = c.num ? -1 : 1; } A.rerender(); },
    }, c.label, st.sort === c.id ? h('span', { 'aria-hidden': 'true' }, st.dir > 0 ? ' ▲' : ' ▼') : null)));
    const inner = h('div', { class: 'vt-inner', style: { height: rows.length * ROW_H + 'px' } });
    const scroller = h('div', { class: 'vt-scroll', role: 'rowgroup', tabindex: '0', 'aria-label': 'Resources' }, inner);
    const wrap = h('div', { class: 'vt card flush', role: 'table', 'aria-rowcount': String(rows.length + 1) }, head, scroller);
    let lastRange = '';
    function draw() {
      const top = scroller.scrollTop;
      const vh = scroller.clientHeight || 600;
      const from = Math.max(0, Math.floor(top / ROW_H) - 8);
      const to = Math.min(rows.length, Math.ceil((top + vh) / ROW_H) + 8);
      const range = from + ':' + to;
      if (range === lastRange) return;
      lastRange = range;
      A.clear(inner);
      for (let i = from; i < to; i++) {
        const r = rows[i];
        const tr = h('div', { class: 'vt-row', role: 'row', tabindex: '0', 'aria-rowindex': String(i + 2), style: { top: i * ROW_H + 'px', gridTemplateColumns: tmpl },
          onClick() { A.drawer.open(r.key); }, onKeydown(e) { if (e.key === 'Enter') A.drawer.open(r.key); } },
        cols.map((c) => h('div', { class: 'vt-td' + (c.num ? ' num' : ''), role: 'cell' }, c.cell ? c.cell(r) : String(c.get(r) ?? ''))));
        inner.appendChild(tr);
      }
    }
    let raf = 0;
    scroller.addEventListener('scroll', () => { cancelAnimationFrame(raf); raf = requestAnimationFrame(draw); });
    scroller.addEventListener('keydown', (e) => {
      const step = { ArrowDown: ROW_H, ArrowUp: -ROW_H, PageDown: scroller.clientHeight, PageUp: -scroller.clientHeight }[e.key];
      if (step) { e.preventDefault(); scroller.scrollTop += step; }
    });
    requestAnimationFrame(() => { lastRange = ''; draw(); });
    new ResizeObserver(() => { lastRange = ''; draw(); }).observe(scroller);
    return wrap;
  }
})();
