/* Chart + UI building blocks: stat tiles, horizontal bars, heatmap, badges.
 * Follows the dataviz rules: thin marks (<=24px, 4px data-end radius), hairline recessive grid,
 * text in text tokens (never series colour), tooltip never the only way to read a value (table twin). */
(function () {
  'use strict';
  const A = (window.AWSA = window.AWSA || {});
  const h = A.h;

  // ---- small atoms ------------------------------------------------------------------------
  A.sevBadge = function sevBadge(sev) {
    const s = A.SEV[sev] || A.SEV.info;
    return h('span', { class: 'sev', style: { '--sev': s.color }, title: `${s.label} severity` },
      h('span', { class: 'sev-icon', 'aria-hidden': 'true' }, s.icon), s.label);
  };
  A.pill = (text, cls) => h('span', { class: 'pill' + (cls ? ' ' + cls : '') }, text);
  A.dot = (tone) => h('span', { class: 'dot ' + (tone || 'none'), 'aria-hidden': 'true' });
  A.groupKey = function groupKey(type) {
    const g = A.groupById[A.typeInfo(type).group];
    return h('span', { class: 'gkey', style: { background: g.color }, title: g.label, 'aria-hidden': 'true' });
  };
  A.typeChip = function typeChip(type) {
    return h('span', { class: 'typechip' }, A.groupKey(type), A.typeInfo(type).label);
  };
  A.link = function link(text, onClick, title) {
    return h('button', { class: 'linkbtn', type: 'button', onClick, title }, text);
  };

  A.card = function card(title, subtitle, ...body) {
    return h('section', { class: 'card' },
      title ? h('header', { class: 'card-h' }, h('h3', null, title), subtitle ? h('p', { class: 'sub' }, subtitle) : null) : null,
      ...body);
  };

  // ---- stat tile / hero ---------------------------------------------------------------------------
  A.stat = function stat({ label, value, sub, onClick, tone }) {
    const el = h(onClick ? 'button' : 'div', { class: 'stat' + (onClick ? ' clickable' : '') + (tone ? ' tone-' + tone : ''), type: onClick ? 'button' : null, onClick },
      h('div', { class: 'stat-label' }, label),
      h('div', { class: 'stat-value' }, value),
      sub ? h('div', { class: 'stat-sub' }, sub) : null);
    return el;
  };

  // ---- table twin (WCAG-clean equivalent of every chart) ---------------------------------------------
  function tableTwin(cols, rows) {
    return h('div', { class: 'twin' }, h('table', { class: 'plain' },
      h('thead', null, h('tr', null, cols.map((c, i) => h('th', { scope: 'col', class: i ? 'num' : '' }, c)))),
      h('tbody', null, rows.map((r) => h('tr', null, r.map((c, i) => h(i ? 'td' : 'th', { scope: i ? null : 'row', class: i ? 'num' : '' }, c)))))));
  }

  function figure(title, subtitle, chartEl, twinEl) {
    const body = h('div', { class: 'fig-body' }, chartEl);
    let table = false;
    const btn = h('button', {
      class: 'ghost-btn', type: 'button', 'aria-pressed': 'false',
      onClick() {
        table = !table;
        btn.setAttribute('aria-pressed', String(table));
        btn.textContent = table ? 'Chart' : 'Table';
        A.clear(body).appendChild(table ? twinEl : chartEl);
      },
    }, 'Table');
    return h('figure', { class: 'card fig' },
      h('figcaption', { class: 'card-h row' }, h('div', null, h('h3', null, title), subtitle ? h('p', { class: 'sub' }, subtitle) : null), btn),
      body);
  }

  // ---- horizontal bars (nominal categories => one series, one colour) ------------------------------------
  /** rows: [{label, value, sub?, onClick?, color?}] */
  A.hbar = function hbar({ title, subtitle, rows, fmt, color, empty, limit, labelFor }) {
    const f = fmt || A.fmt.num;
    let data = rows.filter((r) => r.value > 0 || r.keepZero);
    if (limit && data.length > limit) {
      const rest = data.slice(limit - 1).reduce((s, r) => s + r.value, 0);
      const folded = data.length - limit + 1;
      data = data.slice(0, limit - 1).concat([{ label: `Other (${folded})`, value: rest }]);
    }
    const max = Math.max(1e-9, ...data.map((r) => r.value));
    const list = h('div', { class: 'bars', role: 'list' });
    if (!data.length) list.appendChild(h('p', { class: 'empty' }, empty || 'Nothing to show for the current filters.'));
    for (const r of data) {
      const frac = Math.max(0.004, r.value / max);
      const row = h(r.onClick ? 'button' : 'div', { class: 'bar-row' + (r.onClick ? ' clickable' : ''), role: 'listitem', type: r.onClick ? 'button' : null, onClick: r.onClick, tabindex: r.onClick ? null : '0' },
        h('span', { class: 'bar-label', title: r.label }, labelFor ? labelFor(r) : r.label),
        h('span', { class: 'bar-track' },
          h('span', { class: 'bar', style: { width: `calc((100% - 78px) * ${frac})`, background: r.color || color || 'var(--series-1)' } }),
          h('span', { class: 'bar-value' }, f(r.value))));
      A.tip.attach(row, () => h('div', null, h('div', { class: 'tt-value' }, f(r.value)), h('div', { class: 'tt-label' }, r.label), r.sub ? h('div', { class: 'tt-sub' }, r.sub) : null));
      list.appendChild(row);
    }
    const twin = tableTwin(['Item', 'Value'], data.map((r) => [r.label, f(r.value)]));
    return figure(title, subtitle, list, twin);
  };

  // ---- heatmap (sequential single hue; light = few) -----------------------------------------------------------
  A.heatmap = function heatmap({ title, subtitle, rows, cols, value, onCell, colLabel }) {
    const vals = [];
    rows.forEach((r) => cols.forEach((c) => { const v = value(r, c); if (v > 0) vals.push(v); }));
    const max = Math.max(1, ...vals);
    const steps = 7;
    const stepOf = (v) => (v <= 0 ? -1 : Math.min(steps - 1, Math.floor((Math.log(v + 1) / Math.log(max + 1)) * steps - 1e-9)));
    const grid = h('div', { class: 'heat', style: { gridTemplateColumns: `minmax(110px,auto) repeat(${cols.length}, minmax(46px,1fr))` } });
    grid.appendChild(h('div', { class: 'heat-corner' }));
    cols.forEach((c) => grid.appendChild(h('div', { class: 'heat-col', title: colLabel ? colLabel(c) : c }, colLabel ? colLabel(c) : c)));
    rows.forEach((r) => {
      grid.appendChild(h('div', { class: 'heat-row', title: r }, r));
      cols.forEach((c) => {
        const v = value(r, c);
        const s = stepOf(v);
        const cell = h(onCell && v ? 'button' : 'div', { class: 'heat-cell' + (s < 0 ? ' zero' : ` s${s}`), type: onCell && v ? 'button' : null,
          tabindex: v ? '0' : null, onClick: onCell && v ? () => onCell(r, c) : null }, v ? A.fmt.num(v) : '');
        if (v) A.tip.attach(cell, () => h('div', null, h('div', { class: 'tt-value' }, A.fmt.num(v)), h('div', { class: 'tt-label' }, `${r} · ${colLabel ? colLabel(c) : c}`)));
        grid.appendChild(cell);
      });
    });
    const legend = h('div', { class: 'heat-scale', 'aria-hidden': 'true' }, h('span', null, '1'),
      h('span', { class: 'heat-ramp' }, Array.from({ length: steps }, (_, i) => h('i', { class: 's' + i }))), h('span', null, A.fmt.num(max)));
    const twin = tableTwin(['Region', ...cols.map((c) => (colLabel ? colLabel(c) : c))], rows.map((r) => [r, ...cols.map((c) => A.fmt.num(value(r, c)))]));
    return figure(title, subtitle, h('div', { class: 'heat-wrap' }, grid, legend), twin);
  };

  // ---- legend for categorical keys --------------------------------------------------------------------------------
  A.groupLegend = function groupLegend(extra) {
    return h('ul', { class: 'legend' }, A.GROUPS.map((g) => h('li', null, h('span', { class: 'gkey', style: { background: g.color }, 'aria-hidden': 'true' }), g.label)), extra || null);
  };

  // ---- page-level helper: empty state ---------------------------------------------------------------------------------
  A.empty = (msg) => h('div', { class: 'empty-state' }, h('p', null, msg));

  // ---- segmented control / chips ---------------------------------------------------------------------------------------------
  A.segmented = function segmented(options, value, onChange, label) {
    const wrap = h('div', { class: 'seg', role: 'group', 'aria-label': label || null });
    options.forEach((o) => {
      const b = h('button', { type: 'button', class: o.id === value ? 'on' : '', 'aria-pressed': String(o.id === value),
        onClick() { onChange(o.id); } }, o.label);
      wrap.appendChild(b);
    });
    return wrap;
  };
  A.chips = function chips(options, selected, onToggle) {
    return h('div', { class: 'chips' }, options.map((o) => h('button', {
      type: 'button', class: 'chip' + (selected.has(o.id) ? ' on' : ''), 'aria-pressed': String(selected.has(o.id)),
      onClick() { onToggle(o.id); },
    }, o.label, o.count != null ? h('span', { class: 'chip-n' }, A.fmt.num(o.count)) : null)));
  };
})();
