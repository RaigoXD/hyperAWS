/* Resource detail drawer. */
(function () {
  'use strict';
  const A = (window.AWSA = window.AWSA || {});
  const h = A.h;
  let el = null;
  let lastFocus = null;

  const SOURCE_TEXT = {
    rule: 'matched a rule in analyzer.toml',
    tag: 'from a project tag',
    stack: 'from the CloudFormation stack name (low confidence)',
    'name-match': 'name starts with a known project',
    inherited: 'inherited from a related resource (attached volume, target group, cluster ...)',
    'name-prefix': 'shared name prefix across several resources (low confidence)',
    shared: 'shared infrastructure: not owned by one project',
    none: 'no tag, rule or naming signal found',
  };
  A.sourceText = function sourceText(src) {
    const base = (src || 'none').split(':')[0] || 'none';
    const t = SOURCE_TEXT[base] || base;
    return src && src.includes(':') ? `${t} (${src.split(':')[1]})` : t;
  };

  function fmtVal(v) {
    if (v == null || v === '') return '–';
    if (typeof v === 'boolean') return v ? 'yes' : 'no';
    if (typeof v === 'number') return Number.isInteger(v) ? A.fmt.num(v) : String(Math.round(v * 1000) / 1000);
    if (Array.isArray(v)) return v.length ? v.map((x) => (typeof x === 'object' ? JSON.stringify(x) : String(x))).join(', ') : '–';
    if (typeof v === 'object') return JSON.stringify(v);
    return String(v);
  }

  function kvTable(obj, skip) {
    const rows = Object.entries(obj || {}).filter(([k]) => !(skip || []).includes(k));
    if (!rows.length) return h('p', { class: 'muted' }, 'None');
    return h('table', { class: 'kv' }, h('tbody', null, rows.map(([k, v]) => h('tr', null, h('th', { scope: 'row' }, k), h('td', null, fmtVal(v))))));
  }

  function relList(items, emptyText, incoming) {
    if (!items.length) return h('p', { class: 'muted' }, emptyText);
    return h('ul', { class: 'rel-list' }, items.slice(0, 60).map(({ key, kind, label }) => {
      const r = A.byKey.get(key);
      return h('li', null,
        h('span', { class: 'rel-kind', title: kind }, A.relText(kind, incoming) + (label ? ` · ${label}` : '')),
        r ? h('button', { class: 'linkbtn', type: 'button', onClick() { openDrawer(key); } }, A.groupKey(r.type), r.name || r.rid) : h('span', { class: 'muted' }, key.split(':').slice(2).join(':')));
    }).concat(items.length > 60 ? [h('li', { class: 'muted' }, `… and ${items.length - 60} more`)] : []));
  }

  function ensure() {
    if (el) return el;
    el = h('aside', { id: 'drawer', class: 'drawer', hidden: true, role: 'dialog', 'aria-modal': 'false', 'aria-label': 'Resource details' });
    document.body.appendChild(el);
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && !el.hidden) close(); });
    return el;
  }

  function openDrawer(key) {
    const r = A.byKey.get(key);
    if (!r) return;
    ensure();
    if (el.hidden) lastFocus = document.activeElement;
    const info = A.typeInfo(r.type);
    const out = (r.relations || []).map((x) => ({ key: x.to, kind: x.kind, label: x.label }));
    const inc = (A.incoming.get(key) || []).map((x) => ({ key: x.from, kind: x.kind, label: x.label }));
    const fs = A.findingsOf(r);
    A.clear(el);
    el.appendChild(h('header', { class: 'drawer-h' },
      h('div', { class: 'drawer-title' },
        h('div', { class: 'row gap' }, A.typeChip(r.type), r.state ? h('span', { class: 'state' }, A.dot(A.stateTone(r)), r.state) : null),
        h('h2', null, r.name || r.rid),
        r.name && r.name !== r.rid ? h('div', { class: 'mono muted' }, r.rid) : null),
      h('button', { class: 'icon-btn', type: 'button', 'aria-label': 'Close details', onClick: close }, '✕')));
    const body = h('div', { class: 'drawer-b' });
    body.appendChild(h('div', { class: 'row gap wrap' },
      h('button', { class: 'btn', type: 'button', onClick() { A.showOnMap(key); } }, 'Show on map'),
      A.showInCity ? h('button', { class: 'btn', type: 'button', onClick() { A.showInCity(key); } }, 'Show in 3D') : null,
      r.arn ? h('button', { class: 'btn', type: 'button', onClick(e) {
        const done = () => { e.target.textContent = 'Copied'; setTimeout(() => { e.target.textContent = 'Copy ARN'; }, 1200); };
        try { navigator.clipboard.writeText(r.arn).then(done, () => {}); } catch (err) { /* clipboard unavailable */ }
      } }, 'Copy ARN') : null));

    body.appendChild(h('dl', { class: 'facts' },
      ...[
        ['Account', r.account], ['Region', r.region === 'global' ? 'Global' : r.region],
        ['Project', h('span', null, r.project || '–', h('span', { class: 'muted' }, ' · ' + A.sourceText(r.project_source)))],
        ['Environment', r.env || 'unknown'], ['Created', r.created ? `${A.fmt.date(r.created)} (${A.fmt.age(r.created)} ago)` : '–'],
        ['Est. cost', r.est_monthly_usd ? h('span', null, h('strong', null, A.fmt.usd(r.est_monthly_usd) + '/mo'), h('span', { class: 'muted' }, ` · ${r.cost_conf || 'n/a'} confidence`)) : h('span', { class: 'muted' }, r.cost_basis || 'no fixed monthly cost')],
      ].flatMap(([k, v]) => [h('dt', null, k), h('dd', null, v)])));
    if (r.est_monthly_usd && r.cost_basis) body.appendChild(h('p', { class: 'basis' }, 'Basis: ' + r.cost_basis));

    body.appendChild(h('h4', null, `Findings (${fs.length})`));
    if (!fs.length) body.appendChild(h('p', { class: 'muted' }, 'No findings for this resource.'));
    fs.forEach((f) => body.appendChild(h('div', { class: 'mini-finding' },
      h('div', { class: 'row gap wrap' }, A.sevBadge(f.severity), h('strong', null, f.title), f.savings_usd ? h('span', { class: 'pill good' }, 'save ≈ ' + A.fmt.usd(f.savings_usd) + '/mo') : null),
      h('p', null, f.detail), h('p', { class: 'advice' }, f.advice),
      h('button', { class: 'linkbtn', type: 'button', onClick() { A.emit('goto-finding', f.id); } }, 'Open in Waste & findings'))));

    body.appendChild(h('h4', null, 'Depends on'));
    body.appendChild(relList(out, 'Nothing recorded.', false));
    body.appendChild(h('h4', null, 'Used by'));
    body.appendChild(relList(inc, 'Nothing recorded.', true));
    body.appendChild(h('h4', null, 'Attributes'));
    body.appendChild(kvTable(r.attrs, ['from_tagging']));
    const m = Object.assign({}, r.metrics || {});
    delete m._days;
    if (Object.keys(m).length) {
      body.appendChild(h('h4', null, 'CloudWatch metrics'));
      body.appendChild(kvTable(m));
    }
    body.appendChild(h('h4', null, `Tags (${Object.keys(r.tags || {}).length})`));
    body.appendChild(kvTable(r.tags));
    el.appendChild(body);
    el.hidden = false;
    el.querySelector('.icon-btn').focus();
    A.emit('drawer', key);
  }

  function close() {
    if (!el || el.hidden) return;
    el.hidden = true;
    if (lastFocus && document.contains(lastFocus)) { try { lastFocus.focus(); } catch (e) { /* ignore */ } }
    A.emit('drawer', null);
  }

  A.drawer = { open: openDrawer, close };
  A.openResource = openDrawer;
})();
