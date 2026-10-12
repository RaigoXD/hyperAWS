/* App shell: header, tabs, global filters, routing, theme, loading a file by drag & drop. */
(function () {
  'use strict';
  const A = (window.AWSA = window.AWSA || {});
  const h = A.h;

  const ORDER = ['overview', 'inventory', 'map', 'city', 'waste', 'cost', 'tags', 'scan'];
  A.route = { tab: 'overview' };
  let cleanups = [];
  let els = {};
  A.cleanup = (fn) => cleanups.push(fn);

  // ---- theme ------------------------------------------------------------------------------------------
  const THEMES = ['auto', 'light', 'dark'];
  function applyTheme(t) {
    if (t === 'auto') document.documentElement.removeAttribute('data-theme');
    else document.documentElement.setAttribute('data-theme', t);
    A.emit('theme', t);                 // canvas views (the 3D map) re-read the colour tokens
  }
  applyTheme(A.store.get('theme', 'auto'));
  try {
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => { if (A.store.get('theme', 'auto') === 'auto') A.emit('theme', 'auto'); });
  } catch (e) { /* old browsers */ }

  // ---- hash state: #tab?account=..&region=..&project=..&env=..&q=.. -------------------------------------------
  function readHash() {
    const raw = location.hash.replace(/^#/, '');
    const [tab, qs] = raw.split('?');
    const out = { tab: A.tabs[tab] ? tab : null, filters: {} };
    new URLSearchParams(qs || '').forEach((v, k) => { if (k in A.filters) out.filters[k] = v; });
    return out;
  }
  function syncHash() {
    const p = new URLSearchParams();
    Object.entries(A.filters).forEach(([k, v]) => { if (v) p.set(k, v); });
    const hash = '#' + A.route.tab + (p.toString() ? '?' + p : '');
    try { history.replaceState(null, '', hash); } catch (e) { /* file:// in some browsers */ }
  }

  // ---- routing / rendering ----------------------------------------------------------------------------------------
  A.goto = function goto(tab, state) {
    const t = A.tabs[tab];
    if (!t) return;
    if (t.setState) t.setState(state);
    const changed = A.route.tab !== tab;
    A.route.tab = tab;
    A.drawer.close();
    A.rerender(changed);
  };

  A.rerender = function rerender(toTop) {
    if (!A.data) return;
    const y = window.scrollY;
    const ae = document.activeElement;
    const focusKey = ae && ae.dataset ? ae.dataset.focusKey : null;      // inputs the user is typing in
    const caret = focusKey && typeof ae.selectionStart === 'number' ? ae.selectionStart : null;
    cleanups.forEach((fn) => { try { fn(); } catch (e) { /* ignore */ } });
    cleanups = [];
    A.tip.hide();
    const tab = A.tabs[A.route.tab];
    A.clear(els.main);
    els.main.setAttribute('aria-labelledby', 'tab-' + tab.id);
    tab.render(els.main);
    updateChrome();
    syncHash();
    window.scrollTo(0, toTop ? 0 : y);
    if (focusKey && !toTop) {
      const el = document.querySelector(`[data-focus-key="${focusKey}"]`);
      if (el) { el.focus({ preventScroll: true }); if (caret != null && el.setSelectionRange) el.setSelectionRange(caret, caret); }
    }
  };

  function updateChrome() {
    ORDER.forEach((id) => {
      const b = els.tabs[id];
      const on = id === A.route.tab;
      b.classList.toggle('on', on);
      b.setAttribute('aria-selected', String(on));
      b.tabIndex = on ? 0 : -1;
    });
    els.filters.hidden = A.route.tab === 'scan';
    const f = A.facets();
    const fill = (sel, opts, val) => {
      A.clear(sel).appendChild(h('option', { value: '' }, sel.dataset.all));
      opts.forEach((o) => sel.appendChild(h('option', { value: o, selected: o === val }, o === 'global' ? 'Global' : o)));
      sel.value = val;
    };
    fill(els.account, f.accounts, A.filters.account);
    fill(els.region, f.regions, A.filters.region);
    fill(els.project, f.projects, A.filters.project);
    fill(els.env, f.envs, A.filters.env);
    els.account.hidden = f.accounts.length < 2;
    if (document.activeElement !== els.q) els.q.value = A.filters.q;
    const s = A.scope();
    els.count.textContent = `${A.fmt.num(s.res.length)} of ${A.fmt.num(A.res.length)} resources · ${A.fmt.num(s.findings.length)} findings`;
    els.clear.hidden = !Object.values(A.filters).some(Boolean);
  }

  // ---- shell -------------------------------------------------------------------------------------------------------------
  function buildShell() {
    const root = A.clear(document.getElementById('root'));
    const d = A.data;
    const a = d.accounts || [];
    const themeBtn = h('button', { class: 'btn', type: 'button', title: 'Switch between automatic, light and dark theme',
      onClick() {
        const cur = A.store.get('theme', 'auto');
        const next = THEMES[(THEMES.indexOf(cur) + 1) % THEMES.length];
        A.store.set('theme', next); applyTheme(next); themeBtn.textContent = 'Theme: ' + next;
      } }, 'Theme: ' + A.store.get('theme', 'auto'));
    const file = h('input', { type: 'file', accept: '.json,application/json', hidden: true, onChange(e) { if (e.target.files[0]) A.loadFile(e.target.files[0]); } });
    const header = h('header', { class: 'topbar' },
      h('div', { class: 'brand' }, h('span', { class: 'logo', 'aria-hidden': 'true' }, '◩'), h('h1', null, 'AWS Analyzer')),
      h('div', { class: 'meta' },
        a.length ? h('span', { class: 'chip static' }, (a.length === 1 ? 'Account ' : 'Accounts ') + a.map((x) => x.account).join(', ')) : null,
        d.scanned_at ? h('span', { class: 'chip static' }, 'Scanned ' + d.scanned_at.replace('T', ' ').replace('Z', ' UTC')) : null,
        h('span', { class: 'chip static ok', title: 'See the Scan info tab for the full audit log' }, '✓ read-only')),
      h('div', { class: 'row gap' }, h('button', { class: 'btn', type: 'button', onClick: () => file.click() }, 'Open another file…'), file, themeBtn));

    const tabs = h('nav', { class: 'tabs', role: 'tablist', 'aria-label': 'Sections' });
    els.tabs = {};
    ORDER.forEach((id) => {
      const t = A.tabs[id];
      const b = h('button', { id: 'tab-' + id, class: 'tab', role: 'tab', type: 'button', 'aria-selected': 'false', 'aria-controls': 'main',
        onClick() { A.goto(id); },
        onKeydown(e) {
          const i = ORDER.indexOf(id);
          const j = e.key === 'ArrowRight' ? (i + 1) % ORDER.length : e.key === 'ArrowLeft' ? (i + ORDER.length - 1) % ORDER.length : e.key === 'Home' ? 0 : e.key === 'End' ? ORDER.length - 1 : -1;
          if (j >= 0) { e.preventDefault(); A.goto(ORDER[j]); els.tabs[ORDER[j]].focus(); }
        } }, t.title);
      els.tabs[id] = b;
      tabs.appendChild(b);
    });

    const sel = (key, all, label) => h('select', { class: 'sel', 'aria-label': label, 'data-all': all,
      onChange(e) { const patch = {}; patch[key] = e.target.value; A.setFilters(patch); } });   // no computed keys (audit)
    els.account = sel('account', 'All accounts', 'Account');
    els.region = sel('region', 'All regions', 'Region');
    els.project = sel('project', 'All projects', 'Project');
    els.env = sel('env', 'All environments', 'Environment');
    els.q = h('input', { class: 'inp', type: 'search', placeholder: 'Search name, id, tag…', 'aria-label': 'Search resources',
      onInput: A.debounce((e) => A.setFilters({ q: e.target.value }), 200) });
    els.count = h('span', { class: 'muted', 'aria-live': 'polite' });
    els.clear = h('button', { class: 'linkbtn', type: 'button', onClick() { A.setFilters({ account: '', region: '', project: '', env: '', q: '' }); } }, 'Clear filters');
    els.filters = h('div', { class: 'filters', role: 'search', 'aria-label': 'Filters (apply to every section)' }, els.account, els.region, els.project, els.env, els.q, els.clear, h('span', { class: 'grow' }), els.count);
    els.main = h('main', { id: 'main', class: 'main', role: 'tabpanel' });

    root.append(header, tabs, els.filters, els.main,
      h('footer', { class: 'footer muted small' }, 'Read-only analysis of AWS CLI output. Cost figures are estimates from list prices, not your bill. This page makes no network requests.'));
  }

  // ---- landing + loading ----------------------------------------------------------------------------------------------------
  function landing(message) {
    const root = A.clear(document.getElementById('root'));
    const file = h('input', { type: 'file', accept: '.json,application/json', hidden: true, onChange(e) { if (e.target.files[0]) A.loadFile(e.target.files[0]); } });
    root.appendChild(h('div', { class: 'landing' },
      h('div', { class: 'card drop', tabindex: '0', role: 'button', 'aria-label': 'Choose an analysis JSON file', onClick: () => file.click(),
        onKeydown(e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); file.click(); } } },
      h('h1', null, 'AWS Analyzer'),
      h('p', null, 'Drop an ', h('code', null, 'analysis-*.json'), ' file here, or click to choose one.'),
      message ? h('p', { class: 'notice bad', role: 'alert' }, message) : null,
      h('p', { class: 'muted small' }, 'Create one with: ', h('code', null, 'python3 -m analyzer run --profile <name>'), '. Everything stays in your browser; nothing is uploaded.'), file)));
  }

  A.loadFile = function loadFile(f) {
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const data = JSON.parse(String(reader.result));
        if (!data.resources) throw new Error('not an analysis file');
        if (!data.findings || !data.summary) { landing('This looks like a raw scan file. Run “python3 -m analyzer analyze” on it first, then load the analysis-*.json.'); return; }
        start(data);
      } catch (e) { landing('Could not read that file: ' + e.message); }
    };
    reader.readAsText(f);
  };
  window.addEventListener('dragover', (e) => e.preventDefault());
  window.addEventListener('drop', (e) => { e.preventDefault(); if (e.dataTransfer.files[0]) A.loadFile(e.dataTransfer.files[0]); });

  function start(data) {
    A.init(data);
    A.filters = { account: '', region: '', project: '', env: '', q: '' };
    buildShell();
    const hs = readHash();
    Object.assign(A.filters, hs.filters);
    A.invalidate();
    A.route.tab = hs.tab || 'overview';
    A.on('drawer', () => {});
    A.rerender(true);
  }

  A.on('filters', () => A.rerender());
  window.addEventListener('hashchange', () => { if (!A.data) return; const hs = readHash(); if (hs.tab && hs.tab !== A.route.tab) { A.route.tab = hs.tab; A.rerender(true); } });

  // ---- boot ----------------------------------------------------------------------------------------------------------------------
  function boot() {
    let data = null;
    try { data = JSON.parse(document.getElementById('aws-data').textContent); } catch (e) { data = null; }
    if (data && data.resources) start(data); else landing();
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot); else boot();
})();
