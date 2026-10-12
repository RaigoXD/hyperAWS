/* 3D map tab ("Cloud City"): toolbar, accessible directory, story card, "follow a request", legend and the WebGL
   stage. The stage lives for the whole page; this tab only attaches it. Without WebGL the directory and the stories
   still work. */
(function () {
  'use strict';
  const A = (window.AWSA = window.AWSA || {});
  const h = A.h;
  const C = A.cityCatalog;
  A.tabs = A.tabs || {};

  const LAYERS = [
    { id: 'labels', label: 'Labels', hint: 'Names above cities and buildings' },
    { id: 'security', label: 'Security layer', hint: 'Orange dashes: which buildings the firewall rules allow to talk to each other' },
    { id: 'waste', label: 'Waste layer', hint: 'Fade everything except unused (for rent) buildings' },
    { id: 'likely', label: 'Likely connections (guesses)', hint: 'Grey dashes guessed from names and networks; not observed' },
    { id: 'ghosts', label: 'Quiet regions as cities', hint: 'Show regions without buildings (usually only the default network) as full cities', mode: 'network' },
    { id: 'iam', label: 'Identity HQ (IAM)', hint: 'IAM roles as offices, users as badge holders' },
    { id: 'logs', label: 'Log groups', hint: 'Records offices (CloudWatch log groups)' },
    { id: 'other', label: 'Tag-only resources', hint: 'Resources of services without a collector, known only from tags' },
  ];
  const MODEL_LAYERS = new Set(['ghosts', 'iam', 'logs', 'other', 'likely']);
  const DEFAULTS = { mode: 'project', height: 'cost', traffic: true,
    layers: { labels: true, security: false, waste: false, likely: false, ghosts: false, iam: true, logs: false, other: false } };
  const saved = A.store.get('city', null) || {};
  const st = Object.assign({}, DEFAULTS, saved, { layers: Object.assign({}, DEFAULTS.layers, saved.layers || {}) });
  Object.assign(st, { sel: null, expanded: [], max: false, follow: null, step: 0, pending: null, q: '', legend: false, note: null });
  let cache = { key: null, world: null, data: null };
  let ui = null;                 // DOM refs of the current render
  let stageRef = null;
  let playTimer = null;          // "follow a request" auto-advance

  const persist = () => A.store.set('city', { mode: st.mode, height: st.height, traffic: st.traffic, layers: st.layers });
  const stopPlay = () => { if (playTimer) { clearInterval(playTimer); playTimer = null; } };

  function worldKey() {
    return JSON.stringify([A.filters, st.mode, st.height, st.layers.ghosts, st.layers.iam, st.layers.logs, st.layers.other, st.layers.likely, st.expanded]);
  }
  function getWorld() {
    const k = worldKey();
    if (cache.key === k && cache.data === A.data) return cache.world;
    const world = A.city.build(A.scope().res, { mode: st.mode, height: st.height, ghosts: st.layers.ghosts, iam: st.layers.iam,
      logs: st.layers.logs, other: st.layers.other, likely: st.layers.likely, expanded: st.expanded });
    world.key = k + '|' + (A.data.analyzed_at || '') + '|' + A.res.length;
    cache = { key: k, world, data: A.data };
    return world;
  }

  /** Focus the first enabled control with one of these focus keys inside `box` (keyboard users keep their place). */
  function focusIn(box, keys) {
    if (!box) return false;
    for (const k of keys) {
      const el = box.querySelector(`[data-focus-key="${k}"]`);
      if (el && !el.disabled && !el.hidden) { el.focus({ preventScroll: true }); return true; }
    }
    return false;
  }
  /** Where focus goes when the thing that had it disappears: the map, or the directory search without WebGL. */
  function focusHome() {
    if (!ui) return;
    if (stageRef && stageRef.container) stageRef.canvas.focus({ preventScroll: true });
    else if (ui.search) ui.search.focus({ preventScroll: true });
  }

  // ---- selection ------------------------------------------------------------------------------------------------------
  function selectEnt(id, fly) {
    st.sel = id ? { type: 'ent', id } : null;
    st.follow = null;
    clearNote();
    if (stageRef) { stageRef.follow(null); stageRef.select(id, fly); }
    renderStory();
    markDirectory();
  }
  function selectHit(hit) {
    if (!hit) { selectEnt(null); return; }
    if (hit.ent) { selectEnt(hit.ent.id, false); if (hit.sat) st.sel.sat = hit.sat.key; renderStory(); return; }
    st.follow = null;
    clearNote();
    if (stageRef) stageRef.follow(null);
    if (hit.flow) { st.sel = { type: 'flow', id: hit.flow.id }; if (stageRef) stageRef.selectFlow(hit.flow.id); }
    else if (hit.plate) { st.sel = { type: 'plate', id: hit.plate.id, plate: hit.plate }; if (stageRef) stageRef.select(null); }
    renderStory();
    markDirectory();
  }

  function tooltipFor(hit) {
    const w = cache.world;
    if (hit.flow) {
      const f = hit.flow;
      return h('div', null, h('strong', null, 'Road'), h('div', null, `${w.byId.get(f.from).name} → ${w.byId.get(f.to).name}`), h('div', { class: 'muted' }, rateText(f)));
    }
    if (hit.plate) return h('div', null, h('strong', null, hit.plate.label || 'District'), h('div', { class: 'muted' }, plateKind(hit.plate)));
    const e = hit.ent;
    if (hit.sat) {
      const s = hit.sat;
      return h('div', null, h('strong', null, s.name), h('div', { class: 'muted' }, s.kind === 'shed' ? 'Storage shed · EBS volume' : s.kind === 'signpost' ? 'Street address · Elastic IP' : 'Dispatch kiosk · target group'));
    }
    const ar = C.ARCHETYPES[e.archetype] || C.ARCHETYPES.unknown;
    const aws = e.res ? A.typeInfo(e.res.type).label : e.kind === 'stack' ? `${e.members.length} resources` : '';
    return h('div', null, h('strong', null, e.name), h('div', { class: 'muted' }, [ar.name, aws].filter(Boolean).join(' · ')),
      e.cost ? h('div', null, A.fmt.usd(e.cost) + '/month (estimate)') : null, e.sev ? h('div', null, A.sevBadge(e.sev)) : null,
      st.height === 'size' && e.sizeless ? h('div', { class: 'muted' }, 'No stored-data size: base height') : null);
  }

  const rateText = (f) => (f.status === 'parked' ? `${f.parked} failed message(s) waiting` : f.status === 'unknown' ? 'traffic not measured (grey cars)'
    : f.status === 'zero' ? 'measured: no traffic (cones)' : `${A.city.fmtRate(f.rate, f.unit)} · ${A.city.STATUS_TEXT[f.status]}`);
  const plateKind = (p) => ({ district: 'Private network (VPC)', block: 'Private block (subnet)', 'block-public': 'Public block (subnet)', empty: 'Empty subnets', commons: 'Shared by the whole network' }[p.kind] || 'District');

  // ---- story card -----------------------------------------------------------------------------------------------------
  function renderStory() {
    if (!ui || !ui.story) return;
    stopPlay();
    // rebuilding the card must not drop keyboard focus on <body>
    const ae = document.activeElement;
    const hadFocus = !!ae && ui.story.contains(ae);
    const fk = hadFocus && ae.dataset ? ae.dataset.focusKey : null;
    const box = A.clear(ui.story);
    buildStory(box);
    if (hadFocus) {
      if (box.hidden) focusHome();
      else if (!focusIn(box, [fk, 'city-close'].filter(Boolean))) focusHome();
    }
  }
  function buildStory(box) {
    const w = cache.world;
    const sel = st.sel;
    if (!sel) {
      box.hidden = true;
      ui.live.textContent = '';
      return;
    }
    box.hidden = false;
    const close = h('button', { class: 'icon-btn city-close', type: 'button', 'aria-label': 'Close', title: 'Close (Esc)', dataset: { focusKey: 'city-close' }, onClick: () => selectEnt(null) }, '×');
    if (sel.type === 'flow') {
      const f = w.flows.find((x) => x.id === sel.id);
      if (!f) { box.hidden = true; return; }
      const a = w.byId.get(f.from), b = w.byId.get(f.to);
      const spec = C.KINDS[f.kind] || {};
      box.append(close, h('p', { class: 'city-kicker' }, 'Road'), h('h3', null, `${a.name} → ${b.name}`),
        h('p', null, `${cap(a.kind === 'internet' ? 'visitors from the Internet' : a.name)} ${spec.text || 'connects to'} ${b.name}.`),
        h('p', { class: 'city-rate' }, rateText(f)), f.basis ? h('p', { class: 'muted small' }, 'How we know: ' + f.basis + '.') : null,
        f.danger ? h('p', { class: 'notice bad small' }, `⚠ Open to everyone: its firewall allows the whole Internet on ${f.door}.`) : null,
        h('div', { class: 'row gap wrap' }, h('button', { class: 'btn', type: 'button', onClick: () => selectEnt(a.id, true) }, 'Go to start'),
          h('button', { class: 'btn', type: 'button', onClick: () => selectEnt(b.id, true) }, 'Go to end')));
      ui.live.textContent = `Road from ${a.name} to ${b.name}: ${rateText(f)}`;
      return;
    }
    if (sel.type === 'plate') {
      const p = sel.plate;
      const r = p.key && A.byKey.get(p.key);
      box.append(close, h('p', { class: 'city-kicker' }, plateKind(p)), h('h3', null, p.label || (r && (r.name || r.rid)) || 'District'),
        h('p', null, p.kind === 'district' ? 'A private network (VPC): a walled district. Buildings inside can talk to each other; the gate (Internet gateway) decides whether visitors can come in from the Internet.'
          : 'A subnet: a city block inside a private network. Public blocks are reachable from the gate; private blocks only from inside the walls.'),
        r ? h('div', { class: 'row gap wrap' }, h('button', { class: 'btn', type: 'button', onClick: () => A.drawer.open(p.key) }, 'Open details')) : null);
      ui.live.textContent = `${plateKind(p)} ${p.label || ''}`;
      return;
    }
    const s = A.city.story(w, sel.id);
    if (!s) { box.hidden = true; return; }
    const e = w.byId.get(sel.id);
    const head = [close, h('p', { class: 'city-kicker' }, s.city + (s.aws && s.aws.type ? ' · ' + s.aws.type : '')), h('h3', null, s.title)];
    box.append(...head, h('p', { class: 'city-what' }, s.what));
    if (s.aws) {
      const facts = [];
      if (s.aws.project) facts.push(['Project', s.aws.project]);
      if (s.aws.region) facts.push(['Region', s.aws.region]);
      if (s.aws.state) facts.push(['State', s.aws.state]);
      facts.push(['Cost', A.fmt.usd(s.aws.cost || e.cost || 0) + '/month (estimate)']);
      box.append(h('dl', { class: 'facts' }, ...facts.flatMap(([k, v]) => [h('dt', null, k), h('dd', null, v)])));
    }
    for (const wtext of s.warnings) box.append(h('p', { class: 'notice warn small' }, wtext));
    const fs = (e.findings || []).slice().sort((x, y) => A.SEV[x.severity].rank - A.SEV[y.severity].rank).slice(0, 4);
    if (fs.length) {
      box.append(h('ul', { class: 'city-findings' }, fs.map((f) => h('li', null, A.sevBadge(f.severity), ' ',
        A.link(f.title, () => A.goto('waste', { open: f.id }), 'Open this finding')))));
    }
    if (s.lines.length) box.append(h('ul', { class: 'city-lines' }, s.lines.slice(0, 12).map((l) => h('li', null, l))));
    if (e.sats && e.sats.length) {
      box.append(h('div', { class: 'row gap wrap small' }, e.sats.map((x) => A.link(`Details: ${x.name}`, () => A.drawer.open(x.key)))));
    }
    if (s.members && s.members.length) {
      box.append(h('details', { class: 'city-members' }, h('summary', null, `${s.members.length} resources in this block`),
        h('ul', null, s.members.slice(0, 40).map((k) => { const r = A.byKey.get(k); return h('li', null, A.link(r ? r.name || r.rid : k, () => A.drawer.open(k))); }),
          s.members.length > 40 ? h('li', { class: 'muted' }, `… and ${s.members.length - 40} more`) : null),
        e.kind === 'stack' ? A.link('Show them as separate buildings', () => { st.expanded = st.expanded.concat(e.id); refreshWorld(); }) : null));
    }
    if (e.kind === 'hq') {
      box.append(h('details', { class: 'city-members' }, h('summary', null, `${e.floors.length} offices (IAM roles)`),
        h('ul', null, e.floors.map((f) => h('li', null, A.link(f.name + (f.dormant ? ' (dark)' : ''), () => selectEnt(f.id, true)))))));
    }
    if (e.kind === 'badges') {
      box.append(h('details', { class: 'city-members' }, h('summary', null, `${e.people.length} badge holders (IAM users)`),
        h('ul', null, e.people.map((p) => h('li', null, A.link(p.name, () => selectEnt(p.id, true)))))));
    }
    const actions = h('div', { class: 'row gap wrap city-actions' });
    if (w.flows.some((f) => f.to === e.id || f.from === e.id)) {
      actions.append(h('button', { class: 'btn primary', type: 'button', dataset: { focusKey: 'city-follow-start' }, onClick: () => startFollow(e.id) }, 'Follow a request'));
    }
    if (e.key) {
      actions.append(h('button', { class: 'btn', type: 'button', onClick: () => A.drawer.open(e.key) }, 'Open details'));
      if (A.showOnMap) actions.append(h('button', { class: 'btn', type: 'button', onClick: () => A.showOnMap(e.key) }, 'Show on 2D map'));
    }
    box.append(actions);
    if (st.follow) box.append(renderFollow());
    ui.live.textContent = `${s.title}: ${s.city}. ${s.what}`;
  }
  const cap = (t) => (t ? t.charAt(0).toUpperCase() + t.slice(1) : t);

  function announceStep() {
    const p = st.follow;
    if (!ui || !p) return;
    ui.live.textContent = p.steps.length ? `Step ${st.step + 1} of ${p.steps.length}: ${p.text[st.step]}` : p.text[0];
  }
  function startFollow(id) {
    const p = A.city.requestPath(cache.world, id);
    st.follow = p; st.step = 0;
    if (stageRef) stageRef.follow(p);
    renderStory();
    focusIn(ui && ui.story, ['city-follow-next', 'city-follow-stop']);
    announceStep();
  }
  function stopFollow() {
    st.follow = null;
    if (stageRef) stageRef.follow(null);
    renderStory();
    focusIn(ui && ui.story, ['city-follow-start', 'city-close']);
    if (ui) ui.live.textContent = 'Stopped following the request.';
  }
  /** The stepper updates in place (no rebuild), so the focused button and the screen reader keep their place. */
  function renderFollow() {
    const p = st.follow;
    const box = h('div', { class: 'city-follow' });
    if (!p.steps.length) { box.append(h('p', { class: 'muted' }, p.text[0])); return box; }
    const last = p.steps.length - 1;
    const items = p.text.map((t) => h('li', null, t));
    const prev = h('button', { class: 'btn', type: 'button', dataset: { focusKey: 'city-follow-prev' }, onClick: () => go(st.step - 1) }, '‹ Previous');
    const next = h('button', { class: 'btn', type: 'button', dataset: { focusKey: 'city-follow-next' }, onClick: () => go(st.step + 1) }, 'Next ›');
    const play = h('button', { class: 'btn', type: 'button', 'aria-pressed': 'false', dataset: { focusKey: 'city-follow-play' },
      onClick: () => (playTimer ? pause() : startPlay()) }, '▶ Play');
    const pause = () => { stopPlay(); play.textContent = '▶ Play'; play.setAttribute('aria-pressed', 'false'); };
    const startPlay = () => {
      if (st.step >= last) go(0, true);
      playTimer = setInterval(() => { if (st.step >= last) pause(); else go(st.step + 1, true); }, 3000);
      play.textContent = '❚❚ Pause'; play.setAttribute('aria-pressed', 'true');
    };
    const mark = () => {
      items.forEach((li, i) => { li.classList.toggle('on', i === st.step); if (i === st.step) li.setAttribute('aria-current', 'step'); else li.removeAttribute('aria-current'); });
      const had = document.activeElement;
      prev.disabled = st.step === 0;
      next.disabled = st.step >= last;
      if (had === next && next.disabled) prev.focus();
      else if (had === prev && prev.disabled) next.focus();
    };
    function go(i, playing) {
      if (!playing) pause();
      st.step = Math.max(0, Math.min(last, i));
      if (stageRef) stageRef.focusEnt(p.steps[st.step].to);
      mark();
      announceStep();
    }
    mark();
    box.append(h('p', { class: 'city-kicker' }, p.reachedInternet ? 'One visitor’s trip, from the Internet' : 'One request’s trip'),
      h('ol', null, items),
      h('div', { class: 'row gap wrap' }, prev, next, play,
        h('button', { class: 'linkbtn', type: 'button', dataset: { focusKey: 'city-follow-stop' }, onClick: stopFollow }, 'Stop')),
      h('p', { class: 'muted small' }, 'The highlighted car drives this path. Rates are daily averages; responses are not drawn.'));
    return box;
  }

  // ---- "Show in 3D" for something that may not be a building --------------------------------------------------------
  function clearNote() { if (st.note) { st.note = null; renderNote(); } }
  function renderNote() {
    if (!ui || !ui.note) return;
    const n = st.note;
    A.clear(ui.note);
    ui.note.hidden = !n;
    if (!n) return;
    const again = (fn) => () => { fn(); persist(); st.pending = n.key; st.note = null; A.rerender(); };
    ui.note.append(n.text);
    if (n.layer) {
      const l = LAYERS.find((x) => x.id === n.layer);
      ui.note.append(' ', A.link(`Turn on “${l ? l.label : n.layer}”`, again(() => { st.layers[n.layer] = true; })));
    }
    if (n.mode) ui.note.append(' ', A.link('Switch to the Network view', again(() => { st.mode = n.mode; st.expanded = []; })));
    ui.note.append(' ', h('button', { class: 'linkbtn', type: 'button', 'aria-label': 'Dismiss this note', onClick: clearNote }, '×'));
  }
  function applyPending(world) {
    const k = st.pending;
    st.pending = null;
    const loc = A.city.locate(world, k);
    if (loc.id) selectEnt(loc.id, true);
    else if (loc.plate) {
      st.sel = { type: 'plate', id: loc.plate.id, plate: loc.plate };
      st.follow = null;
      if (stageRef) { stageRef.follow(null); stageRef.select(null); stageRef.focusPlate(loc.plate); }
    } else {
      st.sel = null;
      if (stageRef) stageRef.select(null);
    }
    st.note = loc.note ? { text: loc.note, layer: loc.layer, mode: loc.mode, key: k } : null;
    renderNote();
  }

  // ---- directory (the accessible way through the city) ---------------------------------------------------------------------------
  function renderDirectory() {
    if (!ui || !ui.dir) return;
    const w = cache.world;
    const list = A.clear(ui.dir);
    const q = st.q.trim().toLowerCase();
    const item = (id, label, sub) => h('li', null, h('button', { type: 'button', class: 'city-dir-item', dataset: { id }, onClick: () => selectEnt(id, true) },
      h('span', { class: 'n' }, label), sub ? h('span', { class: 's' }, sub) : null));
    const archOf = (id) => { const e = w.byId.get(id); return e ? (C.ARCHETYPES[e.archetype] || C.ARCHETYPES.unknown).name : ''; };
    if (q) {
      const hits = w.ents.filter((e) => e.kind !== 'internet' && (e.name || '').toLowerCase().includes(q)).slice(0, 80);
      list.append(hits.length ? h('ul', { class: 'city-dir-flat' }, hits.map((e) => item(e.id, e.name, archOf(e.id)))) : h('p', { class: 'muted small' }, 'Nothing matches.'));
      markDirectory();
      return;
    }
    const hub = w.ents.filter((e) => e.cityId === 'hub' && e.kind !== 'floor' && e.kind !== 'person');
    list.append(h('details', { open: true }, h('summary', null, 'The capital'), h('ul', null, hub.map((e) => item(e.id, e.name, archOf(e.id))))));
    for (const c of w.directory) {
      const kids = [];
      for (const col of c.children) {
        const rows = col.children.filter((r) => r.children.length);
        if (!rows.length) continue;
        kids.push(h('li', null, h('details', { open: c.children.length <= 2 }, h('summary', null, col.label),
          h('ul', null, rows.map((r) => h('li', null, h('span', { class: 'city-dir-row' }, r.label),
            h('ul', null, r.children.map((x) => item(x.id, x.label, archOf(x.id))))))))));
      }
      list.append(h('details', { open: w.directory.length <= 3 }, h('summary', null, c.label), h('ul', null, kids)));
    }
    if (w.ghosts.length) {
      const gh = w.ents.filter((e) => e.kind === 'ghost');
      list.append(h('details', null, h('summary', null, `${gh.length} quiet regions`),
        h('ul', null, gh.map((e) => item(e.id, e.name, e.defaultOnly ? 'only the default network' : 'no buildings in this view')))));
    }
    markDirectory();
  }
  function markDirectory() {
    if (!ui || !ui.dir) return;
    const id = st.sel && st.sel.type === 'ent' ? st.sel.id : null;
    ui.dir.querySelectorAll('.city-dir-item').forEach((b) => {
      const on = b.dataset.id === id;
      b.classList.toggle('on', on);
      if (on) b.setAttribute('aria-current', 'true'); else b.removeAttribute('aria-current');
    });
  }

  // ---- legend -------------------------------------------------------------------------------------------------------------
  function legendPanel() {
    return h('div', { class: 'city-legend card', role: 'dialog', 'aria-label': 'How to read this city' },
      h('div', { class: 'row' }, h('h3', { class: 'grow' }, 'How to read this city'),
        h('button', { class: 'icon-btn', type: 'button', 'aria-label': 'Close', onClick: () => setLegend(false) }, '×')),
      h('ul', null, C.LEGEND.map((l) => h('li', null, h('span', { class: 'city-lg-icon lg-' + l.icon, 'aria-hidden': 'true' }), h('div', null, h('strong', null, l.title), h('p', null, l.text))))),
      h('details', null, h('summary', null, 'Every building type'),
        h('ul', { class: 'city-lg-types' }, Object.entries(C.ARCHETYPES).filter(([k]) => !['floor', 'plot', 'stack', 'internet'].includes(k))
          .map(([, a]) => h('li', null, h('strong', null, a.name), ' — ', a.what)))));
  }
  function setLegend(v) {
    const had = ui && ui.legend && ui.legend.contains(document.activeElement);
    st.legend = v;
    if (ui && ui.legend) ui.legend.hidden = !v;
    if (had && !v && ui.legendBtn) ui.legendBtn.focus({ preventScroll: true });
  }

  // ---- full view and Escape -------------------------------------------------------------------------------------------------
  function setMax(v) {
    st.max = v;
    if (!ui) return;
    ui.wrap.classList.toggle('max', v);
    if (ui.maxBtn) { ui.maxBtn.textContent = v ? 'Exit full view' : 'Full view'; ui.maxBtn.setAttribute('aria-pressed', String(v)); }
  }
  /** Escape anywhere in the tab: closes the legend, then leaves full view, then closes the story card. */
  function onEscape(e) {
    if (e.key !== 'Escape' || !ui) return;
    if (e.target !== document.body && !ui.wrap.contains(e.target)) return;
    if (/^(INPUT|TEXTAREA|SELECT)$/.test(e.target.tagName) && e.target.value) return;      // Escape clears a search field first
    const drawer = document.getElementById('drawer');
    if (drawer && !drawer.hidden) return;                                                     // the details drawer closes first
    if (st.legend) setLegend(false);
    else if (st.max) setMax(false);
    else if (st.sel) selectEnt(null);
    else return;
    e.preventDefault();
  }

  // ---- toolbar ------------------------------------------------------------------------------------------------------------
  function markSeg(seg, opts, v) {
    [...seg.children].forEach((b, i) => { const on = opts[i].id === v; b.classList.toggle('on', on); b.setAttribute('aria-pressed', String(on)); });
  }
  function toolbar() {
    const layersMenu = h('details', { class: 'menu' }, h('summary', { class: 'btn' }, 'Layers'),
      h('div', { class: 'menu-body' }, LAYERS.filter((l) => !l.mode || l.mode === st.mode).map((l) => h('label', { class: 'check', title: l.hint },
        h('input', { type: 'checkbox', checked: !!st.layers[l.id], onChange(e) {
          st.layers[l.id] = e.target.checked;
          persist();
          if (MODEL_LAYERS.has(l.id)) refreshWorld();
          else if (stageRef) stageRef.setLayers(stageLayers());
        } }), l.label))));
    const traffic = h('button', { class: 'btn', type: 'button', 'aria-pressed': String(st.traffic), title: 'Pause or play the cars',
      onClick() { st.traffic = !st.traffic; persist(); traffic.textContent = st.traffic ? '❚❚ Traffic' : '▶ Traffic'; traffic.setAttribute('aria-pressed', String(st.traffic)); if (stageRef) stageRef.setLayers(stageLayers()); } },
    st.traffic ? '❚❚ Traffic' : '▶ Traffic');
    const heights = [{ id: 'cost', label: 'Cost' }, { id: 'size', label: 'Size' }];
    const heightSeg = A.segmented(heights, st.height, (v) => { st.height = v; persist(); markSeg(heightSeg, heights, v); refreshWorld(); }, 'Building height');
    ui.legendBtn = h('button', { class: 'btn', type: 'button', onClick() { setLegend(!st.legend); } }, 'How to read this');
    ui.maxBtn = h('button', { class: 'btn', type: 'button', 'aria-pressed': String(st.max), onClick() { setMax(!st.max); } }, st.max ? 'Exit full view' : 'Full view');
    return h('div', { class: 'toolbar city-toolbar' },
      h('span', { class: 'muted small' }, 'View by'),
      A.segmented([{ id: 'project', label: 'Projects' }, { id: 'network', label: 'Network' }], st.mode, (v) => { st.mode = v; st.sel = null; st.follow = null; st.expanded = []; persist(); A.rerender(); }, 'View by'),
      h('span', { class: 'muted small' }, 'Height'),
      heightSeg,
      traffic, layersMenu,
      h('span', { class: 'grow' }),
      ui.legendBtn,
      stageRef ? h('button', { class: 'btn', type: 'button', title: 'Download a picture of the current view', onClick: () => stageRef.savePng(pngFooter()) }, 'Save PNG') : null,
      ui.maxBtn);
  }
  const stageLayers = () => ({ labels: st.layers.labels, security: st.layers.security, waste: st.layers.waste, likely: st.layers.likely, traffic: st.traffic });
  function pngFooter() {
    const a = (A.data.accounts || []).map((x) => x.account).join(', ');
    return `AWS Analyzer · 3D map (${st.mode === 'network' ? 'network' : 'projects'} view) · account ${a} · scanned ${(A.data.scanned_at || '').replace('T', ' ').replace('Z', ' UTC')} · costs are list-price estimates`;
  }
  const canvasLabel = (world) => `3D city map: ${world.stats.cities} cities, ${world.stats.buildings} buildings, ${world.stats.flows} roads with traffic. ` +
    'Use the directory to browse with the keyboard; with the map focused, arrows move, + and - zoom, Q and E turn, N and P step through buildings.';

  function statsLine(world) {
    const s = world.stats;
    const hidden = world.hiddenSummary || {};
    const hid = [hidden.logs ? `${hidden.logs} log groups` : null, hidden.other ? `${hidden.other} tag-only resources` : null, hidden.iam ? `${hidden.iam} IAM identities` : null].filter(Boolean);
    const days = A.data.scan_options && A.data.scan_options.metrics_days;
    return h('p', { class: 'muted small city-foot' },
      `${A.fmt.plural(s.cities, 'city', 'cities')} · ${A.fmt.plural(s.buildings, 'building')} · ${A.fmt.plural(s.flows, 'road')} with traffic`,
      s.unknown ? ` (${s.unknown} not measured)` : '', s.ghosts ? ` · ${s.ghosts} quiet regions` : '',
      hid.length ? ` · hidden: ${hid.join(', ')} (see Layers)` : '', '. ',
      `Roads come from configuration the scan could read; car density comes from CloudWatch over the last ${days || 14}–30 days where measured. ` +
      'Dashed lines are permissions, directory entries, borrowed roles or guesses, not observed traffic.',
      st.height === 'size' ? ' Height shows stored data; buildings without a stored-data size keep their base height.' : '',
      world.carsScaled ? ' Car numbers are scaled down to keep the animation smooth.' : '');
  }

  /** Display options changed (layers, height, an expanded block): rebuild the world and the stage in place, keeping the
      camera, the open Layers menu and the keyboard focus (a full re-render would throw all three away). */
  function refreshWorld() {
    const old = cache.world;
    const world = getWorld();
    if (!ui || !ui.foot || world.tooBig) { A.rerender(); return; }
    const sel = st.sel;
    if (sel && sel.type === 'ent' && !world.byId.has(sel.id)) st.sel = null;
    else if (sel && sel.type === 'flow' && !world.flows.some((f) => f.id === sel.id)) st.sel = null;
    else if (sel && sel.type === 'plate') { const p = world.plates.find((x) => x.id === sel.id); if (p) sel.plate = p; else st.sel = null; }
    st.follow = st.follow && st.sel && st.sel.type === 'ent' ? A.city.requestPath(world, st.sel.id) : null;
    st.step = 0;
    if (stageRef && stageRef.container) {
      stageRef.setWorld(world, false, true);
      stageRef.canvas.setAttribute('aria-label', canvasLabel(world));
      if (st.sel && st.sel.type === 'ent') {
        const a = old && old.byId.get(st.sel.id), b = world.byId.get(st.sel.id);
        stageRef.select(st.sel.id, !!a && Math.hypot(a.cx - b.cx, a.cz - b.cz) > 1);     // follow the building if the layout moved it
      } else if (st.sel && st.sel.type === 'flow') stageRef.selectFlow(st.sel.id);
      else stageRef.select(null);
      stageRef.follow(st.follow);
    }
    const foot = statsLine(world);
    ui.foot.replaceWith(foot);
    ui.foot = foot;
    renderDirectory();
    renderStory();
  }

  // ---- the tab ---------------------------------------------------------------------------------------------------------------
  A.tabs.city = {
    id: 'city', title: '3D map',
    setState(s) { if (s && s.select) st.pending = s.select; },
    render(root) {
      const world = getWorld();
      const wrap = h('div', { class: 'city-wrap' + (st.max ? ' max' : '') });
      root.appendChild(wrap);
      ui = { wrap };
      document.addEventListener('keydown', onEscape, true);         // capture: before the drawer's own Escape handler
      A.cleanup(() => { document.removeEventListener('keydown', onEscape, true); stopPlay(); });
      if (world.tooBig) {
        wrap.append(A.empty(`This view has ${A.fmt.num(world.stats.buildings)} buildings; the 3D map draws up to ${A.fmt.num(A.city.MAX_BUILDINGS)}. Narrow it with the filters above (a project or a region).`));
        return;
      }
      let error = null;
      try { stageRef = A.cityStage(); } catch (e) { stageRef = null; error = e; }
      ui.live = h('div', { class: 'sr-only', 'aria-live': 'polite' });
      ui.story = h('section', { class: 'city-story card', 'aria-label': 'Selected', hidden: true });
      ui.legend = legendPanel();
      ui.legend.hidden = !st.legend;
      ui.note = h('p', { class: 'notice small city-note', role: 'status', hidden: true });
      ui.search = h('input', { class: 'inp', type: 'search', placeholder: 'Find a building…', 'aria-label': 'Find a building in the city', value: st.q, dataset: { focusKey: 'city-q' },
        onInput: A.debounce((e) => { st.q = e.target.value; renderDirectory(); }, 120) });
      ui.dir = h('nav', { class: 'city-dir', 'aria-label': 'City directory' });
      const side = h('aside', { class: 'city-side' }, h('h3', { class: 'city-side-h' }, 'Directory'), ui.search, ui.dir);
      const stageBox = h('div', { class: 'city-stage' });
      ui.foot = statsLine(world);
      wrap.append(toolbar(), ui.note, h('div', { class: 'city-body' }, side, stageBox), ui.foot, ui.live);

      if (!stageRef) {
        stageBox.classList.add('fallback');
        stageBox.append(h('div', { class: 'notice warn' }, h('strong', null, 'The 3D view is not available here. '),
          `This browser or device could not start WebGL 2 (${String(error && error.message || error).slice(0, 140)}). You can still browse the city with the directory, or open the `,
          A.link('2D project map', () => A.goto('map')), '.'), ui.story, ui.legend);
        if (st.pending) applyPending(world);
        else if (st.sel && st.sel.type === 'ent' && !world.byId.has(st.sel.id)) st.sel = null;
        renderNote();
        renderDirectory();
        renderStory();
        return;
      }
      const overlay = h('div', { class: 'city-overlay' },
        h('div', { class: 'city-nav', role: 'group', 'aria-label': 'Camera' },
          h('button', { class: 'icon-btn', type: 'button', title: 'Zoom in', 'aria-label': 'Zoom in', onClick: () => stageRef.zoom(1 / 1.35) }, '+'),
          h('button', { class: 'icon-btn', type: 'button', title: 'Zoom out', 'aria-label': 'Zoom out', onClick: () => stageRef.zoom(1.35) }, '−'),
          h('button', { class: 'icon-btn', type: 'button', title: 'Start view', 'aria-label': 'Back to the start view', onClick: () => stageRef.resetView() }, '⌂'),
          h('button', { class: 'icon-btn', type: 'button', title: 'See everything', 'aria-label': 'Fit everything', onClick: () => stageRef.fitAll() }, '⤢')));
      const hintSeen = A.store.get('cityHint', false);
      const hint = hintSeen ? null : h('div', { class: 'city-hint', role: 'note' },
        h('span', null, 'Drag to move · Right-drag (or Shift-drag) to turn · Scroll to zoom · Click a building to learn what it is'),
        h('button', { class: 'linkbtn', type: 'button', onClick() { A.store.set('cityHint', true); hint.remove(); } }, 'Got it'));
      const status = h('div', { class: 'city-status', role: 'status', hidden: true });
      stageBox.append(overlay, ui.story, ui.legend, status);
      if (hint) stageBox.append(hint);

      stageRef.mount(stageBox, {
        select: (hit) => selectHit(hit),
        tooltip: tooltipFor,
        status(kind) {
          status.hidden = false;
          A.clear(status);
          if (kind === 'lost') status.append('The 3D view was paused by the browser (graphics memory). ', A.link('Restore', () => A.rerender()));
          else if (kind === 'simplified') status.append('Simplified for this device: cars are hidden to keep it smooth.');
          else status.hidden = true;
        },
        key(e) {           // Escape is handled for the whole tab by onEscape
          if (e.key === 'Enter' && st.sel && st.sel.type === 'ent') { const ent = cache.world.byId.get(st.sel.id); if (ent && ent.key) A.drawer.open(ent.key); }
          else if (e.key === 'n' || e.key === 'N' || e.key === 'p' || e.key === 'P') {
            const ids = [...ui.dir.querySelectorAll('.city-dir-item')].map((b) => b.dataset.id);
            if (!ids.length) return;
            const cur = st.sel && st.sel.type === 'ent' ? ids.indexOf(st.sel.id) : -1;
            const next = (cur + (e.key.toLowerCase() === 'n' ? 1 : ids.length - 1)) % ids.length;
            selectEnt(ids[Math.max(0, next)], true);
          }
        },
      });
      stageRef.canvas.setAttribute('aria-label', canvasLabel(world));
      stageRef.setLayers(stageLayers());
      stageRef.setWorld(world);
      // restore or apply a pending selection
      if (st.pending) applyPending(world);
      else if (st.sel && st.sel.type === 'ent' && world.byId.has(st.sel.id)) stageRef.select(st.sel.id, false);
      else if (st.sel && st.sel.type === 'flow' && world.flows.some((f) => f.id === st.sel.id)) stageRef.selectFlow(st.sel.id);
      else {
        const plate = st.sel && st.sel.type === 'plate' ? world.plates.find((p) => p.id === st.sel.id) : null;
        if (plate) st.sel.plate = plate; else st.sel = null;
        stageRef.select(null);
      }
      if (st.follow && st.sel) stageRef.follow(st.follow);
      renderNote();
      renderDirectory();
      renderStory();
      A.cleanup(() => { if (stageRef) stageRef.unmount(); ui = null; });
    },
  };

  A.showInCity = function showInCity(key) {
    if (!A.scope().keys.has(key)) A.setFilters({ account: '', region: '', project: '', env: '', q: '' });
    // a kind of resource a layer hides is shown by switching that layer on
    const r = A.byKey.get(key);
    const layer = !r ? null : r.type === 'logs:log-group' ? 'logs' : r.type.startsWith('other:') ? 'other' : r.type.startsWith('iam:') ? 'iam' : null;
    if (layer && !st.layers[layer]) { st.layers[layer] = true; persist(); }
    A.goto('city', { select: key });
  };

  A.on('filters', () => { st.sel = null; st.follow = null; st.note = null; });
  // a theme change while another tab is showing is applied when the 3D map is shown again
  A.on('theme', () => {
    if (!stageRef) return;
    if (A.route && A.route.tab === 'city' && stageRef.container) stageRef.applyTheme();
    else stageRef.themeDirty = true;
  });
})();
