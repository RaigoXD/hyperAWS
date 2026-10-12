/* 3D map: the three.js stage. One renderer and canvas for the life of the page (tab switches and filter changes only
   detach it), instanced low-poly buildings (~30 draw calls for any city), roads, animated cars, picking, an HTML label
   overlay and PNG export. three.js is evaluated lazily from the vendored factory the first time the tab opens. */
(function () {
  'use strict';
  const A = (window.AWSA = window.AWSA || {});
  const C = A.cityCatalog;

  let THREE = null;
  let stage = null;

  const ISLAND_TOP = 0.3, DISTRICT_TOP = 0.42, BLOCK_TOP = 0.54, ROAD_Y = 0.56, BASE_Y = 0.6;
  const reducedMotion = () => { try { return window.matchMedia('(prefers-reduced-motion: reduce)').matches; } catch (e) { return false; } };

  /** The singleton stage. Throws when the 3D library or WebGL2 is unavailable (the tab then falls back). */
  A.cityStage = function cityStage() {
    if (stage) return stage;
    if (A.store.get('city3dOff', false)) throw new Error('3D disabled (debug flag)');
    if (!THREE) {
      if (typeof window.AWSA_THREE_FACTORY !== 'function') throw new Error('the 3D library is not included in this report');
      THREE = window.AWSA_THREE_FACTORY();
    }
    stage = new Stage();
    return stage;
  };

  // ---- colours ---------------------------------------------------------------------------------------------------------
  function palette() {
    const cs = getComputedStyle(document.documentElement);
    const v = (n, fb) => (cs.getPropertyValue(n) || '').trim() || fb;
    const col = (s) => new THREE.Color().setStyle(s);
    const page = col(v('--page', '#f6f7f9'));
    const dark = page.r * 0.2126 + page.g * 0.7152 + page.b * 0.0722 < 0.35;
    const P = (light, night) => col(dark ? night : light);
    const white = new THREE.Color(1, 1, 1);
    const groups = {};
    const series = (i, fb) => col(v(`--series-${i}`, fb));
    const g = { compute: series(1, '#2a78d6'), network: series(2, '#eb6834'), data: series(3, '#1baf7a'), serverless: series(4, '#eda100'),
      containers: series(5, '#e87ba4'), security: series(6, '#008300'), ops: col(v('--text-muted', '#6b7280')) };
    const base = P('#ffffff', '#3a4250');
    for (const [k, c] of Object.entries(g)) {
      groups[k] = { accent: c, body: c.clone().lerp(base, dark ? 0.45 : 0.62), roof: c.clone().multiplyScalar(dark ? 0.75 : 0.82) };
    }
    return {
      dark, page, groups, white,
      sky: P('#dfeaf3', '#0b1220'), water: P('#a9cfe6', '#0d2234'), waterDeep: P('#8fbfdc', '#0a1a29'),
      sand: P('#efe4c8', '#3b3a33'), land: P('#cfe5bf', '#22352a'), landUtil: P('#d9ddd3', '#2c3330'), landOut: P('#e3d9c4', '#352f28'),
      landHub: P('#e9edf2', '#283041'), landGhost: P('#d6e2d0', '#1e2a24'),
      district: P('#e6ebf0', '#2a3342'), downtown: P('#eef0ea', '#2b3330'), bandCol: P('#dcebd0', '#26392d'),
      block: P('#f4f6f8', '#323c4d'), blockPublic: P('#fbf3df', '#3b3a32'), commons: P('#eceff5', '#30394a'), emptyBlock: P('#ece6d6', '#2f2d27'),
      band0: P('#d3e8c4', '#24382b'), band1: P('#cbe2bb', '#203327'),
      pavement: P('#c9ced6', '#3b4352'), asphalt: P('#5d6472', '#202631'), lane: P('#ffffff', '#c9cdd4'),
      wall: P('#9aa3b2', '#64708a'), wallDefault: P('#b9c0cb', '#4f5a6e'),
      winLit: P('#eaf3ff', '#ffd76a'), winOff: P('#58657a', '#18202c'),
      vacant: P('#c4c7cc', '#4a4f58'), vacantRoof: P('#a3a8b0', '#3c4049'),
      tree: P('#5f9f5a', '#2f5a3a'), trunk: P('#8b6b4a', '#4a3a2c'),
      accent: col(v('--accent', '#2a78d6')), critical: col(v('--critical', '#d03b3b')), serious: col(v('--serious', '#e07a10')),
      warn: col(v('--warn', '#e0a400')), muted: col(v('--text-muted', '#6b7280')), good: col(v('--good', '#1f9d55')),
      gold: P('#f2c230', '#f2c230'), metal: P('#aab3bf', '#6d7787'), glass: P('#bcd9f2', '#2d4a66'), dim: P('#e4e7eb', '#262c36'),
      car: [P('#ffffff', '#e8ecf2'), P('#e2483d', '#ff6b5e'), P('#2f6fd6', '#6aa3ff'), P('#f2c230', '#ffd75e'), P('#3a3f48', '#aab3bf')],
      van: P('#f08a24', '#ffa64d'), truck: P('#3d7fb8', '#7db4e6'), ghostCar: P('#8a919c', '#9aa3b2'), cone: P('#f26b1d', '#ff7f2a'),
      portal: P('#2a78d6', '#58a6ff'), danger: col(v('--critical', '#d03b3b')),
    };
  }

  // ---- shared unit primitives (base at y = 0), with a baked bottom-dark gradient --------------------------------------------
  function shade(geo) {
    const pos = geo.getAttribute('position');
    const cols = new Float32Array(pos.count * 3);
    for (let i = 0; i < pos.count; i++) { const y = pos.getY(i); const s = 0.74 + 0.26 * Math.max(0, Math.min(1, y)); cols[i * 3] = cols[i * 3 + 1] = cols[i * 3 + 2] = s; }
    geo.setAttribute('color', new THREE.BufferAttribute(cols, 3));
    return geo;
  }
  function gable() {
    // a gable roof: ridge along x, unit box footprint, apex at y = 1
    const p = [-0.5, 0, -0.5, 0.5, 0, -0.5, 0.5, 1, 0, -0.5, 1, 0, -0.5, 0, 0.5, 0.5, 0, 0.5];
    const idx = [0, 3, 2, 0, 2, 1, 4, 5, 2, 4, 2, 3, 0, 4, 3, 1, 2, 5, 0, 1, 5, 0, 5, 4];
    const g = new THREE.BufferGeometry();
    g.setAttribute('position', new THREE.Float32BufferAttribute(p, 3));
    g.setIndex(idx);
    const ng = g.toNonIndexed();
    ng.computeVertexNormals();
    return ng;
  }
  function primitives() {
    const up = (g) => { g.translate(0, 0.5, 0); return shade(g); };
    return {
      box: up(new THREE.BoxGeometry(1, 1, 1)),
      cyl: up(new THREE.CylinderGeometry(0.5, 0.5, 1, 10)),
      cyl6: up(new THREE.CylinderGeometry(0.5, 0.5, 1, 6)),
      disc: up(new THREE.CylinderGeometry(0.5, 0.5, 1, 32)),
      cone: up(new THREE.ConeGeometry(0.5, 1, 8)),
      sphere: up(new THREE.SphereGeometry(0.5, 14, 10)),
      octa: up(new THREE.OctahedronGeometry(0.5)),
      roof: shade(gable()),
      plane: (() => { const g = new THREE.PlaneGeometry(1, 1); g.rotateX(-Math.PI / 2); return g; })(),
    };
  }
  function carGeometry(parts) {
    const geos = parts.map(([w, h, d, x, y]) => { const b = new THREE.BoxGeometry(w, h, d); b.translate(x, y + h / 2, 0); return b.toNonIndexed(); });
    const n = geos.reduce((t, g) => t + g.getAttribute('position').count, 0);
    const pos = new Float32Array(n * 3), nor = new Float32Array(n * 3);
    let o = 0;
    for (const g of geos) { pos.set(g.getAttribute('position').array, o * 3); nor.set(g.getAttribute('normal').array, o * 3); o += g.getAttribute('position').count; g.dispose(); }
    const out = new THREE.BufferGeometry();
    out.setAttribute('position', new THREE.BufferAttribute(pos, 3));
    out.setAttribute('normal', new THREE.BufferAttribute(nor, 3));
    return shade(out);
  }

  // =====================================================================================================================
  function Stage() {
    this.canvas = document.createElement('canvas');
    this.canvas.className = 'city-canvas';
    this.canvas.tabIndex = 0;
    this.canvas.setAttribute('role', 'img');
    this.renderer = new THREE.WebGLRenderer({ canvas: this.canvas, antialias: true, alpha: false, stencil: false, powerPreference: 'default' });
    this.renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    this.dpr = Math.min(window.devicePixelRatio || 1, 2);
    this.scene = new THREE.Scene();
    this.camera = new THREE.PerspectiveCamera(42, 1.6, 0.5, 6000);
    this.cam = new A.CityCamera({ reduced: reducedMotion() });
    this.cam.fov = 42;
    this.hemi = new THREE.HemisphereLight(0xffffff, 0x445566, 1.6);
    this.sun = new THREE.DirectionalLight(0xffffff, 2.0);
    this.sun.position.set(-120, 260, 90);
    this.scene.add(this.hemi, this.sun);
    this.prims = primitives();
    this.carGeo = {
      car: carGeometry([[2.1, 0.62, 1.05, 0, 0.18], [1.1, 0.5, 0.92, -0.2, 0.8]]),
      van: carGeometry([[2.5, 1.25, 1.15, 0, 0.18]]),
      truck: carGeometry([[0.95, 1.1, 1.15, 1.25, 0.18], [2.6, 1.35, 1.25, -0.6, 0.18]]),
    };
    this.mats = {
      solid: new THREE.MeshLambertMaterial({ vertexColors: true }),
      glow: new THREE.MeshBasicMaterial({ color: 0xffffff }),
      ghost: new THREE.MeshBasicMaterial({ color: 0xffffff, transparent: true, opacity: 0.38, depthWrite: false }),
      shadow: new THREE.MeshBasicMaterial({ color: 0x000000, transparent: true, opacity: 0.16, depthWrite: false }),
      water: new THREE.MeshLambertMaterial({ color: 0xffffff }),
    };
    this.raycaster = new THREE.Raycaster();
    this.root = null;
    this.world = null;
    this.layers = { labels: true, security: false, waste: false, likely: false, traffic: true };
    this.sel = null;
    this.hover = null;
    this.t = 0;
    this.listeners = [];
    this.labelLayer = document.createElement('div');
    this.labelLayer.className = 'city-labels';
    this.labelLayer.setAttribute('aria-hidden', 'true');
    this.labelPool = [];
    this.dirty = true;
    this.lost = false;
    this.frameTimes = [];
    this.quality = 2;
    this.onSelect = null;
    this.onStatus = null;
    this.canvas.addEventListener('webglcontextlost', (e) => { e.preventDefault(); this.lost = true; this.stop(); if (this.onStatus) this.onStatus('lost'); });
    this.canvas.addEventListener('webglcontextrestored', () => { this.lost = false; if (this.world) this.setWorld(this.world, true); this.start(); if (this.onStatus) this.onStatus('restored'); });
  }

  Stage.prototype.mount = function (container, cb) {
    this.container = container;
    this.onSelect = cb.select; this.onStatus = cb.status; this.onHoverText = cb.tooltip;
    container.appendChild(this.canvas);
    container.appendChild(this.labelLayer);
    this.cam.o.reduced = reducedMotion();
    const self = this;
    this.cam.attach(this.canvas, {
      ground: (x, y) => self.ground(x, y),
      changed: () => { self.dirty = true; },
      hover: (e) => self.hoverAt(e),
      leave: () => { self.setHover(null); A.tip.hide(); },
      click: (e) => { const hit = self.pick(e.clientX, e.clientY); if (self.onSelect) self.onSelect(hit, e); },
      dblclick: (e) => { const hit = self.pick(e.clientX, e.clientY); if (hit && hit.ent) self.focusEnt(hit.ent.id); else { const g = self.ground(e.clientX, e.clientY); if (g) self.cam.view({ x: g.x, z: g.z, d: self.cam.goal.d / 1.8 }); } self.dirty = true; },
      key: (e) => { if (cb.key) cb.key(e); },
    });
    this.ro = new ResizeObserver(() => { this.resize(); if (this.autoView && this.world) this.resetView(true); });
    this.ro.observe(container);
    // until the user moves the camera, the start view follows the canvas size (it may mount while hidden or tiny)
    const manual = () => { this.autoView = false; };
    for (const ev of ['pointerdown', 'wheel', 'keydown']) {
      this.canvas.addEventListener(ev, manual, { passive: true });
      this.listeners.push(() => this.canvas.removeEventListener(ev, manual));
    }
    const vis = () => { if (document.hidden) this.stop(); else this.start(); };
    document.addEventListener('visibilitychange', vis);
    this.listeners.push(() => document.removeEventListener('visibilitychange', vis));
    this.resize();
    this.start();
  };

  Stage.prototype.unmount = function () {
    this.stop();
    this.cam.detach();
    if (this.ro) { this.ro.disconnect(); this.ro = null; }
    this.listeners.forEach((f) => f());
    this.listeners = [];
    A.tip.hide();
    if (this.canvas.parentNode) this.canvas.parentNode.removeChild(this.canvas);
    if (this.labelLayer.parentNode) this.labelLayer.parentNode.removeChild(this.labelLayer);
    this.container = null;
  };

  Stage.prototype.resize = function () {
    const c = this.container;
    if (!c) return;
    const w = Math.max(50, c.clientWidth), h = Math.max(50, c.clientHeight);
    this.renderer.setSize(w, h, false);
    this.canvas.style.width = w + 'px';
    this.canvas.style.height = h + 'px';
    this.camera.aspect = w / h;
    this.cam.aspect = w / h;
    this.camera.updateProjectionMatrix();
    this.dirty = true;
  };

  Stage.prototype.start = function () {
    if (this.raf || this.lost || !this.container) return;
    let last = performance.now();
    const loop = (now) => {
      this.raf = requestAnimationFrame(loop);
      const dt = Math.min(0.1, (now - last) / 1000);
      last = now;
      this.frame(dt, now);
    };
    this.raf = requestAnimationFrame(loop);
  };
  Stage.prototype.stop = function () { if (this.raf) cancelAnimationFrame(this.raf); this.raf = null; };

  Stage.prototype.animating = function () { return this.layers.traffic && !this.cam.o.reduced && !this.carsOff; };

  Stage.prototype.frame = function (dt, now) {
    if (!this.world || !this.root) return;
    if (this.needFit && this.container && this.container.clientWidth > 100 && this.container.clientHeight > 100) {
      this.needFit = false;
      this.resize();
      // a focus requested before the canvas had its size ("Show in 3D") wins over the start view
      if (this.autoView) this.resetView(true);
      else if (this.focusId) this.focusEnt(this.focusId);
    }
    const moved = this.cam.update(dt);
    const anim = this.animating();
    if (!moved && !anim && !this.dirty) return;
    const t0 = performance.now();
    if (anim) { this.t += dt; this.updateCars(); this.updateFollow(dt); }
    if (this.portal && !this.cam.o.reduced) this.portal.rotation.y += dt * 0.35;
    if (this.pinGroup && !this.cam.o.reduced) this.pinGroup.position.y = Math.sin(now / 600) * 0.35;
    this.cam.apply(this.camera);
    this.renderer.render(this.scene, this.camera);
    if (moved || this.dirty || this.labelsStale) this.updateLabels();
    this.dirty = false;
    this.adapt(performance.now() - t0, dt);
  };

  /** Adaptive quality: lower the pixel ratio, then stop the cars, if frames are slow. */
  Stage.prototype.adapt = function (cpuMs, dt) {
    this.frameTimes.push(dt * 1000);
    if (this.frameTimes.length < 90) return;
    const avg = this.frameTimes.reduce((a, b) => a + b, 0) / this.frameTimes.length;
    this.frameTimes = [];
    if (avg > 26 && this.dpr > 1) {
      this.dpr = this.dpr > 1.5 ? 1.5 : 1;
      this.renderer.setPixelRatio(this.dpr);
      this.resize();
    } else if (avg > 55 && this.dpr <= 1 && !this.carsOff) {
      this.carsOff = true;
      if (this.onStatus) this.onStatus('simplified');
    }
  };

  // ---- ground ray & picking ---------------------------------------------------------------------------------------------------
  Stage.prototype.ray = function (cx, cy) {
    const r = this.canvas.getBoundingClientRect();
    const ndc = new THREE.Vector2(((cx - r.left) / r.width) * 2 - 1, -((cy - r.top) / r.height) * 2 + 1);
    this.cam.apply(this.camera);
    this.raycaster.setFromCamera(ndc, this.camera);
    return this.raycaster.ray;
  };
  Stage.prototype.ground = function (cx, cy, y) {
    const ray = this.ray(cx, cy);
    const dy = ray.direction.y;
    if (dy > -0.02) return null;                                  // near-horizontal: ignore
    const t = ((y || 0) - ray.origin.y) / dy;
    return { x: ray.origin.x + ray.direction.x * t, z: ray.origin.z + ray.direction.z * t };
  };

  function rayBox(ray, cx, y0, cz, w, h, d, rot) {
    // ray into the box's local frame (rotation about Y), then a slab test
    const c = Math.cos(rot), s = Math.sin(rot);
    const ox = ray.origin.x - cx, oy = ray.origin.y - y0, oz = ray.origin.z - cz;
    const lox = ox * c - oz * s, loz = ox * s + oz * c;
    const ldx = ray.direction.x * c - ray.direction.z * s, ldz = ray.direction.x * s + ray.direction.z * c, ldy = ray.direction.y;
    let tmin = -Infinity, tmax = Infinity;
    for (const [o, dd, lo, hi] of [[lox, ldx, -w / 2, w / 2], [oy, ldy, 0, h], [loz, ldz, -d / 2, d / 2]]) {
      if (Math.abs(dd) < 1e-9) { if (o < lo || o > hi) return null; continue; }
      let t1 = (lo - o) / dd, t2 = (hi - o) / dd;
      if (t1 > t2) { const tt = t1; t1 = t2; t2 = tt; }
      tmin = Math.max(tmin, t1); tmax = Math.min(tmax, t2);
      if (tmin > tmax) return null;
    }
    return tmax < 0 ? null : Math.max(tmin, 0);
  }
  const inRect = (x, z, p) => {
    const c = Math.cos(p.rot), s = Math.sin(p.rot);
    const dx = x - p.cx, dz = z - p.cz;
    const lx = dx * c - dz * s, lz = dx * s + dz * c;
    return Math.abs(lx) <= p.w / 2 && Math.abs(lz) <= p.d / 2;
  };
  function segDist(px, pz, a, b) {
    const vx = b[0] - a[0], vz = b[1] - a[1];
    const L = vx * vx + vz * vz || 1;
    const t = Math.max(0, Math.min(1, ((px - a[0]) * vx + (pz - a[1]) * vz) / L));
    return Math.hypot(px - a[0] - vx * t, pz - a[1] - vz * t);
  }

  Stage.prototype.pick = function (cx, cy) {
    if (!this.world) return null;
    const ray = this.ray(cx, cy);
    let best = null;
    const test = (e, y0, h, w, d, cxx, czz, extra) => {
      const t = rayBox(ray, cxx, y0, czz, Math.max(w, 2), Math.max(h, 1.4), Math.max(d, 2), e.rot || 0);
      if (t != null && (!best || t < best.t - (extra ? 0.5 : 0))) best = Object.assign({ t, ent: e }, extra || {});
    };
    for (const e of this.world.ents) {
      if (e.kind === 'floor') continue;
      if (e.kind === 'person') { test(e, BASE_Y, 2, 1.4, 1.4, e.cx, e.cz); continue; }
      const top = e.kind === 'internet' ? 14 : e.kind === 'ghost' ? 1.2 : e.kind === 'hq' ? 3 : e.h;
      test(e, e.kind === 'ghost' ? 0 : BASE_Y, top, e.w, e.d, e.cx, e.cz);
      if (e.kind === 'hq') test(e, BASE_Y + e.h - 2, 7, e.w, e.d, e.cx, e.cz);
      for (const s of e.sats || []) test(e, BASE_Y, s.h, s.w, s.d, s.cx, s.cz, { sat: s });
    }
    let floor = null;
    for (const e of this.world.ents) {
      if (e.kind !== 'floor') continue;
      const t = rayBox(ray, e.cx, BASE_Y + e.y0, e.cz, e.w + 0.4, e.h + 0.1, e.d + 0.4, e.rot || 0);
      if (t != null && (!floor || t < floor.t)) floor = { t, ent: e };
    }
    if (floor && (!best || floor.t < best.t + 1)) return floor;           // offices win inside their tower
    if (best) return best;
    const g = this.ground(cx, cy, BASE_Y);
    if (!g) return null;
    let road = null;
    for (const f of this.visibleFlows()) {
      for (let i = 1; i < f.pts.length; i++) {
        const dd = segDist(g.x, g.z, f.pts[i - 1], f.pts[i]);
        if (dd < 1.6 && (!road || dd < road.dd)) road = { dd, flow: f };
      }
    }
    if (road) return { flow: road.flow };
    const plates = this.world.plates.filter((p) => p.key && inRect(g.x, g.z, p)).sort((a, b) => a.w * a.d - b.w * b.d);
    if (plates.length) return { plate: plates[0] };
    return null;
  };

  Stage.prototype.hoverAt = function (e) {
    if (this.hoverPending) { this.hoverEvt = e; return; }
    this.hoverPending = true;
    this.hoverEvt = e;
    requestAnimationFrame(() => {
      this.hoverPending = false;
      const ev = this.hoverEvt;
      if (!ev || !this.world) return;
      const hit = this.pick(ev.clientX, ev.clientY);
      const id = hit ? (hit.ent ? hit.ent.id + (hit.sat ? '|' + hit.sat.key : '') : hit.flow ? hit.flow.id : hit.plate ? hit.plate.id : null) : null;
      this.canvas.style.cursor = hit ? 'pointer' : '';
      if (id !== this.hoverId) {
        this.hoverId = id;
        this.setHover(hit && hit.ent ? hit.ent.id : null);
      }
      if (hit && this.onHoverText) { const content = this.onHoverText(hit); if (content) A.tip.show(ev, content); else A.tip.hide(); }
      else A.tip.hide();
    });
  };
  Stage.prototype.setHover = function (id) { if (this.hover !== id) { this.hover = id; this.labelsStale = true; this.dirty = true; } };

  // ---- world -> meshes -----------------------------------------------------------------------------------------------------
  /** Shows `world`. `rebuild` redraws the same world (new theme, restored context); `keepView` keeps the camera where it
      is for a new world that only changed display options (layers, height). */
  Stage.prototype.setWorld = function (world, rebuild, keepView) {
    const same = this.world === world;
    if (same && !rebuild && !this.themeDirty) return;
    const fresh = !this.world || this.worldKey !== world.key;
    if (!same) this.followData = null;
    this.world = world;
    this.worldKey = world.key;
    this.buildScene();
    this.cam.setBounds(world.bounds);
    if (fresh && (!keepView || this.autoView)) { this.resetView(true); this.needFit = true; this.autoView = true; this.focusId = null; }   // again once the canvas has its real size
    this.sel = this.sel && world.byId.has(this.sel) ? this.sel : null;
    this.applyFocus();
    if (this.followData) this.follow(this.followData);      // the highlighted car survives a redraw of the same world
    this.dirty = true;
  };

  Stage.prototype.resetView = function (instant) {
    const v = this.world.view0;
    this.cam.flyTo(v.x, v.z, v.r, { az: v.azimuth, pol: 0.92, y: 0 });
    if (instant) this.cam.view({}, true);
    this.dirty = true;
  };
  Stage.prototype.fitAll = function () {
    const b = this.world.bounds;
    this.cam.flyTo(b.cx, b.cz, b.r * 0.9, { y: 0 });
    this.dirty = true;
  };
  Stage.prototype.zoom = function (f) { this.cam.view({ d: this.cam.goal.d * f }); this.dirty = true; };
  Stage.prototype.northUp = function () { this.cam.view({ az: Math.PI }); this.dirty = true; };
  Stage.prototype.focusEnt = function (id) {
    const e = this.world && this.world.byId.get(id);
    if (!e) return;
    this.autoView = false;
    this.focusId = id;
    const r = Math.max(28, Math.max(e.w || 8, e.d || 8) * 2.4, (e.h || 0) * 1.4);
    // aim a little to the right of the building so it stays visible next to the story card (which sits on the right)
    const az = this.cam.goal.az, wide = this.container && this.container.clientWidth > 700;
    const shift = wide ? r * 0.55 : 0;
    // look at the entity's own height when it floats (an office high up in the Identity HQ), the ground otherwise
    const y = e.y0 ? BASE_Y + e.y0 + (e.h || 0) / 2 : 0;
    this.cam.flyTo(e.cx + Math.cos(az) * shift, e.cz - Math.sin(az) * shift, r, { y });
    this.dirty = true;
  };
  /** Frames a district or block of land (a plate). */
  Stage.prototype.focusPlate = function (p) {
    if (!p) return;
    this.autoView = false;
    this.focusId = null;
    this.cam.flyTo(p.cx, p.cz, Math.max(30, Math.max(p.w, p.d) * 0.6), { y: 0 });
    this.dirty = true;
  };

  Stage.prototype.disposeRoot = function () {
    if (!this.root) return;
    this.root.traverse((o) => {
      if (o.isInstancedMesh) o.dispose();
      if (o.userData.ownGeometry && o.geometry) { o.geometry.dispose(); if (o.material) o.material.dispose(); }
    });
    this.followMesh = null; this.followPath = null; this.hlMesh = null; this.ovMesh = null;
    this.scene.remove(this.root);
    this.root = null;
  };

  Stage.prototype.applyTheme = function () {
    if (!this.world) { this.themeDirty = true; return; }
    this.setWorld(this.world, true);
  };

  Stage.prototype.buildScene = function () {
    this.disposeRoot();
    const w = this.world;
    const pal = (this.pal = palette());
    this.themeDirty = false;
    this.scene.background = pal.sky;
    const R = w.bounds.r;
    this.scene.fog = new THREE.Fog(pal.sky, R * 1.8, R * 6);
    this.hemi.color.copy(pal.dark ? new THREE.Color('#6d7fa6') : new THREE.Color('#ffffff'));
    this.hemi.groundColor.copy(pal.dark ? new THREE.Color('#1a2230') : new THREE.Color('#8a9aa8'));
    this.hemi.intensity = pal.dark ? 1.1 : 1.65;
    this.sun.intensity = pal.dark ? 0.55 : 2.0;
    this.mats.water.color.copy(pal.water);
    const root = (this.root = new THREE.Group());
    this.scene.add(root);

    // water
    const water = new THREE.Mesh(this.prims.plane, this.mats.water);
    water.scale.set(R * 14, 1, R * 14);
    water.position.set(w.bounds.cx, -0.45, w.bounds.cz);
    root.add(water);

    const B = new Batcher(this);
    this.batch = B;
    this.instOf = new Map();
    drawTerrain(w, B, pal);
    drawStreets(w, B, pal);
    for (const e of w.ents) drawEnt(e, B, pal, this);
    B.flush(root);
    this.instOf = B.owner;

    // pins and coins bob together
    const PB = new Batcher(this);
    for (const e of w.ents) drawPin(e, PB, pal);
    this.pinGroup = new THREE.Group();
    PB.flush(this.pinGroup);
    root.add(this.pinGroup);

    // the Internet portal (a spinning ring with a globe)
    const portal = new THREE.Group();
    const ring = new THREE.Mesh(new THREE.TorusGeometry(6.5, 0.7, 10, 48), new THREE.MeshLambertMaterial({ color: pal.portal }));
    ring.userData.ownGeometry = true;
    ring.position.y = 8;
    const globe = new THREE.Mesh(new THREE.SphereGeometry(4, 24, 16), new THREE.MeshBasicMaterial({ color: pal.portal.clone().lerp(pal.white, 0.55), transparent: true, opacity: 0.85 }));
    globe.userData.ownGeometry = true;
    globe.position.y = 8;
    portal.add(ring, globe);
    portal.position.set(0, BASE_Y, 0);
    root.add(portal);
    this.portal = portal;

    this.buildCars();
    this.buildOverlay();
    this.labelsStale = true;
  };

  // ---- batching: one InstancedMesh per (primitive x material) ----------------------------------------------------------------
  function Batcher(st) { this.st = st; this.groups = new Map(); this.owner = new Map(); }
  Batcher.prototype.add = function (prim, mat, x, y, z, sx, sy, sz, ry, color, owner, rx) {
    const k = prim + '|' + mat;
    let g = this.groups.get(k);
    if (!g) { g = { prim, mat, m: [], c: [], own: [] }; this.groups.set(k, g); }
    if (rx) {
      const q = new THREE.Quaternion().setFromEuler(new THREE.Euler(rx, ry || 0, 0, 'YXZ'));
      const mm = new THREE.Matrix4().compose(new THREE.Vector3(x, y, z), q, new THREE.Vector3(sx, sy, sz));
      g.m.push(...mm.elements);
    } else {
      const c = Math.cos(ry || 0), s = Math.sin(ry || 0);
      g.m.push(c * sx, 0, -s * sx, 0, 0, sy, 0, 0, s * sz, 0, c * sz, 0, x, y, z, 1);
    }
    g.c.push(color.r, color.g, color.b);
    g.own.push(owner || null);
  };
  /** A function placing parts in an object's local frame (centre cx/cz, rotation rot, base y). */
  Batcher.prototype.local = function (cx, cz, rot, y0, owner) {
    const c = Math.cos(rot), s = Math.sin(rot);
    return (prim, mat, lx, ly, lz, sx, sy, sz, color, ry, rx) => this.add(prim, mat, cx + lx * c + lz * s, y0 + ly, cz - lx * s + lz * c, sx, sy, sz, rot + (ry || 0), color, owner, rx);
  };
  Batcher.prototype.flush = function (parent) {
    for (const [k, g] of this.groups) {
      const n = g.c.length / 3;
      if (!n) continue;
      const geo = g.prim.startsWith('car:') ? this.st.carGeo[g.prim.slice(4)] : this.st.prims[g.prim];
      const mesh = new THREE.InstancedMesh(geo, this.st.mats[g.mat], n);
      mesh.instanceMatrix.array.set(g.m);
      mesh.instanceColor = new THREE.InstancedBufferAttribute(new Float32Array(g.c), 3);
      mesh.userData.base = new Float32Array(g.c);
      mesh.userData.own = g.own;
      mesh.computeBoundingSphere();
      if (g.mat === 'ghost' || g.mat === 'shadow') mesh.renderOrder = 2;
      parent.add(mesh);
      g.own.forEach((o, i) => { if (!o) return; if (!this.owner.has(o)) this.owner.set(o, []); this.owner.get(o).push([mesh, i]); });
      g.mesh = mesh;
      this.groups.set(k, g);
    }
  };

  // ---- terrain: water, islands, districts, blocks, walls, gates, trees ---------------------------------------------------------
  function drawTerrain(w, B, pal) {
    for (const i of w.islands) {
      if (i.shape === 'disc') {
        B.add('disc', 'solid', i.cx, -1.5, i.cz, i.r * 2 + 5, 1.75, i.r * 2 + 5, 0, pal.sand);
        B.add('disc', 'solid', i.cx, -1.3, i.cz, i.r * 2, 1.6, i.r * 2, 0, pal.landHub);
        continue;
      }
      const land = i.kind === 'ghost' ? pal.landGhost : i.kind === 'utilities' ? pal.landUtil : i.kind === 'outskirts' ? pal.landOut : pal.land;
      B.add('box', 'solid', i.cx, -1.5, i.cz, i.w + 4, 1.75, i.d + 4, i.rot, pal.sand);
      B.add('box', 'solid', i.cx, -1.3, i.cz, i.w, 1.6, i.d, i.rot, land);
      if (i.kind !== 'ghost' && i.kind !== 'hub') trees(B, i, pal);
    }
    let band = 0;
    for (const p of w.plates) {
      const col = { district: pal.district, downtown: pal.downtown, 'band-col': pal.bandCol, block: pal.block, 'block-public': pal.blockPublic,
        commons: pal.commons, empty: pal.emptyBlock, band: band++ % 2 ? pal.band1 : pal.band0 }[p.kind];
      if (!col) continue;
      // districts sit on the island, blocks and bands on top of the districts
      B.add('box', 'solid', p.cx, p.y > 0.15 ? DISTRICT_TOP - 0.02 : ISLAND_TOP, p.cz, p.w, 0.12, p.d, p.rot, col, p.key ? 'plate:' + p.id : null);
    }
    for (const wl of w.walls) {
      const len = Math.hypot(wl.x2 - wl.x1, wl.z2 - wl.z1);
      const ang = Math.atan2(-(wl.z2 - wl.z1), wl.x2 - wl.x1);
      const col = wl.dashed ? pal.wallDefault : pal.wall;
      if (!wl.dashed) { B.add('box', 'solid', (wl.x1 + wl.x2) / 2, ISLAND_TOP, (wl.z1 + wl.z2) / 2, len + 0.5, wl.h, 0.5, ang, col); continue; }
      const n = Math.max(1, Math.floor(len / 3.5));
      for (let k = 0; k < n; k++) {
        const t = (k + 0.5) / n;
        B.add('box', 'solid', wl.x1 + (wl.x2 - wl.x1) * t, ISLAND_TOP, wl.z1 + (wl.z2 - wl.z1) * t, Math.min(2.2, len / n * 0.6), wl.h, 0.4, ang, col);
      }
    }
    for (const g of w.gates) {
      const put = B.local(g.cx, g.cz, g.rot, ISLAND_TOP, g.key ? 'gate:' + g.id : null);
      if (g.kind === 'igw') {
        const accent = pal.groups.network.accent;
        put('box', 'solid', -g.w / 2, 0, 0, 0.9, 4.2, 0.9, accent);
        put('box', 'solid', g.w / 2, 0, 0, 0.9, 4.2, 0.9, accent);
        put('box', 'solid', 0, 4.2, 0, g.w + 0.9, 0.8, 1.0, accent);
        put('cone', 'solid', -g.w / 2, 4.2, 0, 0.9, 1.2, 0.9, pal.groups.network.roof);
        put('cone', 'solid', g.w / 2, 4.2, 0, 0.9, 1.2, 0.9, pal.groups.network.roof);
      } else {
        put('box', 'solid', -g.w / 2, 0, 0, 0.5, 1.4, 0.5, pal.wall);
        put('box', 'solid', g.w / 2, 0, 0, 0.5, 1.4, 0.5, pal.wall);
      }
    }
  }

  function trees(B, i, pal) {
    // a row of trees along the back and sides of an island (the front faces the hub and stays open)
    const c = Math.cos(i.rot), s = Math.sin(i.rot);
    const P = (lx, lz) => [i.cx + lx * c + lz * s, i.cz - lx * s + lz * c];
    const spots = [];
    const hw = i.w / 2 - 2.2, hd = i.d / 2 - 2.2;
    for (let x = -hw; x <= hw; x += 6.5) spots.push([x, hd]);
    for (let z = -hd + 10; z <= hd - 4; z += 7) { spots.push([-hw, z]); spots.push([hw, z]); }
    spots.forEach(([lx, lz], k) => {
      const hsh = A.city.hash(i.id + ':' + k);
      if (hsh % 5 === 0) return;
      const [x, z] = P(lx + ((hsh >> 3) % 10) / 10 - 0.5, lz);
      const h = 2.2 + (hsh % 7) / 3;
      B.add('cyl', 'solid', x, ISLAND_TOP, z, 0.45, h * 0.45, 0.45, 0, pal.trunk);
      B.add('cone', 'solid', x, ISLAND_TOP + h * 0.35, z, 2.2, h, 2.2, 0, pal.tree.clone().multiplyScalar(0.9 + (hsh % 4) / 20));
    });
  }

  function drawStreets(w, B, pal) {
    for (const s of w.streets) {
      const len = Math.hypot(s.x2 - s.x1, s.z2 - s.z1);
      if (len < 0.05) continue;
      const ang = Math.atan2(-(s.z2 - s.z1), s.x2 - s.x1);
      const mx = (s.x1 + s.x2) / 2, mz = (s.z1 + s.z2) / 2;
      const over = s.kind === 'bridge' || s.kind === 'spoke';
      const col = s.used ? pal.asphalt : pal.pavement;
      B.add('box', 'solid', mx, over ? ROAD_Y - 0.25 : ROAD_Y - 0.06, mz, len + s.width * 0.5, over ? 0.35 : 0.1, s.width, ang, col);
      if (s.kind === 'bridge') {
        const n = Math.floor(len / 14);
        for (let k = 1; k <= n; k++) {
          const t = k / (n + 1);
          B.add('box', 'solid', s.x1 + (s.x2 - s.x1) * t, -0.6, s.z1 + (s.z2 - s.z1) * t, 1.2, ROAD_Y + 0.3, s.width * 0.7, ang, pal.metal);
        }
      }
      if (s.used && s.width >= 4.5) {
        const n = Math.floor(len / 4);
        for (let k = 0; k < n; k++) {
          const t = (k + 0.5) / n;
          B.add('box', 'glow', s.x1 + (s.x2 - s.x1) * t, ROAD_Y + 0.02, s.z1 + (s.z2 - s.z1) * t, 1.5, 0.04, 0.16, ang, pal.lane);
        }
      }
    }
  }

  // ---- buildings ---------------------------------------------------------------------------------------------------------------
  function colorsFor(e, pal) {
    const g = pal.groups[e.group] || pal.groups.ops;
    const k = { accent: g.accent, body: g.body, roof: g.roof, win: pal.winLit, winOff: pal.winOff, lit: e.lit !== false };
    if (e.vacant) { k.body = pal.vacant; k.roof = pal.vacantRoof; k.accent = pal.vacantRoof; k.lit = false; }
    else if (e.stopped) { k.body = g.body.clone().lerp(pal.vacant, 0.55); k.lit = false; }
    return k;
  }

  const ARCH = {
    tower(e, p, k) {
      const w = e.w * 0.84, d = e.d * 0.84, h = e.h;
      p('box', 'solid', 0, 0, 0, w, h, d, k.body);
      const fl = Math.max(2, Math.min(12, Math.floor((h - 1.2) / 1.9)));
      const step = (h - 1.4) / fl;
      for (let i = 0; i < fl; i++) p('box', k.lit ? 'glow' : 'solid', 0, 1 + i * step, 0, w + 0.1, step * 0.42, d + 0.1, k.lit ? k.win : k.winOff);
      p('box', 'solid', 0, h, 0, w * 0.5, 0.7, d * 0.4, k.roof);
      p('box', 'solid', 0, 0, -d / 2 - 0.3, 2.2, 2.2, 0.6, k.accent);
    },
    shed(e, p, k) { p('box', 'solid', 0, 0, 0, e.w * 0.8, e.h * 0.7, e.d * 0.8, k.body); p('roof', 'solid', 0, e.h * 0.7, 0, e.w * 0.86, 1.1, e.d * 0.86, k.roof); },
    yard(e, p, k) {
      p('box', 'solid', 0, 0, 0, e.w, 0.15, e.d, k.roof);
      const n = Math.min(12, Math.max(1, e.members.length));
      const per = Math.ceil(Math.sqrt(n));
      for (let i = 0; i < n; i++) {
        const hs = A.city.hash(e.id + i);
        const cx = ((i % per) - (per - 1) / 2) * (e.w / (per + 0.6)), cz = (Math.floor(i / per) - (per - 1) / 2) * (e.d / (per + 0.6));
        const st = 1 + (hs % 3);
        for (let j = 0; j < st; j++) p('box', 'solid', cx, 0.15 + j * 1.05, cz, 1.8, 1, 1.8, j % 2 ? k.body : k.accent.clone().lerp(k.body, 0.4));
      }
    },
    signpost(e, p, k) { post(p, 0, 0, e.h || 3.5, k.accent, e.vacant); },
    plaza(e, p, k) {
      p('disc', 'solid', 0, 0, 0, e.w, 0.22, e.d, k.body.clone().lerp(k.roof, 0.2));
      p('disc', 'solid', 0, 0.22, 0, e.w * 0.46, 0.25, e.d * 0.46, k.roof);
      p('box', 'solid', 0, 0.45, 0, 1.3, Math.max(5, e.h + 4), 1.3, k.accent);
      p('cone', 'solid', 0, 0.45 + Math.max(5, e.h + 4), 0, 1.3, 1.4, 1.3, k.accent);
    },
    kiosk(e, p, k) { p('box', 'solid', 0, 0, 0, e.w * 0.7, 1.5, e.d * 0.7, k.body); p('cone', 'solid', 0, 1.5, 0, e.w * 0.9, 1, e.d * 0.9, k.roof); },
    factory(e, p, k) {
      const w = e.w * 0.62, d = e.d * 0.86, h = e.h;
      p('box', 'solid', -e.w * 0.17, 0, 0, w, h, d, k.body);
      for (let i = 0; i < 3; i++) p('roof', 'solid', -e.w * 0.17, h, -d / 2 + d / 6 + (i * d) / 3, w, 1.4, d / 3, k.roof, Math.PI / 2);
      p('cyl', 'solid', -e.w * 0.17 - w * 0.3, h, d * 0.3, 0.9, 3.2, 0.9, k.roof);
      const n = Math.min(12, Math.max(0, (e.res && e.res.attrs && (e.res.attrs.running != null ? e.res.attrs.running : e.res.attrs.desired)) || 0));
      for (let i = 0; i < n; i++) {
        const col = i % 3 === 0 ? k.accent : i % 3 === 1 ? k.roof : k.body.clone().lerp(k.accent, 0.5);
        p('box', 'solid', e.w * 0.31, (i % 3) * 1.1, -d / 2 + 1.4 + Math.floor(i / 3) * 2.2, 3.2, 1, 1.9, col);
      }
    },
    park(e, p, k) { p('box', 'solid', 0, 0, 0, e.w * 0.8, e.h, e.d * 0.7, k.body); p('box', 'solid', 0, e.h, 0, e.w * 0.84, 0.4, e.d * 0.74, k.roof); fence(p, e, k.roof); },
    port(e, p, k) {
      p('box', 'solid', 0, 0, 0, e.w, 0.3, e.d, k.roof.clone().lerp(k.body, 0.5));
      for (const sx of [-1, 1]) {
        p('box', 'solid', sx * e.w * 0.3, 0.3, -e.d * 0.2, 0.9, 9, 0.9, k.accent);
        p('box', 'solid', sx * e.w * 0.3 + 2.2, 9.3, -e.d * 0.2, 6, 0.6, 0.7, k.accent);
      }
      for (let i = 0; i < 6; i++) p('box', 'solid', -e.w * 0.3 + (i % 3) * 3.3, 0.3, e.d * 0.18 + Math.floor(i / 3) * 1.6, 3, 1.2 + (i % 2), 1.4, i % 2 ? k.body : k.roof);
    },
    warehouse(e, p, k) { p('box', 'solid', 0, 0, 0, e.w * 0.9, e.h, e.d * 0.8, k.body); p('roof', 'solid', 0, e.h, 0, e.w * 0.94, 1.6, e.d * 0.84, k.roof); },
    truck(e, p, k) {
      p('box', 'solid', -0.6, 0.45, 0, e.w * 0.62, 2.2, e.d * 0.62, k.body);
      p('box', 'solid', e.w * 0.3, 0.45, 0, e.w * 0.24, 1.6, e.d * 0.58, k.roof);
      p('box', k.lit ? 'glow' : 'solid', -0.6, 1.1, -e.d * 0.32, e.w * 0.5, 0.7, 0.1, k.lit ? k.win : k.winOff);
      p('box', 'solid', -0.6, 2.4, -e.d * 0.36, e.w * 0.66, 0.15, 1.1, k.accent);
      for (const sx of [-1.3, 1.5]) for (const sz of [-1, 1]) p('cyl', 'solid', sx, 0, sz * e.d * 0.3, 0.8, 0.5, 0.8, k.winOff);
    },
    reception(e, p, k) {
      p('box', 'solid', 0, 0, 1, e.w * 0.9, e.h, e.d * 0.6, k.body);
      p('box', 'solid', -e.w * 0.3, 0, -e.d * 0.3, 0.8, e.h * 0.9, 0.8, k.roof);
      p('box', 'solid', e.w * 0.3, 0, -e.d * 0.3, 0.8, e.h * 0.9, 0.8, k.roof);
      p('box', 'solid', 0, e.h * 0.9, -e.d * 0.12, e.w * 0.75, 0.7, e.d * 0.5, k.accent);
    },
    vault(e, p, k) {
      const w = e.w * 0.86, d = e.d * 0.8, h = e.h;
      p('box', 'solid', 0, 0, 0, w + 0.8, 0.8, d + 0.8, k.roof);
      p('box', 'solid', 0, 0.8, 0.6, w * 0.92, h - 0.8, d * 0.8, k.body);
      const cols = 5;
      for (let i = 0; i < cols; i++) p('cyl', 'solid', -w / 2 + 0.8 + (i * (w - 1.6)) / (cols - 1), 0.8, -d / 2 + 0.6, 0.85, h - 0.8, 0.85, k.body.clone().lerp(new THREE.Color(1, 1, 1), 0.3));
      p('box', 'solid', 0, h, 0, w + 0.4, 0.5, d + 0.4, k.roof);
      p('roof', 'solid', 0, h + 0.5, 0, w, 1.8, d * 0.9, k.accent);
    },
    cabinet(e, p, k) {
      p('cyl6', 'solid', 0, 0, 0, e.w * 0.8, e.h, e.d * 0.8, k.body);
      for (let i = 1; i < 4; i++) p('cyl6', 'solid', 0, (e.h * i) / 4 - 0.15, 0, e.w * 0.84, 0.3, e.d * 0.84, k.accent);
      p('cyl6', 'solid', 0, e.h, 0, e.w * 0.6, 0.5, e.d * 0.6, k.roof);
    },
    corner(e, p, k) { p('box', 'solid', 0, 0, 0, e.w * 0.8, e.h, e.d * 0.8, k.body); p('roof', 'solid', 0, e.h, -0.4, e.w * 0.9, 0.9, e.d * 0.7, k.accent); },
    silo(e, p, k) {
      p('cyl', 'solid', 0, 0, 0, e.w * 0.8, e.h, e.d * 0.8, k.body);
      p('cyl', 'solid', 0, e.h * 0.33, 0, e.w * 0.83, 0.25, e.d * 0.83, k.roof);
      p('cyl', 'solid', 0, e.h * 0.66, 0, e.w * 0.83, 0.25, e.d * 0.83, k.roof);
      p('sphere', 'solid', 0, e.h - e.w * 0.38, 0, e.w * 0.8, e.w * 0.8, e.d * 0.8, k.accent);
    },
    postoffice(e, p, k) {
      p('box', 'solid', 0, 0, 1, e.w * 0.85, e.h, e.d * 0.6, k.body);
      p('roof', 'solid', 0, e.h, 1, e.w * 0.9, 1.6, e.d * 0.66, k.roof);
      p('box', 'solid', e.w * 0.38, 0, -e.d * 0.2, 0.2, e.h + 2.5, 0.2, k.roof);
      p('box', 'solid', e.w * 0.38 + 0.7, e.h + 1.6, -e.d * 0.2, 1.3, 0.8, 0.1, k.accent);
      const n = Math.min(10, Math.max(0, (e.res && e.res.attrs && e.res.attrs.messages) || 0));
      for (let i = 0; i < n; i++) p('box', 'solid', -e.w * 0.4 + i * 0.9, 0, -e.d * 0.4, 0.7, 0.55, 0.5, k.accent.clone().lerp(new THREE.Color(1, 1, 1), 0.35));
    },
    radio(e, p, k) {
      p('box', 'solid', 0, 0, 0, e.w * 0.7, 2.2, e.d * 0.7, k.body);
      p('cone', 'solid', 0, 2.2, 0, 1.8, e.h - 2, 1.8, k.accent);
      p('sphere', 'glow', 0, e.h - 0.2, 0, 1.1, 1.1, 1.1, k.lit ? k.win : k.winOff);
    },
    control(e, p, k) { p('box', 'solid', 0, 0, 0, e.w * 0.85, e.h * 0.7, e.d * 0.85, k.body); p('sphere', 'solid', 0, e.h * 0.7 - e.w * 0.25, 0, e.w * 0.6, e.w * 0.6, e.d * 0.6, k.accent); },
    depot(e, p, k) {
      p('box', 'solid', 0, 0, 0, e.w, 0.2, e.d, k.roof);
      for (let i = 0; i < 8; i++) p('box', 'solid', -e.w * 0.3 + (i % 4) * (e.w * 0.2), 0.2 + Math.floor(i / 4) * 1.2, -e.d * 0.15 + (i % 2) * 2, e.w * 0.17, 1.1, 1.8, i % 3 ? k.body : k.accent);
    },
    locksmith(e, p, k) { p('box', 'solid', 0, 0, 0, e.w * 0.8, e.h, e.d * 0.8, k.body); p('cone', 'solid', 0, e.h, 0, e.w, 1.4, e.d, k.roof); p('cyl', 'solid', e.w * 0.45, e.h * 0.5, -e.d * 0.45, 0.9, 0.9, 0.2, k.accent, 0, Math.PI / 2); },
    records(e, p, k) { p('box', 'solid', 0, 0, 0, e.w * 0.8, e.h, e.d * 0.8, k.body); p('roof', 'solid', 0, e.h, 0, e.w * 0.86, 1, e.d * 0.86, k.roof); },
    toll(e, p, k) {
      p('box', 'solid', 0, 0, 0.6, 2.2, e.h, 2.2, k.body);
      for (const sx of [-1, 1]) p('box', 'solid', sx * e.w * 0.42, 0, 0.6, 0.4, e.h + 0.8, 0.4, k.roof);
      p('box', 'solid', 0, e.h + 0.8, 0.6, e.w, 0.35, e.d * 0.7, k.accent);
      p('box', 'solid', e.w * 0.25, 1.1, -e.d * 0.35, e.w * 0.55, 0.25, 0.25, k.accent);
    },
    tunnel(e, p, k) {
      p('box', 'solid', -e.w * 0.38, 0, 0, 0.9, e.h + 0.6, e.d * 0.8, k.roof);
      p('box', 'solid', e.w * 0.38, 0, 0, 0.9, e.h + 0.6, e.d * 0.8, k.roof);
      p('box', 'solid', 0, e.h + 0.6, 0, e.w * 0.95, 0.7, e.d * 0.8, k.accent);
      p('box', 'solid', 0, 0, 0.2, e.w * 0.6, e.h + 0.5, e.d * 0.5, k.winOff);
    },
    airport(e, p, k) {
      p('box', 'solid', 0, 0, e.d * 0.12, e.w, 0.12, e.d * 0.76, k.roof.clone().lerp(k.body, 0.6));
      p('box', 'solid', 0, 0.12, e.d * 0.28, e.w * 0.95, 0.06, 2.4, k.winOff);
      for (let i = 0; i < 6; i++) p('box', 'glow', -e.w * 0.4 + i * (e.w * 0.16), 0.19, e.d * 0.28, 1.6, 0.03, 0.25, k.win);
      p('box', 'solid', -e.w * 0.12, 0, -e.d * 0.28, e.w * 0.6, e.h, e.d * 0.3, k.body);
      p('box', k.lit ? 'glow' : 'solid', -e.w * 0.12, e.h * 0.4, -e.d * 0.28 - e.d * 0.15 - 0.05, e.w * 0.56, e.h * 0.35, 0.12, k.lit ? k.win : k.winOff);
      p('cyl', 'solid', e.w * 0.33, 0, -e.d * 0.28, 1.4, e.h + 6, 1.4, k.roof);
      p('cyl', 'glow', e.w * 0.33, e.h + 6, -e.d * 0.28, 2.6, 1.4, 2.6, k.lit ? k.win : k.winOff);
      // a plane on the apron
      p('box', 'solid', -e.w * 0.25, 0.9, e.d * 0.08, 4.2, 0.7, 0.7, k.accent);
      p('box', 'solid', -e.w * 0.25 + 0.2, 1.0, e.d * 0.08, 0.9, 0.18, 4.4, k.accent);
      p('box', 'solid', -e.w * 0.25 - 1.8, 1.2, e.d * 0.08, 0.6, 0.9, 1.6, k.accent);
    },
    directory(e, p, k) {
      p('box', 'solid', 0, 0, 0, e.w * 0.7, 1, e.d * 0.7, k.roof);
      p('box', 'solid', 0, 1, 0, e.w * 0.4, e.h - 1, e.d * 0.4, k.body);
      p('box', 'glow', 0, e.h - 2.2, -e.d * 0.21, e.w * 0.36, 1.6, 0.1, k.win);
      p('cone', 'solid', 0, e.h, 0, e.w * 0.44, 2.2, e.d * 0.44, k.accent);
    },
    hq(e, p, k) {
      p('box', 'solid', 0, 0, 0, e.w + 1, 3, e.d + 1, k.roof);
      p('box', 'solid', 0, e.h - 2, 0, e.w * 0.9, 1, e.d * 0.9, k.roof);
      p('cyl', 'solid', 0, e.h - 1, 0, 0.4, 5, 0.4, k.roof);
      p('sphere', 'glow', 0, e.h + 3.8, 0, 0.9, 0.9, 0.9, k.win);
    },
    floor(e, p, k) {
      p('box', 'solid', 0, 0, 0, e.w, e.h, e.d, k.body);
      p('box', e.lit ? 'glow' : 'solid', 0, e.h * 0.28, 0, e.w + 0.14, e.h * 0.46, e.d + 0.14, e.lit ? k.win : k.winOff);
    },
    badges(e, p, k) { p('box', 'solid', 0, 0, 0, e.w * 0.85, e.h, e.d * 0.8, k.body); p('roof', 'solid', 0, e.h, 0, e.w * 0.9, 1.4, e.d * 0.86, k.roof); p('box', 'glow', 0, e.h * 0.55, -e.d * 0.41, e.w * 0.5, 1, 0.1, k.win); },
    unknown(e, p, k) { p('box', 'solid', 0, 0, 0, e.w * 0.75, e.h, e.d * 0.75, k.body); p('sphere', 'solid', 0, e.h, 0, 1.6, 1.6, 1.6, k.accent); },
    stack(e, p, k) {
      const n = Math.min(9, e.members.length);
      const per = Math.ceil(Math.sqrt(n));
      const cell = e.w / per;
      for (let i = 0; i < n; i++) {
        const hs = A.city.hash(e.id + i);
        p('box', 'solid', ((i % per) - (per - 1) / 2) * cell, 0, (Math.floor(i / per) - (per - 1) / 2) * cell, cell * 0.8, e.h * (0.6 + (hs % 5) / 10), cell * 0.8, i % 2 ? k.body : k.body.clone().lerp(k.roof, 0.3));
      }
    },
    plot(e, p, k, pal) {
      p('box', 'solid', 0, 0, 0, e.w, 0.12, e.d, pal.emptyBlock.clone().lerp(pal.vacantRoof, 0.25));
      for (const sx of [-1, 1]) for (const sz of [-1, 1]) p('box', 'solid', sx * (e.w / 2 - 0.4), 0, sz * (e.d / 2 - 0.4), 0.25, 1.2, 0.25, pal.trunk);
    },
  };

  function post(p, x, z, h, color, vacant) {
    p('box', 'solid', x, 0, z, 0.25, h, 0.25, color);
    p('box', 'solid', x, h - 1, z - 0.15, 1.8, 0.95, 0.15, color);
    if (vacant) p('cyl', 'solid', x, 0, z + 1.2, 1.2, 0.2, 1.2, color);
  }
  function fence(p, e, color) {
    const w = e.w, d = e.d;
    p('box', 'solid', 0, 0, d / 2, w, 0.7, 0.15, color);
    p('box', 'solid', -w / 2, 0, 0, 0.15, 0.7, d, color);
    p('box', 'solid', w / 2, 0, 0, 0.15, 0.7, d, color);
  }

  function drawEnt(e, B, pal, st) {
    if (e.kind === 'internet') return;               // drawn as its own spinning portal
    if (e.kind === 'ghost') {
      const put = B.local(e.cx, e.cz, e.rot, ISLAND_TOP, e.id);
      put('box', 'solid', 2, 0, 1, 3, 1.4, 3, pal.vacantRoof);
      put('box', 'solid', -2.5, 0, -1.5, 2.2, 0.8, 2.2, pal.vacant);
      return;
    }
    if (e.kind === 'person') {
      const put = B.local(e.cx, e.cz, e.rot, BASE_Y, e.id);
      const k = colorsFor(Object.assign({ group: 'security' }, e), pal);
      put('cyl', 'solid', 0, 0, 0, 0.7, 1.2, 0.7, e.vacant ? pal.vacant : k.accent);
      put('sphere', 'solid', 0, 1.2, 0, 0.6, 0.6, 0.6, pal.sand);
      return;
    }
    const group = e.kind === 'hq' || e.kind === 'floor' || e.kind === 'badges' ? 'security' : e.group || 'ops';
    const k = colorsFor(Object.assign({}, e, { group }), pal);
    const y0 = BASE_Y + (e.y0 || 0);
    const put = B.local(e.cx, e.cz, e.rot, y0, e.id);
    // blob shadow
    if (e.kind !== 'floor' && e.kind !== 'plot') B.add('plane', 'shadow', e.cx, BLOCK_TOP + 0.03, e.cz, (e.w || 4) * 1.15, 1, (e.d || 4) * 1.15, e.rot, pal.white);
    const fn = ARCH[e.archetype] || ARCH.unknown;
    fn(e, put, k, pal);
    // satellites
    for (const s of e.sats || []) {
      const sp = B.local(s.cx, s.cz, s.rot, BASE_Y, e.id);
      const sk = colorsFor({ group: s.kind === 'shed' ? 'data' : 'network', vacant: s.vacant }, pal);
      if (s.kind === 'shed') ARCH.shed(Object.assign({}, s, { h: 2.4 }), sp, sk);
      else if (s.kind === 'signpost') post(sp, 0, 0, 3.4, sk.accent, s.vacant);
      else ARCH.kiosk(s, sp, sk);
    }
    // "for rent" sign on vacant buildings
    if (e.vacant && e.kind !== 'plot') {
      put('box', 'solid', (e.w || 6) / 2 + 0.6, 0, -(e.d || 6) / 2 - 0.4, 0.2, 2.2, 0.2, pal.trunk);
      put('box', 'solid', (e.w || 6) / 2 + 0.6, 1.4, -(e.d || 6) / 2 - 0.5, 1.9, 1.1, 0.12, pal.warn);
    }
    // an open door to the whole Internet: a red arch in front
    if (e.door && e.kind === 'building') {
      const hw = Math.min(3, (e.w || 6) / 3);
      put('box', 'solid', -hw, 0, -(e.d || 6) / 2 - 1.6, 0.5, 3.2, 0.5, pal.danger);
      put('box', 'solid', hw, 0, -(e.d || 6) / 2 - 1.6, 0.5, 3.2, 0.5, pal.danger);
      put('box', 'solid', 0, 3.2, -(e.d || 6) / 2 - 1.6, hw * 2 + 0.5, 0.5, 0.6, pal.danger);
    }
  }

  function drawPin(e, B, pal) {
    if (e.kind === 'floor' || e.kind === 'person') return;
    const top = BASE_Y + (e.y0 || 0) + (e.h || 2) + (e.archetype === 'plaza' ? 8 : e.archetype === 'airport' ? 8 : 2.6);
    // the shape carries the severity (as in the legend: ▲ high, ◆ medium, ● low); the colour only repeats it
    if (e.sev === 'high') B.add('cone', 'glow', e.cx, top - 0.6, e.cz, 2.2, 2.4, 2.2, 0, pal.critical, e.id);
    else if (e.sev === 'medium') B.add('octa', 'glow', e.cx, top - 0.6, e.cz, 1.9, 2.6, 1.9, 0, pal.serious, e.id);
    else if (e.sev === 'low') B.add('sphere', 'glow', e.cx, top - 0.4, e.cz, 1.5, 1.5, 1.5, 0, pal.muted, e.id);
    if (e.coin > 0.5) B.add('cyl', 'solid', e.cx + 2.2, top + (e.sev ? 0.6 : -0.6), e.cz, 1.8, 0.35, 1.8, e.rot, pal.gold, e.id, Math.PI / 2);
  }

  // ---- traffic ----------------------------------------------------------------------------------------------------------------
  Stage.prototype.visibleFlows = function () {
    if (!this.world) return [];
    return this.world.flows;
  };

  Stage.prototype.buildCars = function () {
    const w = this.world, pal = this.pal;
    const counts = { car: 0, van: 0, truck: 0, ghost: 0 };
    const cars = [];
    for (const f of w.flows) {
      if (!f.pts || f.pts.length < 2) continue;
      const cum = [0];
      for (let i = 1; i < f.pts.length; i++) cum.push(cum[i - 1] + Math.hypot(f.pts[i][0] - f.pts[i - 1][0], f.pts[i][1] - f.pts[i - 1][1]));
      f.cum = cum;
      const ghost = f.status === 'unknown';
      for (let i = 0; i < f.cars; i++) {
        const type = ghost ? 'ghost' : f.car;
        const hs = A.city.hash(f.id + ':' + i);
        const color = ghost ? pal.ghostCar : f.danger ? pal.danger : type === 'car' ? pal.car[hs % pal.car.length] : pal[type];
        cars.push({ f, type, idx: counts[type]++, off: (i / f.cars) * f.len + (hs % 1000) / 1000 * (f.len / Math.max(1, f.cars)) * 0.5, speed: A.city.CAR_SPEED * (ghost ? 0.55 : 0.85 + (hs % 30) / 100), seg: 0, color });
      }
    }
    this.cars = cars;
    this.carMeshes = {};
    for (const type of ['car', 'van', 'truck', 'ghost']) {
      const n = counts[type];
      if (!n) continue;
      const geo = this.carGeo[type === 'ghost' ? 'car' : type];
      const mesh = new THREE.InstancedMesh(geo, type === 'ghost' ? this.mats.ghost : this.mats.solid, n);
      mesh.instanceMatrix.setUsage(THREE.DynamicDrawUsage);
      mesh.instanceColor = new THREE.InstancedBufferAttribute(new Float32Array(n * 3), 3);
      mesh.frustumCulled = false;
      this.carMeshes[type] = mesh;
      this.root.add(mesh);
    }
    for (const c of cars) this.carMeshes[c.type].setColorAt(c.idx, c.color);
    // parked vans for dead-letter queues, cones on roads measured empty
    const PB = new Batcher(this);
    for (const f of w.flows) {
      if (!f.pts || f.pts.length < 2) continue;
      const end = f.pts[f.pts.length - 1], prev = f.pts[f.pts.length - 2];
      const ang = Math.atan2(-(end[1] - prev[1]), end[0] - prev[0]);
      if (f.status === 'zero') {
        for (const [p, q] of [[f.pts[0], f.pts[1]], [end, prev]]) {
          const t = Math.min(1, 3 / Math.max(0.1, Math.hypot(q[0] - p[0], q[1] - p[1])));
          PB.add('cone', 'solid', p[0] + (q[0] - p[0]) * t, ROAD_Y, p[1] + (q[1] - p[1]) * t, 0.7, 1.1, 0.7, 0, pal.cone, f.id);
        }
      }
      if (f.status === 'parked' && f.parked > 0) {
        const n = Math.min(6, f.parked);
        for (let i = 0; i < n; i++) {
          const t = Math.min(1, (2 + i * 2.8) / Math.max(0.1, Math.hypot(prev[0] - end[0], prev[1] - end[1])));
          PB.add('car:van', 'solid', end[0] + (prev[0] - end[0]) * t, ROAD_Y + 0.02, end[1] + (prev[1] - end[1]) * t, 1, 1, 1, ang, pal.van, f.id);
        }
      }
    }
    PB.flush(this.root);
    this.updateCars(true);
  };

  Stage.prototype.updateCars = function (force) {
    if (!this.cars) return;
    const t = this.t;
    const hide = this.carFilter;
    const off = !!this.carsOff;
    const touched = new Set();
    for (const c of this.cars) {
      const f = c.f;
      const arr = this.carMeshes[c.type].instanceMatrix.array;
      const o = c.idx * 16;
      touched.add(c.type);
      if (off || (hide && !hide.has(f.id))) { arr.fill(0, o, o + 16); continue; }
      const s = (c.off + t * c.speed) % f.len;
      if (s < (c.last || 0)) c.seg = 0;
      c.last = s;
      const cum = f.cum;
      while (c.seg < cum.length - 2 && cum[c.seg + 1] < s) c.seg++;
      const a = f.pts[c.seg], b = f.pts[c.seg + 1];
      const L = cum[c.seg + 1] - cum[c.seg] || 1;
      const u = (s - cum[c.seg]) / L;
      const dx = (b[0] - a[0]) / L, dz = (b[1] - a[1]) / L;
      const x = a[0] + (b[0] - a[0]) * u + dz * 0.95, z = a[1] + (b[1] - a[1]) * u - dx * 0.95;
      const cs = dx, sn = -dz;                       // yaw so the car's +x points along the road
      arr[o] = cs; arr[o + 1] = 0; arr[o + 2] = -sn; arr[o + 3] = 0;
      arr[o + 4] = 0; arr[o + 5] = 1; arr[o + 6] = 0; arr[o + 7] = 0;
      arr[o + 8] = sn; arr[o + 9] = 0; arr[o + 10] = cs; arr[o + 11] = 0;
      arr[o + 12] = x; arr[o + 13] = ROAD_Y; arr[o + 14] = z; arr[o + 15] = 1;
    }
    touched.forEach((k) => { this.carMeshes[k].instanceMatrix.needsUpdate = true; });
  };

  // ---- "follow a request": one highlighted car driving the whole path ----------------------------------------------------------------
  Stage.prototype.follow = function (path) {
    if (this.followMesh) { this.root && this.root.remove(this.followMesh); this.followMesh = null; }
    this.followPath = null;
    this.followData = path || null;
    if (!path || !path.pts || path.pts.length < 2) { this.dirty = true; return; }
    const cum = [0];
    for (let i = 1; i < path.pts.length; i++) cum.push(cum[i - 1] + Math.hypot(path.pts[i][0] - path.pts[i - 1][0], path.pts[i][1] - path.pts[i - 1][1]));
    this.followPath = { pts: path.pts, cum, len: cum[cum.length - 1], s: 0 };
    const g = new THREE.Group();
    const body = new THREE.Mesh(this.carGeo.car, new THREE.MeshBasicMaterial({ color: this.pal.accent }));
    body.scale.set(1.6, 1.6, 1.6);
    const halo = new THREE.Mesh(this.prims.sphere, new THREE.MeshBasicMaterial({ color: this.pal.accent, transparent: true, opacity: 0.25, depthWrite: false }));
    halo.scale.set(6, 6, 6);
    halo.position.y = -1.2;
    g.add(body, halo);
    this.followMesh = g;
    this.root.add(g);
    this.updateFollow(0);
    this.dirty = true;
  };
  Stage.prototype.updateFollow = function (dt) {
    const p = this.followPath;
    if (!p || !this.followMesh) return;
    p.s = (p.s + dt * 14) % p.len;
    let i = 0;
    while (i < p.cum.length - 2 && p.cum[i + 1] < p.s) i++;
    const a = p.pts[i], b = p.pts[i + 1];
    const L = p.cum[i + 1] - p.cum[i] || 1;
    const u = (p.s - p.cum[i]) / L;
    this.followMesh.position.set(a[0] + (b[0] - a[0]) * u, ROAD_Y + 0.1, a[1] + (b[1] - a[1]) * u);
    this.followMesh.rotation.y = Math.atan2(-(b[1] - a[1]), b[0] - a[0]);
  };

  // ---- selection, layers, overlays ----------------------------------------------------------------------------------------------
  Stage.prototype.setLayers = function (layers) {
    const before = JSON.stringify(this.layers);
    Object.assign(this.layers, layers);
    if (JSON.stringify(this.layers) === before) return;
    if (!this.layers.traffic) this.updateCars(true);
    this.applyFocus();
    this.buildOverlay();
    this.labelsStale = true;
    this.dirty = true;
  };

  /** Select one road: only its two ends stay in colour and only its cars keep driving. */
  Stage.prototype.selectFlow = function (flowId) {
    this.sel = null;
    this.selFlow = flowId;
    this.applyFocus();
    this.buildOverlay();
    this.labelsStale = true;
    this.dirty = true;
  };

  Stage.prototype.select = function (id, fly) {
    this.selFlow = null;
    this.sel = id;
    if (fly && id) this.focusEnt(id);
    this.applyFocus();
    this.buildOverlay();
    this.labelsStale = true;
    this.dirty = true;
  };

  Stage.prototype.neighbours = function (id) {
    const out = new Set([id]);
    const e = this.world.byId.get(id);
    if (e && e.parent) out.add(e.parent);
    if (e && e.floors) e.floors.forEach((f) => out.add(f.id));
    for (const f of this.world.flows) if (f.from === id || f.to === id) { out.add(f.from); out.add(f.to); }
    for (const o of this.world.overlays) {
      if (o.from !== id && o.to !== id) continue;
      if (o.kind === 'likely' && !this.layers.likely) continue;
      if (o.kind === 'may-connect' && !this.layers.security) continue;
      out.add(o.from); out.add(o.to);
      const t = this.world.byId.get(o.from === id ? o.to : o.from);
      if (t && t.parent) out.add(t.parent);
    }
    return out;
  };

  /** Dims everything outside the selection (or outside the waste layer) and filters the cars. */
  Stage.prototype.applyFocus = function () {
    if (!this.world || !this.instOf) return;
    let keep = null;
    const flow = this.selFlow && this.world.flows.find((f) => f.id === this.selFlow);
    if (flow) keep = new Set([flow.from, flow.to]);
    else if (this.sel && this.world.byId.has(this.sel)) keep = this.neighbours(this.sel);
    else if (this.layers.waste) keep = new Set(this.world.ents.filter((e) => e.vacant || (e.sats || []).some((s) => s.vacant) || (e.findings || []).some((f) => f.category === 'unused')).map((e) => e.id));
    const dim = this.pal.dim.toArray();
    const meshes = new Set();
    this.instOf.forEach((list) => list.forEach(([m]) => meshes.add(m)));
    meshes.forEach((m) => {
      const base = m.userData.base, own = m.userData.own, arr = m.instanceColor.array;
      for (let i = 0; i < own.length; i++) {
        const o = own[i];
        const fade = keep && o && !o.startsWith('plate:') && !o.startsWith('gate:') && !keep.has(o);
        for (let c = 0; c < 3; c++) arr[i * 3 + c] = fade ? base[i * 3 + c] * 0.3 + dim[c] * 0.7 : base[i * 3 + c];
      }
      m.instanceColor.needsUpdate = true;
    });
    this.carFilter = flow ? new Set([flow.id]) : this.sel ? new Set(this.world.flows.filter((f) => f.from === this.sel || f.to === this.sel).map((f) => f.id)) : null;
    this.updateCars(true);
    this.buildHighlight();
    this.dirty = true;
  };

  Stage.prototype.buildHighlight = function () {
    if (this.hlMesh) { this.root.remove(this.hlMesh); this.hlMesh.traverse((o) => { if (o.isInstancedMesh) o.dispose(); }); this.hlMesh = null; }
    if ((!this.sel && !this.selFlow) || !this.world) return;
    const B = new Batcher(this);
    for (const f of this.world.flows) {
      if (this.selFlow ? f.id !== this.selFlow : f.from !== this.sel && f.to !== this.sel) continue;
      const col = f.danger ? this.pal.danger : this.pal.accent;
      for (let i = 1; i < f.pts.length; i++) {
        const a = f.pts[i - 1], b = f.pts[i];
        const len = Math.hypot(b[0] - a[0], b[1] - a[1]);
        if (len < 0.05) continue;
        B.add('box', 'glow', (a[0] + b[0]) / 2, ROAD_Y + 0.05, (a[1] + b[1]) / 2, len + 0.4, 0.05, 0.9, Math.atan2(-(b[1] - a[1]), b[0] - a[0]), col);
      }
    }
    const g = new THREE.Group();
    B.flush(g);
    this.hlMesh = g;
    this.root.add(g);
  };

  /** Dashed arcs: footpaths to the directory, badge beams, firewall permissions, guesses. */
  Stage.prototype.buildOverlay = function () {
    if (!this.root) return;
    if (this.ovMesh) { this.root.remove(this.ovMesh); this.ovMesh.traverse((o) => { if (o.isInstancedMesh) o.dispose(); }); this.ovMesh = null; }
    const w = this.world, pal = this.pal;
    const B = new Batcher(this);
    const q = new THREE.Quaternion(), X = new THREE.Vector3(1, 0, 0), dir = new THREE.Vector3(), m = new THREE.Matrix4();
    const pos = new THREE.Vector3(), scl = new THREE.Vector3();
    const g = B.groups;
    const push = (mat, col, x, y, z, len, thick) => {
      const k = 'box|' + mat;
      if (!g.has(k)) g.set(k, { prim: 'box', mat, m: [], c: [], own: [] });
      const gg = g.get(k);
      pos.set(x, y, z); scl.set(len, thick, thick);
      m.compose(pos, q, scl);
      gg.m.push(...m.elements); gg.c.push(col.r, col.g, col.b); gg.own.push(null);
    };
    for (const o of w.overlays) {
      const sel = this.sel && (o.from === this.sel || o.to === this.sel);
      let show = false, col = pal.muted, mat = 'glow', gap = 0.55;
      if (o.kind === 'may-connect') { show = this.layers.security || sel && this.layers.security; col = pal.serious; }
      else if (o.kind === 'likely') { show = this.layers.likely; col = pal.muted; mat = 'ghost'; gap = 0.45; }
      else if (o.kind === 'dns') { show = !!sel; col = pal.accent; }        // blue: never the security layer's orange
      else if (o.kind === 'uses-role') { show = !!sel; col = pal.groups.security.accent; gap = 0.7; }
      if (!show) continue;
      const a = w.byId.get(o.from), b = w.byId.get(o.to);
      if (!a || !b) continue;
      const ya = BASE_Y + (a.y0 || 0) + (a.kind === 'floor' ? a.h / 2 : Math.min(a.h || 3, 6));
      const yb = BASE_Y + (b.y0 || 0) + (b.kind === 'floor' ? b.h / 2 : Math.min(b.h || 3, 6));
      const dist = Math.hypot(b.cx - a.cx, b.cz - a.cz);
      const lift = 4 + dist * 0.18;
      const n = Math.max(6, Math.min(70, Math.round(dist / 2.2)));
      const P = (t) => {
        const it = 1 - t;
        return [it * it * a.cx + 2 * it * t * ((a.cx + b.cx) / 2) + t * t * b.cx,
          it * it * ya + 2 * it * t * (Math.max(ya, yb) + lift) + t * t * yb,
          it * it * a.cz + 2 * it * t * ((a.cz + b.cz) / 2) + t * t * b.cz];
      };
      for (let i = 0; i < n; i++) {
        const p0 = P(i / n), p1 = P((i + 1) / n);
        dir.set(p1[0] - p0[0], p1[1] - p0[1], p1[2] - p0[2]);
        const len = dir.length();
        dir.normalize();
        q.setFromUnitVectors(X, dir);
        push(mat, sel ? (o.kind === 'likely' ? pal.muted : col) : col, (p0[0] + p1[0]) / 2, (p0[1] + p1[1]) / 2, (p0[2] + p1[2]) / 2, len * gap, o.kind === 'likely' ? 0.35 : 0.42);
      }
    }
    const grp = new THREE.Group();
    B.flush(grp);
    this.ovMesh = grp;
    this.root.add(grp);
  };

  // ---- labels (pooled DOM overlay) ---------------------------------------------------------------------------------------------
  Stage.prototype.updateLabels = function () {
    this.labelsStale = false;
    const w = this.world;
    if (!w || !this.container) return;
    const W = this.container.clientWidth, H = this.container.clientHeight;
    const v = new THREE.Vector3();
    const camPos = this.camera.position;
    const cand = [];
    const neigh = this.sel ? this.neighbours(this.sel) : null;
    const showAll = this.layers.labels;
    for (const l of w.labels) {
      if (!showAll && l.kind !== 'city') continue;
      cand.push({ id: l.id, text: l.text, sub: l.sub, x: l.x, y: l.y, z: l.z, kind: l.kind, pri: l.kind === 'city' ? 3 : l.kind === 'district' ? 4 : 7, lod: l.kind === 'city' ? 1e9 : l.kind === 'district' ? 900 : 230 });
    }
    for (const e of w.ents) {
      const special = e.id === this.sel ? 0 : e.id === this.hover ? 1 : neigh && neigh.has(e.id) ? 2 : null;
      if (special == null && (!showAll || e.kind === 'floor' || e.kind === 'person' || e.kind === 'plot')) continue;
      const pri = special != null ? special : e.kind === 'internet' || e.kind === 'hq' ? 3 : e.kind === 'ghost' ? 6 : e.sev === 'high' ? 5 : 6;
      const top = BASE_Y + (e.y0 || 0) + (e.kind === 'internet' ? 15 : (e.h || 2)) + 1.2;
      const sevMark = e.sev && e.sev !== 'info' && A.SEV && A.SEV[e.sev] ? `${A.SEV[e.sev].icon} ${A.SEV[e.sev].label.toLowerCase()} · ` : '';
      const sub = e.kind === 'internet' ? 'visitors arrive here' : e.kind === 'ghost' ? sevMark + 'quiet region' : sevMark + (C.ARCHETYPES[e.archetype] || C.ARCHETYPES.unknown).name;
      cand.push({ id: e.id, text: e.name, sub, x: e.cx, y: top, z: e.cz, kind: special != null ? 'focus' : 'building', pri, lod: special != null ? 1e9 : e.kind === 'internet' || e.kind === 'hq' ? 1200 : 200, cost: e.cost || 0, ent: e });
    }
    const placed = [];
    const rects = [];
    for (const c of cand) {
      const dist = Math.hypot(c.x - camPos.x, c.y - camPos.y, c.z - camPos.z);
      if (dist > c.lod) continue;
      v.set(c.x, c.y, c.z).project(this.camera);
      if (v.z > 1 || v.x < -1.1 || v.x > 1.1 || v.y < -1.1 || v.y > 1.1) continue;
      c.sx = (v.x * 0.5 + 0.5) * W; c.sy = (-v.y * 0.5 + 0.5) * H; c.dist = dist;
      placed.push(c);
    }
    placed.sort((a, b) => a.pri - b.pri || (b.cost || 0) - (a.cost || 0) || a.dist - b.dist);
    const out = [];
    for (const c of placed) {
      if (out.length >= 60) break;
      const tw = Math.min(220, Math.max(c.text.length * 7.2, (c.sub || '').length * 6) + 14), th = c.sub ? 34 : 20;
      const r = { x0: c.sx - tw / 2, x1: c.sx + tw / 2, y0: c.sy - th - 4, y1: c.sy - 4 };
      if (c.pri > 2 && rects.some((q) => r.x0 < q.x1 && r.x1 > q.x0 && r.y0 < q.y1 && r.y1 > q.y0)) continue;
      rects.push(r);
      out.push(c);
    }
    while (this.labelPool.length < out.length) {
      const el = document.createElement('div');
      el.className = 'city-label';
      el.appendChild(document.createElement('b'));
      el.appendChild(document.createElement('span'));
      this.labelLayer.appendChild(el);
      this.labelPool.push(el);
    }
    this.labelPool.forEach((el, i) => {
      const c = out[i];
      if (!c) { el.hidden = true; return; }
      el.hidden = false;
      el.className = 'city-label k-' + c.kind + (c.ent && c.ent.sev ? ' sev-' + c.ent.sev : '');
      if (el.firstChild.textContent !== c.text) el.firstChild.textContent = c.text;
      const sub = c.sub || '';
      if (el.lastChild.textContent !== sub) el.lastChild.textContent = sub;
      el.lastChild.hidden = !sub;
      el.style.transform = `translate(${Math.round(c.sx)}px, ${Math.round(c.sy)}px) translate(-50%, -100%)`;
    });
    this.visibleLabels = out;
  };

  // ---- export ----------------------------------------------------------------------------------------------------------------
  Stage.prototype.savePng = function (footer) {
    this.cam.apply(this.camera);
    this.renderer.render(this.scene, this.camera);
    const src = this.renderer.domElement;
    const out = document.createElement('canvas');
    out.width = src.width; out.height = src.height + 40 * this.dpr;
    const g = out.getContext('2d');
    g.drawImage(src, 0, 0);
    const k = src.width / Math.max(1, this.container.clientWidth);
    g.font = `${Math.round(12 * k)}px system-ui, sans-serif`;
    g.textAlign = 'center';
    for (const c of this.visibleLabels || []) {
      const x = c.sx * k, y = c.sy * k - 8 * k;
      const tw = g.measureText(c.text).width + 12 * k;
      g.fillStyle = this.pal.dark ? 'rgba(20,24,32,0.85)' : 'rgba(255,255,255,0.88)';
      g.fillRect(x - tw / 2, y - 14 * k, tw, 18 * k);
      g.fillStyle = this.pal.dark ? '#e8ecf2' : '#1d2430';
      g.fillText(c.text, x, y);
    }
    g.fillStyle = this.pal.dark ? '#0b1220' : '#ffffff';
    g.fillRect(0, src.height, out.width, out.height - src.height);
    g.fillStyle = this.pal.dark ? '#c9cdd4' : '#3a4250';
    g.textAlign = 'left';
    g.fillText(footer, 12 * k, src.height + 25 * this.dpr);
    out.toBlob((blob) => { if (blob) A.downloadBlob('aws-3d-map.png', blob); }, 'image/png');
  };

  Stage.prototype.info = function () { return this.renderer.info; };
})();
