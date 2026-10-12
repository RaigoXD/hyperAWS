/* 3D map: a map-style camera (no three.js add-ons). Left-drag grabs the ground, right-drag / Shift-drag turns and tilts,
   the wheel zooms towards the cursor, two fingers pinch / twist / pan. The maths is plain JS; the scene supplies
   `ground(clientX, clientY) -> {x, z} | null` (a ray cast onto the ground plane with the current camera). */
(function () {
  'use strict';
  const A = (window.AWSA = window.AWSA || {});

  const POL_MIN = 0.12, POL_MAX = 1.38;
  const wrapAngle = (a) => Math.atan2(Math.sin(a), Math.cos(a));
  const clamp = (x, lo, hi) => Math.max(lo, Math.min(hi, x));

  function CityCamera(opts) {
    this.o = Object.assign({ minDist: 12, maxDist: 4000, reduced: false }, opts || {});
    this.cur = { x: 0, y: 0, z: 0, d: 300, az: Math.PI, pol: 0.95 };          // looks at (x, y, z); y > 0 only to frame a high floor
    this.goal = Object.assign({}, this.cur);
    this.rate = 12;               // smoothing (1/s); lower while flying
    this.bounds = null;
    this.moving = true;
    this.listeners = [];
  }

  CityCamera.prototype.setBounds = function (b) { this.bounds = b; this.o.maxDist = Math.max(400, b.r * 3.2); };

  CityCamera.prototype.view = function (v, instant) {
    const g = this.goal;
    if (v.x != null) g.x = v.x;
    if (v.y != null) g.y = v.y;
    if (v.z != null) g.z = v.z;
    if (v.d != null) g.d = clamp(v.d, this.o.minDist, this.o.maxDist);
    if (v.az != null) g.az = this.cur.az + wrapAngle(v.az - this.cur.az);
    if (v.pol != null) g.pol = clamp(v.pol, POL_MIN, POL_MAX);
    this.clampTarget();
    if (instant || this.o.reduced) Object.assign(this.cur, g);
    this.moving = true;
  };
  /** Frame a circle of radius r around (x, z). */
  CityCamera.prototype.flyTo = function (x, z, r, extra) {
    const vf = (this.fov || 45) * Math.PI / 180;
    const hf = 2 * Math.atan(Math.tan(vf / 2) * Math.max(0.3, this.aspect || 1.6));
    const d = clamp(r / Math.sin(Math.min(vf, hf) / 2), this.o.minDist, this.o.maxDist);
    this.rate = 4.5;
    this.view(Object.assign({ x, z, d }, extra || {}));
  };
  /** Slides a raised look-at point down its line of sight onto the ground: the same view, with a ground pivot again. */
  CityCamera.prototype.level = function () {
    for (const s of [this.cur, this.goal]) {
      if (!s.y) continue;
      const k = s.y / Math.max(0.05, Math.cos(s.pol));
      s.x -= k * Math.sin(s.pol) * Math.sin(s.az);
      s.z -= k * Math.sin(s.pol) * Math.cos(s.az);
      s.d += k;
      s.y = 0;
    }
  };
  CityCamera.prototype.clampTarget = function () {
    const b = this.bounds;
    if (!b) return;
    const m = 60;
    this.goal.x = clamp(this.goal.x, b.x0 - m, b.x1 + m);
    this.goal.z = clamp(this.goal.z, b.z0 - m, b.z1 + m);
  };

  /** Advance the smoothing; returns true while the view is still changing. */
  CityCamera.prototype.update = function (dt) {
    const c = this.cur, g = this.goal;
    const k = this.o.reduced ? 1 : 1 - Math.exp(-this.rate * Math.min(dt, 0.1));
    let delta = 0;
    for (const p of ['x', 'y', 'z', 'd', 'az', 'pol']) {
      const diff = g[p] - c[p];
      c[p] += diff * k;
      delta = Math.max(delta, Math.abs(diff) / (p === 'd' || p === 'x' || p === 'y' || p === 'z' ? Math.max(1, g.d) : 1));
    }
    if (delta < 1e-4) { Object.assign(c, g); if (this.rate !== 12) this.rate = 12; }
    const was = this.moving;
    this.moving = delta >= 1e-4;
    return this.moving || was;
  };

  /** Writes position + orientation into a three.js PerspectiveCamera. */
  CityCamera.prototype.apply = function (cam) {
    const c = this.cur;
    const s = Math.sin(c.pol);
    cam.position.set(c.x + c.d * s * Math.sin(c.az), c.y + c.d * Math.cos(c.pol), c.z + c.d * s * Math.cos(c.az));
    cam.lookAt(c.x, c.y, c.z);
    cam.near = Math.max(0.5, c.d / 400);
    cam.far = Math.max(2000, c.d * 8);
    cam.updateProjectionMatrix();
  };

  // ---- input -------------------------------------------------------------------------------------------------------------
  CityCamera.prototype.attach = function (el, cb) {
    const self = this;
    const ptrs = new Map();
    let drag = null;
    let pinch = null;
    const on = (t, type, fn, o) => { t.addEventListener(type, fn, o); this.listeners.push(() => t.removeEventListener(type, fn, o)); };
    const instant = () => Object.assign(self.cur, self.goal);

    on(el, 'contextmenu', (e) => e.preventDefault());
    on(el, 'pointerdown', (e) => {
      el.focus({ preventScroll: true });
      self.level();
      ptrs.set(e.pointerId, { x: e.clientX, y: e.clientY });
      try { el.setPointerCapture(e.pointerId); } catch (err) { /* ignore */ }
      if (ptrs.size === 2) { pinch = pinchState(); drag = null; return; }
      const rotate = e.button === 2 || e.button === 1 || e.shiftKey || e.ctrlKey || e.altKey;
      drag = { mode: rotate ? 'rotate' : 'pan', x: e.clientX, y: e.clientY, sx: e.clientX, sy: e.clientY, moved: false,
        g0: rotate ? null : cb.ground(e.clientX, e.clientY) };
    });
    on(el, 'pointermove', (e) => {
      if (ptrs.has(e.pointerId)) ptrs.set(e.pointerId, { x: e.clientX, y: e.clientY });
      if (pinch && ptrs.size === 2) { pinchMove(); return; }
      if (!drag) { if (cb.hover) cb.hover(e); return; }
      const dx = e.clientX - drag.x, dy = e.clientY - drag.y;
      if (Math.hypot(e.clientX - drag.sx, e.clientY - drag.sy) > 4) drag.moved = true;
      if (!drag.moved) return;
      if (drag.mode === 'rotate') {
        const w = el.clientWidth || 800, h = el.clientHeight || 600;
        self.goal.az -= (dx * 2.6) / w;
        self.goal.pol = clamp(self.goal.pol - (dy * 1.6) / h, POL_MIN, POL_MAX);
        instant();
      } else if (drag.g0) {
        const g1 = cb.ground(e.clientX, e.clientY);
        if (g1) { self.goal.x += drag.g0.x - g1.x; self.goal.z += drag.g0.z - g1.z; self.clampTarget(); instant(); cb.changed(); }
      }
      drag.x = e.clientX; drag.y = e.clientY;
      self.moving = true;
      el.classList.add('grabbing');
    });
    const up = (e) => {
      ptrs.delete(e.pointerId);
      if (ptrs.size < 2) pinch = null;
      if (drag && !drag.moved && e.type === 'pointerup' && cb.click) cb.click(e);
      drag = null;
      el.classList.remove('grabbing');
    };
    on(el, 'pointerup', up);
    on(el, 'pointercancel', up);
    on(el, 'pointerleave', (e) => { if (!drag && cb.leave) cb.leave(e); });
    on(el, 'dblclick', (e) => { if (cb.dblclick) cb.dblclick(e); });
    on(el, 'wheel', (e) => {
      e.preventDefault();
      self.level();
      const g = cb.ground(e.clientX, e.clientY);
      const f = Math.exp(clamp(e.deltaY, -120, 120) * (e.ctrlKey ? 0.01 : 0.0016));
      const d0 = self.goal.d;
      const d1 = clamp(d0 * f, self.o.minDist, self.o.maxDist);
      if (g) { self.goal.x = g.x + (self.goal.x - g.x) * (d1 / d0); self.goal.z = g.z + (self.goal.z - g.z) * (d1 / d0); }
      self.goal.d = d1;
      self.clampTarget();
      self.rate = 14;
      self.moving = true;
    }, { passive: false });
    on(el, 'keydown', (e) => {
      if (e.target !== el) return;
      if (/^(Arrow|[-+=_qQeEwWsS]$)/.test(e.key)) self.level();
      const step = self.goal.d * 0.08;
      const fx = -Math.sin(self.goal.az), fz = -Math.cos(self.goal.az);        // forward on the ground
      const rx = Math.cos(self.goal.az), rz = -Math.sin(self.goal.az);         // right
      let handled = true;
      switch (e.key) {
        case 'ArrowUp': self.goal.x += fx * step; self.goal.z += fz * step; break;
        case 'ArrowDown': self.goal.x -= fx * step; self.goal.z -= fz * step; break;
        case 'ArrowLeft': self.goal.x -= rx * step; self.goal.z -= rz * step; break;
        case 'ArrowRight': self.goal.x += rx * step; self.goal.z += rz * step; break;
        case '+': case '=': self.goal.d = clamp(self.goal.d / 1.25, self.o.minDist, self.o.maxDist); break;
        case '-': case '_': self.goal.d = clamp(self.goal.d * 1.25, self.o.minDist, self.o.maxDist); break;
        case 'q': case 'Q': self.goal.az += 0.2; break;
        case 'e': case 'E': self.goal.az -= 0.2; break;
        case 'w': case 'W': self.goal.pol = clamp(self.goal.pol - 0.1, POL_MIN, POL_MAX); break;
        case 's': case 'S': self.goal.pol = clamp(self.goal.pol + 0.1, POL_MIN, POL_MAX); break;
        default: handled = false;
      }
      if (handled) { e.preventDefault(); self.clampTarget(); self.moving = true; if (self.o.reduced) instant(); }
      if (cb.key && !handled) cb.key(e);
    });

    function pinchState() {
      const [a, b] = [...ptrs.values()];
      const mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2;
      return { dist: Math.hypot(a.x - b.x, a.y - b.y), ang: Math.atan2(b.y - a.y, b.x - a.x), mx, my, g: cb.ground(mx, my) };
    }
    function pinchMove() {
      const s = pinchState();
      if (pinch.dist > 0 && s.dist > 0) {
        self.goal.d = clamp(self.goal.d * (pinch.dist / s.dist), self.o.minDist, self.o.maxDist);
        self.goal.az -= wrapAngle(s.ang - pinch.ang);
        self.goal.pol = clamp(self.goal.pol - ((s.my - pinch.my) * 1.2) / (el.clientHeight || 600), POL_MIN, POL_MAX);
      }
      instant();
      const g = cb.ground(s.mx, s.my);
      if (g && pinch.g) { self.goal.x += pinch.g.x - g.x; self.goal.z += pinch.g.z - g.z; self.clampTarget(); instant(); }
      pinch = Object.assign(s, { g: cb.ground(s.mx, s.my) });
      self.moving = true;
      cb.changed();
    }
  };

  CityCamera.prototype.detach = function () { this.listeners.forEach((f) => f()); this.listeners = []; };

  A.CityCamera = CityCamera;
})();
