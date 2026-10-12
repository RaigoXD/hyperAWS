/* Tiny DOM + formatting helpers. Everything user/AWS-supplied goes in via textContent. */
(function () {
  'use strict';
  const A = (window.AWSA = window.AWSA || {});
  const SVG_NS = 'http://www.w3.org/2000/svg';

  function append(el, kids) {
    for (const k of kids) {
      if (k == null || k === false) continue;
      if (Array.isArray(k)) append(el, k);
      else if (k instanceof Node) el.appendChild(k);
      else el.appendChild(document.createTextNode(String(k)));
    }
  }

  /** CSS custom properties (--sev) are ignored by Object.assign(el.style, ...): they need setProperty. */
  function setStyle(el, styles) {
    for (const [name, value] of Object.entries(styles)) {
      if (value == null) continue;
      if (name.startsWith('--')) el.style.setProperty(name, value);
      else el.style[name] = value;
    }
  }

  // ---- element factories: nothing that navigates ---------------------------------------------------------------------
  // No CSP directive blocks a top-level navigation (a link, a meta refresh, a form), so report data must never end up in
  // a URL that a click or the page itself could open. A.h and A.svg are the viewer's element factories and refuse what
  // can navigate or load a URL: such elements (every link included), URL attributes and event handlers given as
  // strings. The viewer's one link, the local download in A.downloadBlob (a blob: URL), is built there and nowhere
  // else. Defence in depth: audit-readonly also scans the viewer's source for other routes (a best-effort heuristic).
  const NAV_TAGS = new Set(['a', 'area', 'base', 'meta', 'link', 'script', 'form', 'iframe', 'frame', 'frameset', 'object',
    'embed', 'applet', 'portal', 'image', 'feimage', 'foreignobject', 'animate', 'animatemotion', 'set']);
  const URL_ATTRS = new Set(['src', 'srcset', 'action', 'formaction', 'ping', 'poster', 'background', 'codebase', 'manifest']);

  function refuse(what) {
    throw new Error('AWSA: refusing ' + what + ' (the report must never navigate or load a URL)');
  }

  /** Throws unless attribute k=v is inert: no URL attribute, no string event handler, and href only as an in-document
      #reference on an SVG element. Attribute names are case-insensitive, so are the checks. */
  function checkAttr(k, v, svg) {
    const name = String(k).toLowerCase();
    if (name.startsWith('on') && typeof v !== 'function') refuse(`a string event handler (${k})`);
    if (URL_ATTRS.has(name)) refuse(`the ${name} attribute`);
    if ((name === 'href' || name.endsWith(':href')) && !(svg && /^#/.test(String(v)))) {
      refuse(`href ${JSON.stringify(String(v).slice(0, 60))}`);
    }
  }

  /** h('div', {class:'x', onClick: fn, dataset:{a:1}}, 'text', childEl) */
  A.h = function h(tag, attrs, ...kids) {
    tag = String(tag);          // converted once: an object's toString could name another element the second time
    if (NAV_TAGS.has(tag.toLowerCase())) refuse(`<${tag}>`);
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null || v === false) continue;
      checkAttr(k, v, false);
      if (k === 'class') el.className = v;
      else if (k === 'dataset') Object.assign(el.dataset, v);
      else if (k === 'style' && typeof v === 'object') setStyle(el, v);
      else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2).toLowerCase(), v);
      else el.setAttribute(k, v === true ? '' : v);
    }
    append(el, kids);
    return el;
  };

  A.svg = function svg(tag, attrs, ...kids) {
    tag = String(tag);
    if (NAV_TAGS.has(tag.toLowerCase())) refuse(`<svg:${tag}>`);
    const el = document.createElementNS(SVG_NS, tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null || v === false) continue;
      if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2).toLowerCase(), v);
      else if (k === 'style' && typeof v === 'object') setStyle(el, v);
      else {
        const s = String(v);    // converted once: the value that is checked is the value that is set
        checkAttr(k, s, true);
        el.setAttribute(k, s);
      }
    }
    append(el, kids);
    return el;
  };

  A.clear = function clear(el) {
    while (el.firstChild) el.removeChild(el.firstChild);
    return el;
  };

  // ---- formatting -------------------------------------------------------
  const nf0 = new Intl.NumberFormat('en-US', { maximumFractionDigits: 0 });
  const nf2 = new Intl.NumberFormat('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  A.fmt = {
    num: (n) => nf0.format(n || 0),
    usd(n) {
      n = n || 0;
      if (Math.abs(n) >= 100) return '$' + nf0.format(n);
      return '$' + nf2.format(n);
    },
    usdc(n) { // compact: $1.2K, $3.4M
      n = n || 0;
      const a = Math.abs(n);
      if (a >= 1e6) return '$' + (n / 1e6).toFixed(1) + 'M';
      if (a >= 1e4) return '$' + (n / 1e3).toFixed(0) + 'K';
      if (a >= 1e3) return '$' + (n / 1e3).toFixed(1) + 'K';
      return '$' + nf0.format(n);
    },
    pct: (n) => (n == null ? '–' : (Math.round(n * 10) / 10) + '%'),
    bytes(n) {
      n = n || 0;
      const u = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
      let i = 0;
      while (n >= 1000 && i < u.length - 1) { n /= 1000; i++; }
      return (i === 0 ? nf0.format(n) : n.toFixed(n >= 100 ? 0 : 1)) + ' ' + u[i];
    },
    date: (iso) => (iso ? iso.slice(0, 10) : '–'),
    ageDays(iso) {
      if (!iso) return null;
      const t = Date.parse(iso);
      return isNaN(t) ? null : (Date.now() - t) / 86400000;
    },
    age(iso) {
      const d = A.fmt.ageDays(iso);
      if (d == null) return '–';
      if (d < 1) return 'today';
      if (d < 60) return Math.round(d) + 'd';
      if (d < 730) return Math.round(d / 30) + 'mo';
      return (d / 365).toFixed(1) + 'y';
    },
    plural: (n, one, many) => `${nf0.format(n)} ${n === 1 ? one : (many || one + 's')}`,
  };

  // ---- localStorage that never throws ------------------------------------
  A.store = {
    get(k, d) {
      try {
        const v = window.localStorage.getItem('awsa.' + k);
        return v == null ? d : JSON.parse(v);
      } catch (e) { return d; }
    },
    set(k, v) {
      try { window.localStorage.setItem('awsa.' + k, JSON.stringify(v)); } catch (e) { /* private mode */ }
    },
  };

  // ---- tiny pub/sub ---------------------------------------------------------
  const subs = {};
  A.on = (ev, fn) => { (subs[ev] = subs[ev] || []).push(fn); };
  A.emit = (ev, arg) => { (subs[ev] || []).forEach((fn) => fn(arg)); };

  // ---- tooltip -----------------------------------------------------------------
  let tipEl = null;
  A.tip = {
    show(evt, content) {
      tipEl = tipEl || document.getElementById('tooltip');
      A.clear(tipEl);
      append(tipEl, [content]);
      tipEl.hidden = false;
      A.tip.move(evt);
    },
    move(evt) {
      if (!tipEl || tipEl.hidden) return;
      const pad = 14;
      const r = tipEl.getBoundingClientRect();
      let x = (evt.clientX != null ? evt.clientX : 0) + pad;
      let y = (evt.clientY != null ? evt.clientY : 0) + pad;
      if (x + r.width > window.innerWidth - 8) x = (evt.clientX || 0) - r.width - pad;
      if (y + r.height > window.innerHeight - 8) y = (evt.clientY || 0) - r.height - pad;
      tipEl.style.left = Math.max(8, x) + 'px';
      tipEl.style.top = Math.max(8, y) + 'px';
    },
    hide() { if (tipEl) tipEl.hidden = true; },
    /** attach hover + keyboard-focus tooltip to an element; build() returns the content */
    attach(el, build) {
      const focusEvt = () => { const b = el.getBoundingClientRect(); return { clientX: b.left + b.width / 2, clientY: b.top + b.height }; };
      el.addEventListener('pointerenter', (e) => A.tip.show(e, build()));
      el.addEventListener('pointermove', (e) => A.tip.move(e));
      el.addEventListener('pointerleave', A.tip.hide);
      el.addEventListener('focus', () => A.tip.show(focusEvt(), build()));
      el.addEventListener('blur', A.tip.hide);
    },
  };

  // ---- downloads (local Blob, no network) -----------------------------------------
  A.download = function download(filename, text, mime) {
    A.downloadBlob(filename, new Blob([text], { type: mime || 'text/plain' }));
  };
  /** The viewer's one link: a local blob: URL with a download name, built here because A.h refuses every <a>. */
  A.downloadBlob = function downloadBlob(filename, blob) {
    const url = String(URL.createObjectURL(blob));
    if (!/^blob:/.test(url)) refuse('a download that is not a local blob: URL');
    const a = document.createElement('a');
    a.download = String(filename);
    a.setAttribute('href', url);
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };
  /** Names and tags (also project/env, which come from tags) are untrusted: spreadsheet formula injection. Every field
      is quoted and a field that starts like a formula gets an apostrophe in front, so it stays text. A spreadsheet that
      splits on ';' or tabs (Excel in many locales) only sees the first column's quotes, though (the others follow a
      ','), so a cell can also start after a ';', tab or line break inside a value: such a formula start gets one too. */
  A.csv = function csv(rows) {
    const esc = (v) => {
      let s = v == null ? '' : String(v);
      if (/^[=+\-@\t\r]/.test(s) && !/^-?\d+(\.\d+)?$/.test(s)) s = "'" + s;
      s = s.replace(/([;\t\r\n][\s"]*)(?=[=+\-@])/g, "$1'");
      return '"' + s.replace(/"/g, '""') + '"';
    };
    return rows.map((r) => r.map(esc).join(',')).join('\n');
  };

  A.debounce = function debounce(fn, ms) {
    let t;
    return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
  };
})();
