// Security behaviour of viewer/js/util.js, run by tests/test_security_audit.py: the CSV export and the element factories'
// navigation guard. Loads util.js into a Node VM with a minimal fake DOM and prints
// {"failures": [...], "csv": "<exported text>"} on stdout.
'use strict';
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const failures = [];
const check = (cond, msg) => { if (!cond) failures.push(msg); };

class FakeNode {
  constructor(tag, ns) { this.tagName = tag; this.ns = ns || null; this.attrs = {}; this.children = []; this.dataset = {}; this.listeners = {}; this.style = { setProperty() {} }; }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  appendChild(c) { this.children.push(c); return c; }
  addEventListener(t, f) { this.listeners[t] = f; }
  set className(v) { this.attrs.class = v; }
  click() { this.clicked = true; }
  remove() { this.removed = true; }
}
const created = [];
const document = {
  createElement: (t) => { const n = new FakeNode(t); created.push(n); return n; },
  createElementNS: (ns, t) => { const n = new FakeNode(t, ns); created.push(n); return n; },
  createTextNode: (t) => ({ text: t }),
  body: new FakeNode('body'),
};
const window = { localStorage: { getItem: () => null, setItem() {} }, innerWidth: 1200, innerHeight: 800 };
const context = vm.createContext({
  window, document, Node: FakeNode, console, setTimeout: () => 0,
  URL: { createObjectURL: () => 'blob:null/0b5e7c1a', revokeObjectURL() {} },
  Blob: class { constructor(parts, opts) { this.parts = parts; this.type = opts && opts.type; } },
});
vm.runInContext(fs.readFileSync(path.join(__dirname, '..', '..', 'viewer', 'js', 'util.js'), 'utf8'), context, { filename: 'util.js' });
const A = window.AWSA;

function refused(label, fn) {
  let err = null;
  try { fn(); } catch (e) { err = e; }
  check(err && /refusing/.test(String(err.message)), `${label}: should be refused, got ${err ? err.message : 'no error'}`);
}
function allowed(label, fn) {
  try { fn(); } catch (e) { failures.push(`${label}: should be allowed, got ${e.message}`); }
}

// ---- CSV: every field quoted, formulas neutralised (VIEWER-2) ----------------------------------------------------------
const csv = A.csv([
  ['Name', 'Type', 'Cost'],
  ["x;=cmd|' /C calc'!A0;", 'NAT gateway', '-5'],
  ['y;=WEBSERVICE(CHAR(104)&CHAR(116)&A2)', 'EC2', '12.5'],
  ['web;=HYPERLINK("http://e")', 'x', ''],
  ['t\t=1+1', '=1+1', '+SUM(A1)'],
  ['@SUM(1)', '-cmd', '\r=1'],
  ['a\n=1+1', 'b,c', null],
  // later columns: in a ';' or tab spreadsheet their quotes follow a ',' and do not count, so the value itself is split
  ['web', 'Project=x;=1+1;', 'k=v\n=HYPERLINK("http://e")'],
  ['web', 'a; =1+1', 'b;"=1+1"'],
  ['web', 'env\t@SUM(1)', 'x;-2;+3'],
]);       // parsed with ',', ';' and tab as the separator by the Python side
check(csv.split('\n')[0] === '"Name","Type","Cost"', `header must be quoted: ${csv.split('\n')[0]}`);

// ---- element factories refuse whatever can navigate or load a URL (VIEWER-1, defence in depth) --------------------------
refused('a with a web href', () => A.h('a', { href: 'https://evil.example/?d=1' }).click());
refused('a with a blob href but no download name', () => A.h('a', { href: 'blob:null/1' }));
refused('a with an uppercase HREF key', () => A.h('a', { HREF: 'https://evil.example/', download: 'x' }));
refused('A (uppercase tag)', () => A.h('A', { href: 'https://evil.example/' }));
for (const tag of ['meta', 'META', 'base', 'link', 'script', 'form', 'iframe', 'frame', 'object', 'embed', 'area', 'portal']) {
  refused(`<${tag}>`, () => A.h(tag, {}));
}
refused('meta refresh', () => A.h('meta', { 'http-equiv': 'refresh', content: '0;url=https://evil.example/' }));
refused('string event handler', () => A.h('div', { onclick: 'alert(1)' }));
refused('string event handler, mixed case', () => A.h('div', { onClick: 'alert(1)' }));
refused('img src', () => A.h('img', { src: 'https://evil.example/p.png' }));
refused('button formaction', () => A.h('button', { formaction: 'https://evil.example/' }));
refused('href on a div', () => A.h('div', { href: 'https://evil.example/' }));
refused('ping', () => A.h('span', { ping: 'https://evil.example/' }));
refused('svg <a>', () => A.svg('a', { href: '#x' }));
refused('svg <image>', () => A.svg('image', { href: '#x' }));
refused('svg <set> (can rewrite an href)', () => A.svg('set', { attributeName: 'href', to: 'https://evil.example/' }));
refused('svg <foreignObject>', () => A.svg('foreignObject', {}));
refused('svg use with a web href', () => A.svg('use', { href: 'https://evil.example/s.svg#x' }));
refused('svg xlink:href to the web', () => A.svg('use', { 'xlink:href': '//evil.example/s.svg#x' }));
allowed('svg use with a #reference', () => A.svg('use', { href: '#arr' }));
allowed('svg path with a marker', () => A.svg('path', { d: 'M0,0 L1,1', 'marker-end': 'url(#arr)', class: 'edge' }));
allowed('ordinary elements', () => A.h('div', { class: 'x', dataset: { k: 1 }, style: { left: '1px' }, 'aria-label': 'y', tabindex: '0' }, 'text'));
allowed('details open (not an event handler)', () => A.h('details', { open: true }, A.h('summary', null, 'x')));
allowed('function event handler', () => A.h('button', { type: 'button', onClick() {} }, 'ok'));
allowed('file input', () => A.h('input', { type: 'file', accept: '.json', hidden: true }));
allowed('the local download link', () => A.downloadBlob('aws-inventory.csv', new context.Blob(['x'], { type: 'text/csv' })));
const link = created.find((n) => n.tagName === 'a');
check(link && link.attrs.href === 'blob:null/0b5e7c1a' && link.download === 'aws-inventory.csv' && link.clicked && link.removed,
  'downloadBlob must build, click and remove a blob: link with a download name');

process.stdout.write(JSON.stringify({ failures, csv }));
