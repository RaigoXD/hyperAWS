// Loads the viewer's pure modules (util, data, city-catalog, city-model) into a Node VM with a minimal window stub.
'use strict';
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const JS = path.join(__dirname, '..', '..', 'viewer', 'js');

function load(analysis) {
  const store = new Map();
  const window = {
    localStorage: { getItem: (k) => (store.has(k) ? store.get(k) : null), setItem: (k, v) => store.set(k, String(v)) },
    innerWidth: 1200, innerHeight: 800,
  };
  const context = vm.createContext({ window, console, Math, Date, JSON, Map, Set, Array, Object, String, Number, Promise });
  for (const f of ['util.js', 'data.js', 'city-catalog.js', 'city-model.js']) {
    vm.runInContext(fs.readFileSync(path.join(JS, f), 'utf8'), context, { filename: f });
  }
  const A = window.AWSA;
  if (analysis) A.init(analysis);
  return A;
}
module.exports = { load };
