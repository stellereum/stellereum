'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, '../assets/js/metrics.js'), 'utf8');

function deferred() {
  let resolve;
  const promise = new Promise(r => { resolve = r; });
  return { promise, resolve };
}

function harness() {
  let now = 1000;
  let nextTimer = 1;
  const timers = new Map();
  const explorer = deferred();
  const requests = [];
  let height = '0x64';
  let nextHeightResponse = null;
  const classes = new Set(['is-empty']);
  const value = {
    textContent: '—',
    classList: {
      add: name => classes.add(name),
      remove: name => classes.delete(name)
    },
    removeAttribute() {}
  };
  const box = { querySelector: selector => selector === '[data-value]' ? value : null };
  const document = {
    readyState: 'complete',
    querySelectorAll: selector => selector === '[data-metric="blockTime"]' ? [box] : []
  };
  const setTimer = (fn, delay) => {
    const id = nextTimer++;
    timers.set(id, { fn, at: now + delay });
    return id;
  };
  const window = { matchMedia: () => ({ matches: true }), setTimeout: setTimer };
  const response = result => ({ ok: true, json: () => Promise.resolve({ result }) });
  const methods = [];
  const fetch = (url, options) => {
    requests.push(url);
    if (url.includes('explorer')) return explorer.promise;
    const method = JSON.parse(options.body).method;
    methods.push(method);
    if (method === 'stell_blockNumber') {
      if (nextHeightResponse) {
        const pending = nextHeightResponse;
        nextHeightResponse = null;
        return pending.promise;
      }
      if (height instanceof Error) return Promise.reject(height);
      return Promise.resolve(response(height));
    }
    const results = {
      stell_chainId: '0x167d',
      stell_baseFee: { base_fee: 1 },
      stell_getValidators: { validators: [], quorum: 0, total_power: 0 },
      stell_getStateRoot: '0x1234',
      stell_syncing: false,
      stell_latestBlocks: []
    };
    return Promise.resolve(response(results[method]));
  };
  const context = {
    window, document, fetch, Promise, BigInt, isFinite,
    Date: { now: () => now },
    setTimeout: setTimer,
    clearTimeout: id => timers.delete(id),
    cancelAnimationFrame() {}
  };
  vm.runInNewContext(source, context, { filename: 'metrics.js' });

  async function flush() {
    for (let i = 0; i < 30; i++) await Promise.resolve();
  }
  async function advance(ms) {
    const end = now + ms;
    while (true) {
      let earliest = null;
      for (const [id, timer] of timers) {
        if (timer.at <= end && (!earliest || timer.at < earliest.timer.at)) {
          earliest = { id, timer };
        }
      }
      if (!earliest) break;
      now = earliest.timer.at;
      timers.delete(earliest.id);
      earliest.timer.fn();
      await flush();
    }
    now = end;
    await flush();
  }
  return {
    value, classes, requests, methods, timers, explorer, response, flush, advance,
    setHeight: h => { height = h; },
    deferHeight: () => { nextHeightResponse = deferred(); return nextHeightResponse; },
    refresh: () => window.StellMetrics.refresh()
  };
}

test('height samples show an average rate, not an individual block time', async () => {
  const h = harness();
  await h.flush();
  assert.equal(h.value.textContent, '—');
  h.setHeight('0x66');
  await h.advance(2500);
  assert.equal(h.value.textContent, '1.25 s');
  assert.equal(h.classes.has('is-empty'), false);
});

test('stall hides old rate and recovery includes the stalled interval', async () => {
  const h = harness();
  await h.flush();
  h.setHeight('0x65');
  await h.advance(2500);
  assert.equal(h.value.textContent, '2.50 s');
  await h.advance(15000);
  assert.equal(h.value.textContent, '—');
  assert.equal(h.classes.has('is-empty'), true);
  await h.advance(60000);
  assert.equal(h.value.textContent, '—');
  h.setHeight('0x66');
  await h.advance(15000);
  assert.equal(h.value.textContent, '90.00 s');
});

test('RPC error clears the sample; recovery needs two fresh heights', async () => {
  const h = harness();
  await h.flush();
  h.setHeight('0x65');
  await h.advance(2500);
  assert.equal(h.value.textContent, '2.50 s');
  h.setHeight(new Error('RPC unavailable'));
  await h.advance(15000);
  assert.equal(h.value.textContent, '—');
  h.setHeight('0x66');
  await h.advance(15000);
  assert.equal(h.value.textContent, '—');
  h.setHeight('0x67');
  await h.advance(15000);
  assert.equal(h.value.textContent, '15.00 s');
});

test('height rollback resets the baseline', async () => {
  const h = harness();
  await h.flush();
  h.setHeight('0x65');
  await h.advance(2500);
  h.setHeight('0x60');
  await h.advance(15000);
  assert.equal(h.value.textContent, '—');
  h.setHeight('0x61');
  await h.advance(15000);
  assert.equal(h.value.textContent, '15.00 s');
});

test('no explorer fallback can overwrite the sampled value', async () => {
  const h = harness();
  await h.flush();
  h.setHeight('0x65');
  await h.advance(2500);
  assert.equal(h.value.textContent, '2.50 s');
  h.explorer.resolve({ json: () => Promise.resolve({ avg_block_time: 0.4 }) });
  await h.flush();
  assert.equal(h.value.textContent, '2.50 s');
  assert.equal(h.requests.some(url => url.includes('explorer')), false);
});

test('an older overlapping refresh cannot overwrite a newer sample', async () => {
  const h = harness();
  await h.flush();
  const pending = h.deferHeight();
  h.refresh();
  await h.flush();
  h.setHeight('0x66');
  await h.advance(2500);
  assert.equal(h.value.textContent, '1.25 s');
  pending.resolve(h.response('0x65'));
  await h.flush();
  assert.equal(h.value.textContent, '1.25 s');
  h.setHeight('0x67');
  await h.advance(15000);
  assert.equal(h.value.textContent, '15.00 s');
});

test('refresh drops unused latestBlocks RPC and avoids duplicate poll timers', async () => {
  const h = harness();
  await h.flush();
  assert.equal(h.methods.includes('stell_latestBlocks'), false);
  assert.equal(h.timers.size, 1);
  h.refresh();
  await h.flush();
  assert.equal(h.timers.size, 1);
});
