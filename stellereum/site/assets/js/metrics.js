/* Stellereum — metrics.js
   Live network metrics. Nothing is invented: when an endpoint is unavailable
   the value falls back to an em dash and the status flips to reconnecting.
   Source: POST https://rpc.stellereum.org (CORS: access-control-allow-origin: *).
   Methods: stell_chainId, stell_blockNumber, stell_baseFee,
   stell_getValidators, stell_getStateRoot, stell_syncing, stell_latestBlocks.
   GET https://testnet.stellereum.org/api/stats and /health are intentionally
   not used: the server emits access-control-allow-origin twice («*, *») and the
   browser rejects that response. */
(function () {
  'use strict';

  var RPC = 'https://rpc.stellereum.org';

  var POLL_MS = 15000;     /* refresh cadence */
  var BOOTSTRAP_MS = 2500; /* second sample, enough to derive block time */
  var TIMEOUT_MS = 8000;   /* AbortController timeout */

  var reduce = window.matchMedia('(prefers-reduced-motion: reduce)');

  /* ------------------------------------------------------------- helpers - */
  function boxes(name) {
    return document.querySelectorAll('[data-metric="' + name + '"]');
  }

  function valueNodes(name) {
    var out = [];
    Array.prototype.forEach.call(boxes(name), function (box) {
      var node = box.querySelector('[data-value]') || box;
      if (node) out.push(node);
    });
    return out;
  }

  function valueNode(name) {
    return valueNodes(name)[0] || null;
  }

  function noteNodes(name) {
    var out = [];
    Array.prototype.forEach.call(boxes(name), function (box) {
      var note = box.querySelector('.metric-note');
      if (note) out.push(note);
    });
    return out;
  }

  function fail(name) {
    valueNodes(name).forEach(function (el) {
      el._seeded = true;
      el.textContent = '—';
      el.classList.add('is-empty');
      if (el.removeAttribute) el.removeAttribute('data-full');
    });
  }

  function setNumber(name, num, opts) {
    opts = opts || {};
    var dec = opts.decimals || 0;
    var suffix = opts.suffix || '';
    var prefix = opts.prefix || '';
    var format = opts.raw
      ? function (v) { return prefix + Math.round(v) + suffix; }
      : (dec
        ? function (v) { return prefix + v.toFixed(dec) + suffix; }
        : function (v) { return prefix + Math.round(v).toLocaleString('en-US') + suffix; });

    valueNodes(name).forEach(function (el) {
      var first = !el._seeded;
      el._seeded = true;
      el.classList.remove('is-empty');

      if (first && window.StellMotion && !reduce.matches && isFinite(num)) {
        window.StellMotion.count(el, num, { format: format, duration: 950 });
      } else {
        if (el._countRaf) { cancelAnimationFrame(el._countRaf); el._countRaf = null; }
        el.textContent = format(num);
      }
    });
  }

  function hexToNumber(hex) {
    if (typeof hex !== 'string') return null;
    var s = hex.trim();
    if (s.slice(0, 2).toLowerCase() === '0x') s = s.slice(2);
    if (!s || !/^[0-9a-fA-F]+$/.test(s)) return null;
    try {
      var big = BigInt('0x' + s);
      if (big > BigInt(Number.MAX_SAFE_INTEGER)) return null;
      return Number(big);
    } catch (e) {
      return null;
    }
  }

  function truncateHash(hex) {
    var s = String(hex);
    if (s.slice(0, 2).toLowerCase() === '0x') s = s.slice(2);
    s = s.toLowerCase();
    if (s.length <= 24) return s;
    return s.slice(0, 12) + '\u2026' + s.slice(-10);
  }

  function setStateRoot(hex) {
    var s = String(hex);
    if (s.slice(0, 2).toLowerCase() === '0x') s = s.slice(2);
    valueNodes('stateRoot').forEach(function (el) {
      el.setAttribute('data-full', s);
      el._seeded = true;
      el.classList.remove('is-empty');
      el.textContent = truncateHash(s);
    });
  }

  /* --------------------------------------------------------------- fetch - */
  function request(url, options) {
    var ctrl = typeof AbortController === 'function' ? new AbortController() : null;
    var timer = setTimeout(function () { if (ctrl) ctrl.abort(); }, TIMEOUT_MS);
    var opts = options || {};
    if (ctrl) opts.signal = ctrl.signal;

    return fetch(url, opts).then(function (res) {
      clearTimeout(timer);
      if (!res.ok) throw new Error('HTTP ' + res.status);
      return res.json();
    }, function (err) {
      clearTimeout(timer);
      throw err;
    });
  }

  function rpc(method, params) {
    return request(RPC, {
      method: 'POST',
      mode: 'cors',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: method,
        params: params || []
      })
    }).then(function (data) {
      if (data && data.error) throw new Error(data.error.message || 'rpc error');
      if (!data || typeof data.result === 'undefined' || data.result === null) {
        throw new Error('empty result');
      }
      return data.result;
    });
  }

  function silent(promise) {
    return promise.then(function (v) { return v; }, function () { return null; });
  }

  /* -------------------------------------------------------------- status - */
  var statusBoxes = document.querySelectorAll('[data-status]');
  var statusTexts = document.querySelectorAll('[data-status-text]');
  var online = null;

  function setStatus(isOnline) {
    if (online === isOnline) return;
    online = isOnline;

    Array.prototype.forEach.call(statusBoxes, function (box) {
      box.classList.toggle('is-offline', !isOnline);
    });

    Array.prototype.forEach.call(statusTexts, function (el) {
      el.textContent = isOnline
        ? 'Live · rpc.stellereum.org'
        : 'reconnecting · rpc.stellereum.org';
    });
  }

  /* ----------------------------------------------------------- block time */
  var sample = { start: null, height: null };

  function fetchLiveBlockTime() {
    fetch('https://explorer.stellereum.org/api/v2/stats')
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if (!d) return;
        var bt = Number(d.avg_block_time || d.block_time || 0);
        if (bt > 0 && bt < 10) {
          setNumber('blockTime', bt, { decimals: 2, suffix: ' s' });
        }
      })
      .catch(function () {});
  }

  function trackBlockTime(height, now) {
    if (sample.start === null) {
      sample.start = now;
      sample.height = height;
      fetchLiveBlockTime();
      return;
    }
    var deltaBlocks = height - sample.height;
    var deltaSec = (now - sample.start) / 1000;

    if (deltaBlocks >= 1 && deltaSec >= 1.0) {
      var bt = deltaSec / deltaBlocks;
      if (bt >= 0.1 && bt <= 5.0) {
        setNumber('blockTime', bt, { decimals: 2, suffix: ' s' });
      }
      sample.start = now;
      sample.height = height;
    } else if (deltaSec > 60) {
      sample.start = now;
      sample.height = height;
    }
  }

  /* ---------------------------------------------------------------- poll - */
  var pollCount = 0;

  function poll() {
    pollCount++;
    var jobs = {
      chainId: silent(rpc('stell_chainId')),
      height: silent(rpc('stell_blockNumber')),
      baseFee: silent(rpc('stell_baseFee')),
      validators: silent(rpc('stell_getValidators')),
      stateRoot: silent(rpc('stell_getStateRoot')),
      syncing: silent(rpc('stell_syncing')),
      latestBlocks: silent(rpc('stell_latestBlocks', [10]))
    };

    var keys = Object.keys(jobs);
    Promise.all(keys.map(function (k) {
      return jobs[k].then(function (v) { return { key: k, value: v }; });
    })).then(function (pairs) {
      var map = {};
      pairs.forEach(function (p) { map[p.key] = p.value; });
      try { apply(map); } catch (e) { setStatus(false); }
      schedule();
    }, function () {
      setStatus(false);
      schedule();
    });
  }

  function apply(map) {
    var now = Date.now();

    /* chain id ---------------------------------------------------------- */
    /* Chain id is a protocol constant: keep 5757 when the RPC is down. */
    var chainId = typeof map.chainId === 'number' ? map.chainId : hexToNumber(map.chainId);
    if (chainId !== null) {
      valueNodes('chainId').forEach(function (el) {
        el.textContent = String(chainId);
        el._seeded = true;
        el.classList.remove('is-empty');
      });
    }

    /* block height ------------------------------------------------------ */
    var height = hexToNumber(map.height);
    if (height !== null && isFinite(height)) {
      setNumber('height', height);
      trackBlockTime(height, now);
    } else {
      fail('height');
      fail('blockTime');
    }

    /* base fee ---------------------------------------------------------- */
    if (map.baseFee && map.baseFee.base_fee !== undefined) {
      var fee = Number(map.baseFee.base_fee);
      if (isFinite(fee)) setNumber('baseFee', fee);
      else fail('baseFee');
    } else {
      fail('baseFee');
    }

    /* validators -------------------------------------------------------- */
    if (map.validators && Array.isArray(map.validators.validators)) {
      setNumber('validators', map.validators.validators.length);
      var q = Number(map.validators.quorum);
      var t = Number(map.validators.total_power);
      if (isFinite(q) && isFinite(t) && t > 0) {
        var note = 'quorum ' + (q / t * 100).toFixed(2) + '% of ' + t.toLocaleString('en-US');
        noteNodes('validators').forEach(function (el) { el.textContent = note; });
      }
    } else {
      fail('validators');
    }

    /* state root -------------------------------------------------------- */
    if (typeof map.stateRoot === 'string' && map.stateRoot) {
      setStateRoot(map.stateRoot);
    } else {
      fail('stateRoot');
    }

    /* node health (true = syncing / behind) ------------------------------ */
    var healthy =
      map.chainId !== null &&
      map.height !== null &&
      map.baseFee !== null &&
      map.validators !== null &&
      map.stateRoot !== null &&
      map.syncing !== true;

    setStatus(healthy);
  }

  function schedule() {
    var delay = pollCount <= 1 ? BOOTSTRAP_MS : POLL_MS;
    window.setTimeout(poll, delay);
  }

  /* --------------------------------------------------------------- boot - */
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', poll);
  } else {
    poll();
  }

  window.StellMetrics = { refresh: poll };
})();
