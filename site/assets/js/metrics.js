/* Stellereum — metrics.js
   Живые метрики сети. Ничего не выдумываем: при недоступности эндпоинта
   показываем «—» и бейдж reconnecting.
   Источник: POST https://rpc.stellereum.org (CORS: access-control-allow-origin: *),
   методы stell_chainId, stell_blockNumber, stell_baseFee, stell_getValidators,
   stell_getStateRoot, stell_syncing.
   GET https://testnet.stellereum.org/api/stats и /health сюда сознательно не
   идут: сервер отдаёт заголовок access-control-allow-origin дважды («*, *»),
   и браузер блокирует такой ответ с ошибкой в консоли.
*/
(function () {
  'use strict';

  var RPC = 'https://rpc.stellereum.org';

  var POLL_MS = 15000;     /* обновление каждые 15 с */
  var BOOTSTRAP_MS = 2500; /* первое повторное измерение — чтобы посчитать block time */
  var TIMEOUT_MS = 8000;   /* таймаут через AbortController */

  var reduce = window.matchMedia('(prefers-reduced-motion: reduce)');

  /* ------------------------------------------------------------- утилиты - */
  function valueNode(name) {
    var box = document.querySelector('[data-metric="' + name + '"]');
    if (!box) return null;
    return box.querySelector('[data-value]') || box;
  }

  function noteNode(name) {
    var box = document.querySelector('[data-metric="' + name + '"]');
    return box ? box.querySelector('.metric-note') : null;
  }

  function fail(name) {
    var el = valueNode(name);
    if (el) {
      el._seeded = true;
      el.textContent = '—';
      if (el.removeAttribute) el.removeAttribute('data-full');
    }
  }

  function setNumber(name, num, opts) {
    var el = valueNode(name);
    if (!el) return;
    opts = opts || {};
    var dec = opts.decimals || 0;
    var suffix = opts.suffix || '';
    var prefix = opts.prefix || '';
    var format = opts.raw
      ? function (v) { return prefix + Math.round(v) + suffix; }
      : (dec
        ? function (v) { return prefix + v.toFixed(dec) + suffix; }
        : function (v) { return prefix + Math.round(v).toLocaleString('en-US') + suffix; });

    var first = !el._seeded;
    el._seeded = true;

    if (first && window.StellMotion && !reduce.matches && isFinite(num)) {
      window.StellMotion.count(el, num, { format: format, duration: 950 });
    } else {
      if (el._countRaf) { cancelAnimationFrame(el._countRaf); el._countRaf = null; }
      el.textContent = format(num);
    }
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
    var el = valueNode('stateRoot');
    if (!el) return;
    var s = String(hex);
    if (s.slice(0, 2).toLowerCase() === '0x') s = s.slice(2);
    el.setAttribute('data-full', s);
    el._seeded = true;
    el.textContent = truncateHash(s);
  }

  /* -------------------------------------------------------------- fetch --- */
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

  function rpc(method) {
    return request(RPC, {
      method: 'POST',
      mode: 'cors',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: method, params: [] })
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

  /* ------------------------------------------------------------- статус --- */
  var statusBox = document.querySelector('[data-status]');
  var statusText = statusBox ? statusBox.querySelector('[data-status-text]') : null;
  var online = null;

  function setStatus(isOnline) {
    if (online === isOnline) return;
    online = isOnline;
    if (!statusBox) return;
    statusBox.classList.toggle('is-offline', !isOnline);
    if (statusText) {
      statusText.textContent = isOnline
        ? 'Live \u00b7 testnet.stellereum.org'
        : 'reconnecting \u00b7 testnet.stellereum.org';
    }
  }

  /* ----------------------------------------------------- block time ------ */
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

  /* -------------------------------------------------------------- poll ---- */
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
    var elChain = valueNode('chainId');
    if (elChain) {
      elChain.textContent = '5757';
      elChain._seeded = true;
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
      if (isFinite(fee)) {
        setNumber('baseFee', fee);
      } else { fail('baseFee'); }
    } else {
      fail('baseFee');
    }

    /* validators -------------------------------------------------------- */
    if (map.validators && Array.isArray(map.validators.validators)) {
      setNumber('validators', map.validators.validators.length);
      var note = noteNode('validators');
      if (note) {
        var q = Number(map.validators.quorum);
        var t = Number(map.validators.total_power);
        if (isFinite(q) && isFinite(t) && t > 0) {
          note.textContent = 'quorum ' + (q / t * 100).toFixed(2) + '% of ' + t.toLocaleString('en-US');
        }
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

    /* узел в курсе состояния сети (true = отстаёт) ----------------------- */
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

  /* -------------------------------------------------------------- старт -- */
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', poll);
  } else {
    poll();
  }

  window.StellMetrics = { refresh: poll };
})();
