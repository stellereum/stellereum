/* Stellereum — motion.js
   Reveal-on-scroll, animated counters, scroll progress, magnetic buttons,
   custom cursor and a light hero parallax. Everything is optional and is
   disabled under prefers-reduced-motion. */
(function () {
  'use strict';

  var doc = document;
  var win = window;
  var reduce = win.matchMedia('(prefers-reduced-motion: reduce)');
  var precise = win.matchMedia('(hover: hover) and (pointer: fine)');

  /* ------------------------------------------------------ reveal-on-scroll */
  function showAll() {
    Array.prototype.forEach.call(doc.querySelectorAll('[data-reveal]'), function (el) {
      el.classList.add('is-visible');
    });
  }

  function initReveal() {
    var els = doc.querySelectorAll('[data-reveal]');
    if (!els.length) return;
    if (reduce.matches || !('IntersectionObserver' in win)) { showAll(); return; }

    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add('is-visible');
          io.unobserve(entry.target);
        }
      });
    }, { threshold: 0.05, rootMargin: '0px 0px -2% 0px' });

    Array.prototype.forEach.call(els, function (el) { io.observe(el); });

    win.setTimeout(function () {
      Array.prototype.forEach.call(doc.querySelectorAll('[data-reveal]:not(.is-visible)'), function (el) {
        var r = el.getBoundingClientRect();
        if (r.top < win.innerHeight && r.bottom > 0) el.classList.add('is-visible');
      });
    }, 4000);
  }

  /* ------------------------------------------------------------- counters */
  function formatInt(value) {
    return Math.round(value).toLocaleString('en-US');
  }

  function count(el, to, opts) {
    if (!el) return;
    opts = opts || {};
    var format = opts.format || formatInt;
    var duration = opts.duration || 900;

    if (el._countRaf) { cancelAnimationFrame(el._countRaf); el._countRaf = null; }

    if (reduce.matches || typeof to !== 'number' || !isFinite(to)) {
      el.textContent = format(to);
      return;
    }

    var from = typeof opts.from === 'number' ? opts.from : 0;
    var start = null;

    function frame(ts) {
      if (start === null) start = ts;
      var p = Math.min(1, (ts - start) / duration);
      var eased = 1 - Math.pow(1 - p, 3);
      el.textContent = format(from + (to - from) * eased);
      if (p < 1) el._countRaf = requestAnimationFrame(frame);
      else { el._countRaf = null; el.textContent = format(to); }
    }

    el._countRaf = requestAnimationFrame(frame);
  }

  function makeFormat(prefix, suffix, decimals) {
    prefix = prefix || '';
    suffix = suffix || '';
    return function (v) {
      var n = decimals
        ? v.toFixed(decimals)
        : Math.round(v).toLocaleString('en-US');
      if (prefix === '\u2212') return n.replace('-', '\u2212') + suffix;
      return prefix + n + suffix;
    };
  }

  function initSectionCounters() {
    var nodes = doc.querySelectorAll('[data-count-to]');
    if (!nodes.length) return;

    function readFormat(el) {
      return makeFormat(
        el.getAttribute('data-count-prefix'),
        el.getAttribute('data-count-suffix'),
        parseInt(el.getAttribute('data-count-decimals') || '0', 10)
      );
    }

    if (reduce.matches || !('IntersectionObserver' in win)) {
      Array.prototype.forEach.call(nodes, function (el) {
        count(el, parseFloat(el.getAttribute('data-count-to')), { format: readFormat(el) });
      });
      return;
    }

    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (!entry.isIntersecting) return;
        var el = entry.target;
        io.unobserve(el);
        if (el._counted) return;
        el._counted = true;
        count(el, parseFloat(el.getAttribute('data-count-to')), {
          duration: 1150,
          format: readFormat(el)
        });
      });
    }, { threshold: 0.4 });

    Array.prototype.forEach.call(nodes, function (el) { io.observe(el); });
  }

  /* -------------------------------------------------------- scroll progress */
  function initProgress() {
    var bar = doc.querySelector('[data-scroll-progress]');
    if (!bar) return;
    var ticking = false;

    function update() {
      ticking = false;
      var max = doc.documentElement.scrollHeight - win.innerHeight;
      var y = win.scrollY || win.pageYOffset || 0;
      var p = max > 0 ? Math.min(1, Math.max(0, y / max)) : 0;
      bar.style.width = (p * 100).toFixed(2) + '%';
    }

    function onScroll() {
      if (!ticking) { ticking = true; requestAnimationFrame(update); }
    }

    update();
    win.addEventListener('scroll', onScroll, { passive: true });
    win.addEventListener('resize', onScroll, { passive: true });
  }

  /* ---------------------------------------------------------- hero parallax */
  function initParallax() {
    var mark = doc.querySelector('.hero-object');
    if (!mark || reduce.matches) return;
    var ticking = false;

    function update() {
      ticking = false;
      var y = win.scrollY || win.pageYOffset || 0;
      if (y > win.innerHeight * 1.4) return;
      mark.style.translate = '0 ' + (-y * 0.06).toFixed(1) + 'px';
    }

    function onScroll() {
      if (!ticking) { ticking = true; requestAnimationFrame(update); }
    }

    update();
    win.addEventListener('scroll', onScroll, { passive: true });
  }

  /* ------------------------------------------------- kinetic type shear */
  function initKinetic() {
    var row = doc.querySelector('[data-kinetic]');
    if (!row || reduce.matches) return;
    var ticking = false;

    function update() {
      ticking = false;
      var r = row.getBoundingClientRect();
      var vh = win.innerHeight;
      if (r.bottom < -120 || r.top > vh + 120) return;

      var p = (vh * 0.5 - (r.top + r.height * 0.5)) / (vh * 0.5 + r.height * 0.5);
      p = Math.max(-1, Math.min(1, p));
      row.style.setProperty('--kx', (p * 90).toFixed(1) + 'px');
      row.style.setProperty('--ks', (p * -6).toFixed(2) + 'deg');
    }

    function onScroll() {
      if (!ticking) { ticking = true; requestAnimationFrame(update); }
    }

    update();
    win.addEventListener('scroll', onScroll, { passive: true });
    win.addEventListener('resize', onScroll, { passive: true });
  }

  /* ---------------------------------------------------------- magnetic */
  function initMagnetic() {
    if (reduce.matches || !precise.matches) return;
    var els = doc.querySelectorAll('.btn');
    if (!els.length) return;

    Array.prototype.forEach.call(els, function (el) {
      el.addEventListener('pointermove', function (e) {
        if (e.pointerType === 'touch') return;
        var r = el.getBoundingClientRect();
        var x = ((e.clientX - r.left) / r.width - 0.5) * 6;
        var y = ((e.clientY - r.top) / r.height - 0.5) * 6;
        el.style.translate = x.toFixed(1) + 'px ' + y.toFixed(1) + 'px';
      });

      el.addEventListener('pointerleave', function () {
        el.style.translate = '';
      });
    });
  }

  /* ------------------------------------------------------------ cursor */
  function initCursor() {
    var cursor = doc.getElementById('custom-cursor');
    if (!cursor || reduce.matches || !precise.matches) return;

    doc.documentElement.classList.add('has-cursor');

    var px = win.innerWidth / 2;
    var py = win.innerHeight / 2;
    var x = px;
    var y = py;
    var raf = null;

    function loop() {
      x += (px - x) * 0.2;
      y += (py - y) * 0.2;
      cursor.style.left = x.toFixed(1) + 'px';
      cursor.style.top = y.toFixed(1) + 'px';
      if (Math.abs(px - x) > 0.2 || Math.abs(py - y) > 0.2) {
        raf = requestAnimationFrame(loop);
      } else {
        raf = null;
      }
    }

    doc.addEventListener('pointermove', function (e) {
      if (e.pointerType === 'touch') return;
      px = e.clientX;
      py = e.clientY;
      if (!raf) raf = requestAnimationFrame(loop);
    }, { passive: true });

    doc.addEventListener('pointerover', function (e) {
      var target = e.target.closest ? e.target.closest('a, button, .invert-card, .hero-object-tag') : null;
      cursor.classList.toggle('is-expanded', !!target);
    });

    doc.addEventListener('visibilitychange', function () {
      if (doc.hidden) {
        if (raf) { cancelAnimationFrame(raf); raf = null; }
      }
    });
  }

  /* --------------------------------------------------------------- init */
  function init() {
    initReveal();
    initSectionCounters();
    initProgress();
    initParallax();
    initKinetic();
    initMagnetic();
    initCursor();
  }

  if (doc.readyState === 'loading') doc.addEventListener('DOMContentLoaded', init);
  else init();

  win.StellMotion = { count: count, showAll: showAll, reduce: reduce };
})();
