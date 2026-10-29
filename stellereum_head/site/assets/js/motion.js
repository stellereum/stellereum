/* Stellereum — motion.js
   reveal-on-scroll, параллакс орб, tilt карточек, счётчики.
   Всё отключается при prefers-reduced-motion. */
(function () {
  'use strict';

  var doc = document;
  var win = window;
  var reduce = win.matchMedia('(prefers-reduced-motion: reduce)');
  var precise = win.matchMedia('(hover: hover) and (pointer: fine)');

  /* --------------------------------------------------- reveal-on-scroll --- */
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
    }, { threshold: 0.1, rootMargin: '0px 0px -6% 0px' });

    Array.prototype.forEach.call(els, function (el) { io.observe(el); });

    // страховка: если что-то не всплыло за 4 c — показать
    win.setTimeout(function () {
      Array.prototype.forEach.call(doc.querySelectorAll('[data-reveal]:not(.is-visible)'), function (el) {
        var r = el.getBoundingClientRect();
        if (r.top < win.innerHeight && r.bottom > 0) el.classList.add('is-visible');
      });
    }, 4000);
  }

  /* ------------------------------------------------------------- счётчик -- */
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

  /* --------------------------------------------------- параллакс орб ------ */
  function initParallax() {
    var el = doc.querySelector('[data-parallax]');
    if (!el || reduce.matches) return;

    var ticking = false;
    function update() {
      ticking = false;
      var y = win.scrollY || win.pageYOffset || 0;
      if (y > 1400) return;
      var offset = Math.max(-46, Math.min(46, -y * 0.055));
      el.style.setProperty('--par', offset.toFixed(2) + 'px');
    }
    function onScroll() {
      if (!ticking) { ticking = true; requestAnimationFrame(update); }
    }
    update();
    win.addEventListener('scroll', onScroll, { passive: true });
    win.addEventListener('resize', onScroll, { passive: true });
  }

  /* ---------------------------------------------------------- tilt ------- */
  function initTilt() {
    var cards = doc.querySelectorAll('[data-tilt]');
    if (!cards.length || reduce.matches || !precise.matches) return;

    Array.prototype.forEach.call(cards, function (card) {
      card.addEventListener('pointermove', function (e) {
        if (e.pointerType === 'touch') return;
        var rect = card.getBoundingClientRect();
        var px = (e.clientX - rect.left) / rect.width - 0.5;
        var py = (e.clientY - rect.top) / rect.height - 0.5;
        var rx = (-py * 7).toFixed(2);
        var ry = (px * 9).toFixed(2);
        card.classList.add('is-tilting');
        card.style.transform =
          'perspective(900px) rotateX(' + rx + 'deg) rotateY(' + ry + 'deg) translateY(-5px)';
      });

      card.addEventListener('pointerleave', function () {
        card.classList.remove('is-tilting');
        card.style.transform = '';
      });
    });
  }

  /* ---------------------------------------------------- счётчики секций -- */
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
          duration: 1100,
          format: readFormat(el)
        });
      });
    }, { threshold: 0.4 });

    Array.prototype.forEach.call(nodes, function (el) { io.observe(el); });
  }

  /* ---------------------------------------------------------------- init -- */
  function init() {
    initReveal();
    initParallax();
    initTilt();
    initSectionCounters();
  }

  if (doc.readyState === 'loading') doc.addEventListener('DOMContentLoaded', init);
  else init();

  win.StellMotion = { count: count, showAll: showAll, reduce: reduce };
})();
