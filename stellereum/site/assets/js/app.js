/* Stellereum — app.js
   Swiss nav drawer, smooth anchor travel, active section, tabs, copy, year.
   No dependencies; every enhancement is additive. */
(function () {
  'use strict';

  var doc = document;
  var win = window;
  var reduceMotion = win.matchMedia('(prefers-reduced-motion: reduce)');
  var desktopNav = win.matchMedia('(min-width: 900px)');

  /* --------------------------------------------------------------- header */
  var header = doc.querySelector('.site-header');

  function onScrollHeader() {
    if (!header) return;
    header.classList.toggle('is-scrolled', (win.scrollY || 0) > 8);
  }
  onScrollHeader();
  win.addEventListener('scroll', onScrollHeader, { passive: true });

  /* ------------------------------------------------------- palette invert */
  var invertBtns = doc.querySelectorAll('[data-invert-toggle]');
  var themeMeta = doc.querySelector('meta[name="theme-color"]');

  function applyInvert(on, persist) {
    doc.documentElement.classList.toggle('is-inverted', on);
    doc.body.classList.toggle('is-inverted', on);

    Array.prototype.forEach.call(invertBtns, function (btn) {
      btn.setAttribute('aria-pressed', on ? 'true' : 'false');
      btn.setAttribute('aria-label', on ? 'Switch to dark palette' : 'Switch to light palette');
    });

    if (themeMeta) themeMeta.setAttribute('content', on ? '#eef2ff' : '#060811');

    if (persist) {
      try { win.localStorage.setItem('stell-invert', on ? '1' : '0'); } catch (e) {}
    }
  }

  function isInverted() {
    return doc.body.classList.contains('is-inverted');
  }

  applyInvert(doc.documentElement.classList.contains('is-inverted'), false);

  Array.prototype.forEach.call(invertBtns, function (btn) {
    btn.addEventListener('click', function () { applyInvert(!isInverted(), true); });
  });

  win.addEventListener('storage', function (e) {
    if (e.key === 'stell-invert') applyInvert(e.newValue === '1', false);
  });

  /* --------------------------------------------------------- nav drawer */
  var toggle = doc.querySelector('.nav-toggle');
  var close = doc.querySelector('.nav-close');
  var panel = doc.getElementById('nav-panel');
  var backdrop = doc.querySelector('.nav-backdrop');
  var navOpen = false;
  var lastFocused = null;

  function setNav(open) {
    if (!toggle || !panel) return;
    if (open === navOpen) return;
    navOpen = open;

    toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    toggle.setAttribute('aria-label', open ? 'Close menu' : 'Open menu');
    panel.classList.toggle('is-open', open);
    if (backdrop) backdrop.classList.toggle('is-open', open);
    doc.body.classList.toggle('nav-is-open', open);

    if (open) {
      lastFocused = doc.activeElement;
      var first = panel.querySelector('a[href], button:not([disabled])');
      if (first) win.setTimeout(function () { first.focus(); }, 20);
    } else if (lastFocused && typeof lastFocused.focus === 'function') {
      lastFocused.focus();
      lastFocused = null;
    }
  }

  if (toggle) toggle.addEventListener('click', function () { setNav(!navOpen); });
  if (close) close.addEventListener('click', function () { setNav(false); });
  if (backdrop) backdrop.addEventListener('click', function () { setNav(false); });

  if (panel) {
    panel.addEventListener('click', function (e) {
      var link = e.target.closest ? e.target.closest('a[href]') : null;
      if (link && !desktopNav.matches) setNav(false);
    });
  }

  doc.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && navOpen) setNav(false);
  });

  if (desktopNav.addEventListener) {
    desktopNav.addEventListener('change', function (e) { if (e.matches) setNav(false); });
  }

  /* ------------------------------------------------------- smooth travel */
  function headerOffset() {
    return header ? header.offsetHeight : 68;
  }

  doc.addEventListener('click', function (e) {
    var link = e.target.closest ? e.target.closest('a[href^="#"]') : null;
    if (!link) return;
    var hash = link.getAttribute('href');
    if (!hash || hash === '#' || hash.length < 2) return;

    var target = null;
    try { target = doc.querySelector(hash); } catch (err) { return; }
    if (!target) return;

    e.preventDefault();
    setNav(false);

    var top = target.getBoundingClientRect().top + win.scrollY - headerOffset() - 10;
    var behavior = reduceMotion.matches ? 'auto' : 'smooth';
    if (win.scrollTo) win.scrollTo({ top: Math.max(top, 0), behavior: behavior });
    else win.scrollTo(0, Math.max(top, 0));

    if (history.replaceState) history.replaceState(null, '', hash);
    if (target.focus) {
      target.setAttribute('tabindex', '-1');
      win.setTimeout(function () { target.focus({ preventScroll: true }); }, behavior === 'auto' ? 0 : 520);
    }
  });

  /* ---------------------------------------------------------- active nav */
  var navLinks = Array.prototype.slice.call(doc.querySelectorAll('.nav-link[href^="#"]'));
  var watched = ['network', 'features', 'performance', 'build', 'ecosystem', 'roadmap', 'transmit']
    .map(function (id) { return doc.getElementById(id); })
    .filter(Boolean);

  function setActiveNav(id) {
    navLinks.forEach(function (link) {
      var match = link.getAttribute('href') === '#' + id;
      if (match) link.setAttribute('aria-current', 'true');
      else link.removeAttribute('aria-current');
    });
  }

  if ('IntersectionObserver' in win && watched.length) {
    var visible = {};
    var navObserver = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        visible[entry.target.id] = entry.isIntersecting ? entry.intersectionRatio : 0;
      });
      var best = null;
      var bestRatio = 0;
      Object.keys(visible).forEach(function (id) {
        if (visible[id] > bestRatio) { bestRatio = visible[id]; best = id; }
      });
      if (best) setActiveNav(best);
    }, { rootMargin: '-45% 0px -45% 0px', threshold: [0, 0.25, 0.5, 1] });

    watched.forEach(function (section) { navObserver.observe(section); });
  }

  /* --------------------------------------------------------------- tabs */
  Array.prototype.forEach.call(doc.querySelectorAll('[role="tablist"]'), function (list) {
    var tabs = Array.prototype.slice.call(list.querySelectorAll('[role="tab"]'));
    if (!tabs.length) return;

    function select(tab) {
      tabs.forEach(function (t) {
        var on = t === tab;
        t.setAttribute('aria-selected', on ? 'true' : 'false');
        t.setAttribute('tabindex', on ? '0' : '-1');
        var id = t.getAttribute('aria-controls');
        var pane = id ? doc.getElementById(id) : null;
        if (pane) pane.hidden = !on;
      });
    }

    tabs.forEach(function (tab, index) {
      tab.addEventListener('click', function () { select(tab); });
      tab.addEventListener('keydown', function (e) {
        var next = null;
        if (e.key === 'ArrowRight' || e.key === 'ArrowDown') next = tabs[(index + 1) % tabs.length];
        if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') next = tabs[(index - 1 + tabs.length) % tabs.length];
        if (e.key === 'Home') next = tabs[0];
        if (e.key === 'End') next = tabs[tabs.length - 1];
        if (next) { e.preventDefault(); select(next); next.focus(); }
      });
    });
  });

  /* -------------------------------------------------------------- copy */
  function legacyCopy(text) {
    return new Promise(function (resolve, reject) {
      try {
        var ta = doc.createElement('textarea');
        ta.value = text;
        ta.setAttribute('readonly', '');
        ta.style.position = 'fixed';
        ta.style.top = '-1000px';
        ta.style.opacity = '0';
        doc.body.appendChild(ta);
        ta.select();
        ta.setSelectionRange(0, text.length);
        var ok = false;
        try { ok = doc.execCommand('copy'); } catch (err) { ok = false; }
        doc.body.removeChild(ta);
        if (ok) resolve();
        else reject(new Error('copy command rejected'));
      } catch (err) { reject(err); }
    });
  }

  function copyText(text) {
    if (navigator.clipboard && win.isSecureContext) {
      return navigator.clipboard.writeText(text).catch(function () { return legacyCopy(text); });
    }
    return legacyCopy(text);
  }

  function flashCopied(btn) {
    var label = btn.querySelector('[data-copy-label]');
    var original = btn.getAttribute('data-original-label') ||
      (label ? label.textContent : btn.textContent);
    if (!btn.getAttribute('data-original-label')) btn.setAttribute('data-original-label', original);
    btn.classList.add('is-copied');
    if (label) label.textContent = 'Copied';
    else btn.textContent = 'Copied';
    win.clearTimeout(btn._copyTimer);
    btn._copyTimer = win.setTimeout(function () {
      btn.classList.remove('is-copied');
      var lbl = btn.querySelector('[data-copy-label]');
      if (lbl) lbl.textContent = btn.getAttribute('data-original-label');
      else btn.textContent = btn.getAttribute('data-original-label');
    }, 2000);
  }

  doc.addEventListener('click', function (e) {
    var btn = e.target.closest ? e.target.closest('[data-copy], [data-copy-from], [data-copy-active]') : null;
    if (!btn) return;

    var text = '';
    if (btn.hasAttribute('data-copy')) {
      text = btn.getAttribute('data-copy');
    } else if (btn.hasAttribute('data-copy-active')) {
      var scope = btn.closest('.code-panel') || doc;
      var active = scope.querySelector('[role="tab"][aria-selected="true"]');
      var pane = active ? doc.getElementById(active.getAttribute('aria-controls')) : null;
      if (pane) text = pane.innerText || pane.textContent;
    } else {
      var src = doc.querySelector(btn.getAttribute('data-copy-from'));
      if (src) text = src.getAttribute('data-full') || src.textContent;
    }
    if (!text) return;

    copyText(text.trim()).then(function () { flashCopied(btn); });
  });

  /* ------------------------------------------------------------ details */
  Array.prototype.forEach.call(doc.querySelectorAll('[data-year]'), function (el) {
    el.textContent = String(new Date().getFullYear());
  });

  /* If motion.js fails to load, never leave reveal content hidden. */
  win.setTimeout(function () {
    Array.prototype.forEach.call(doc.querySelectorAll('[data-reveal]:not(.is-visible)'), function (el) {
      var r = el.getBoundingClientRect();
      if (r.top < win.innerHeight && r.bottom > 0) el.classList.add('is-visible');
    });
  }, 3200);

  win.StellereumApp = { copyText: copyText, setNav: setNav, applyInvert: applyInvert };
})();
