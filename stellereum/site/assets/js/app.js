/* Stellereum — app.js
   Бургер-меню, smooth-scroll, active-nav, табы, копирование, мелочи. */
(function () {
  'use strict';

  var doc = document;
  var win = window;
  var reduceMotion = win.matchMedia('(prefers-reduced-motion: reduce)');
  var desktopNav = win.matchMedia('(min-width: 992px)');

  /* ---------------------------------------------------------------- шапка */
  var header = doc.querySelector('.site-header');

  function onScrollHeader() {
    if (!header) return;
    header.classList.toggle('is-scrolled', win.scrollY > 8);
  }
  onScrollHeader();
  win.addEventListener('scroll', onScrollHeader, { passive: true });

  /* ------------------------------------------------------------ бургер ---- */
  var toggle = doc.querySelector('.nav-toggle');
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
      if (first) first.focus();
    } else if (lastFocused && typeof lastFocused.focus === 'function') {
      lastFocused.focus();
      lastFocused = null;
    }
  }

  if (toggle) {
    toggle.addEventListener('click', function () { setNav(!navOpen); });
  }
  if (backdrop) {
    backdrop.addEventListener('click', function () { setNav(false); });
  }
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

  /* --------------------------------------------------- smooth scroll ------ */
  function headerOffset() {
    return header ? header.offsetHeight : 64;
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
      window.setTimeout(function () { target.focus({ preventScroll: true }); }, behavior === 'auto' ? 0 : 500);
    }
  });

  /* ------------------------------------------------------- active nav ----- */
  var navLinks = Array.prototype.slice.call(doc.querySelectorAll('.nav-link[href^="#"]'));
  var watched = ['network', 'build', 'ecosystem', 'roadmap']
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

  /* ----------------------------------------------------------- табы ------- */
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

  /* -------------------------------------------------------- копирование --- */
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

  /* ------------------------------------------------------------- мелочи --- */
  Array.prototype.forEach.call(doc.querySelectorAll('[data-year]'), function (el) {
    el.textContent = String(new Date().getFullYear());
  });

  win.StellereumApp = {
    copyText: copyText,
    setNav: setNav
  };
})();
