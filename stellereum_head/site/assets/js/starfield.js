/* Stellereum — starfield.js
   Canvas в герое: звёздное поле + орбитальные кольца + светящееся ядро. */
(function () {
  'use strict';

  var canvas = document.getElementById('starfield');
  if (!canvas) return;
  var ctx = canvas.getContext && canvas.getContext('2d');
  if (!ctx) return;

  var reduce = window.matchMedia('(prefers-reduced-motion: reduce)');
  var dpr = 1;
  var w = 0;
  var h = 0;
  var stars = [];
  var raf = null;
  var start = 0;
  var paused = false;

  var RINGS = [
    { rx: 0.94, ry: 0.34, rot: -0.42, speed: 0.055, lw: 1.1, a: 0.30, sat: 0.30, satSpeed: 0.9 },
    { rx: 0.80, ry: 0.52, rot: 0.55, speed: -0.040, lw: 1.0, a: 0.24, sat: 0.26, satSpeed: -0.7 },
    { rx: 0.66, ry: 0.66, rot: 0.15, speed: 0.025, lw: 0.9, a: 0.16, sat: 0.20, satSpeed: 0.5 }
  ];

  function seed() {
    stars = [];
    var count = Math.round(Math.min(190, Math.max(70, (w * h) / 2400)));
    for (var i = 0; i < count; i++) {
      var a = Math.random() * Math.PI * 2;
      var r = Math.sqrt(Math.random());
      var hueRoll = Math.random();
      stars.push({
        x: Math.cos(a) * r,
        y: Math.sin(a) * r,
        r: Math.random() * 1.35 + 0.35,
        phase: Math.random() * Math.PI * 2,
        speed: 0.5 + Math.random() * 1.4,
        color: hueRoll < 0.14 ? 'rgba(160,215,255,' : (hueRoll < 0.24 ? 'rgba(186,164,255,' : 'rgba(234,240,251,')
      });
    }
  }

  function resize() {
    var rect = canvas.getBoundingClientRect();
    var cw = Math.round(rect.width);
    var ch = Math.round(rect.height);
    if (!cw || !ch) return false;
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    if (canvas.width !== Math.round(cw * dpr) || canvas.height !== Math.round(ch * dpr)) {
      canvas.width = Math.round(cw * dpr);
      canvas.height = Math.round(ch * dpr);
    }
    w = cw;
    h = ch;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    seed();
    return true;
  }

  function draw(t) {
    var cx = w / 2;
    var cy = h / 2;
    var R = Math.min(w, h) / 2;

    ctx.clearRect(0, 0, w, h);

    /* туманность */
    var nebula = ctx.createRadialGradient(cx, cy, R * 0.05, cx, cy, R);
    nebula.addColorStop(0, 'rgba(63,169,255,.26)');
    nebula.addColorStop(0.42, 'rgba(63,169,255,.09)');
    nebula.addColorStop(0.75, 'rgba(139,108,255,.07)');
    nebula.addColorStop(1, 'rgba(4,6,12,0)');
    ctx.fillStyle = nebula;
    ctx.beginPath();
    ctx.arc(cx, cy, R, 0, Math.PI * 2);
    ctx.fill();

    /* звёзды */
    for (var i = 0; i < stars.length; i++) {
      var s = stars[i];
      var tw = reduce.matches ? 0.75 : 0.42 + 0.58 * Math.abs(Math.sin(t * s.speed + s.phase));
      ctx.beginPath();
      ctx.fillStyle = s.color + (tw * 0.9).toFixed(3) + ')';
      ctx.arc(cx + s.x * R * 0.97, cy + s.y * R * 0.97, s.r, 0, Math.PI * 2);
      ctx.fill();
    }

    /* орбиты */
    for (var k = 0; k < RINGS.length; k++) {
      var ring = RINGS[k];
      var angle = ring.rot + (reduce.matches ? 0 : t * ring.speed);

      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(angle);

      ctx.beginPath();
      ctx.ellipse(0, 0, R * ring.rx, R * ring.ry, 0, 0, Math.PI * 2);
      ctx.lineWidth = ring.lw;
      ctx.strokeStyle = 'rgba(63,169,255,' + ring.a + ')';
      ctx.stroke();

      /* светящийся сегмент */
      var seg = (reduce.matches ? 1.2 : t * ring.satSpeed) + k * 2.1;
      ctx.beginPath();
      ctx.ellipse(0, 0, R * ring.rx, R * ring.ry, 0, seg, seg + 1.15);
      ctx.lineWidth = ring.lw + 1.1;
      ctx.lineCap = 'round';
      ctx.strokeStyle = 'rgba(170,220,255,' + (ring.a + 0.45) + ')';
      ctx.stroke();

      /* спутник */
      var sa = (reduce.matches ? 0.6 : t * ring.satSpeed * 0.8) + k * 1.7;
      var sx = Math.cos(sa) * R * ring.rx;
      var sy = Math.sin(sa) * R * ring.ry;
      ctx.beginPath();
      ctx.fillStyle = 'rgba(234,240,251,.95)';
      ctx.shadowColor = 'rgba(63,169,255,.95)';
      ctx.shadowBlur = 14;
      ctx.arc(sx, sy, 2.6, 0, Math.PI * 2);
      ctx.fill();
      ctx.shadowBlur = 0;

      ctx.restore();
    }

    /* ядро */
    var pulse = reduce.matches ? 1 : 0.92 + 0.08 * Math.sin(t * 1.15);
    var core = ctx.createRadialGradient(cx, cy, 0, cx, cy, R * 0.60 * pulse);
    core.addColorStop(0, 'rgba(226,245,255,.95)');
    core.addColorStop(0.07, 'rgba(120,200,255,.9)');
    core.addColorStop(0.24, 'rgba(63,169,255,.42)');
    core.addColorStop(0.6, 'rgba(63,169,255,.10)');
    core.addColorStop(1, 'rgba(63,169,255,0)');
    ctx.fillStyle = core;
    ctx.beginPath();
    ctx.arc(cx, cy, R * 0.60 * pulse, 0, Math.PI * 2);
    ctx.fill();

    /* мятная искра в центре */
    ctx.beginPath();
    ctx.fillStyle = 'rgba(94,240,200,' + (reduce.matches ? 0.85 : 0.55 + 0.35 * Math.sin(t * 1.7)) + ')';
    ctx.shadowColor = 'rgba(94,240,200,.9)';
    ctx.shadowBlur = 18;
    ctx.arc(cx, cy, 3.4, 0, Math.PI * 2);
    ctx.fill();
    ctx.shadowBlur = 0;
  }

  function loop(ts) {
    raf = requestAnimationFrame(loop);
    if (!start) start = ts;
    draw((ts - start) / 1000);
  }

  function startLoop() {
    if (reduce.matches || paused || raf) return;
    start = 0;
    raf = requestAnimationFrame(loop);
  }

  function stopLoop() {
    if (raf) { cancelAnimationFrame(raf); raf = null; }
  }

  function renderStatic() {
    stopLoop();
    if (resize()) draw(1.4);
  }

  /* --- события ----------------------------------------------------------- */
  function onResize() {
    if (reduce.matches) renderStatic();
    else if (resize()) draw((performance.now() - start) / 1000 || 0);
  }

  if ('ResizeObserver' in window) {
    var ro = new ResizeObserver(function () { onResize(); });
    ro.observe(canvas.parentElement || canvas);
  }
  window.addEventListener('resize', onResize, { passive: true });

  document.addEventListener('visibilitychange', function () {
    paused = document.hidden;
    if (paused) stopLoop();
    else startLoop();
  });

  if ('IntersectionObserver' in window) {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) startLoop();
        else stopLoop();
      });
    }, { threshold: 0.02 });
    io.observe(canvas);
  }

  if (reduce.addEventListener) {
    reduce.addEventListener('change', function () {
      if (reduce.matches) renderStatic();
      else startLoop();
    });
  }

  /* --- старт -------------------------------------------------------------- */
  function boot() {
    if (!resize()) {
      window.setTimeout(boot, 120);
      return;
    }
    if (reduce.matches) renderStatic();
    else startLoop();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
