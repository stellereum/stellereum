/* Stellereum — dither.js
   The reference technique, ported: a parametric 3D torus knot (p=2, q=3) is
   rasterised into a reduced-resolution z-buffer, shaded, then thresholded with
   the Bayer 4x4 ordered-dither matrix and coloured through a 256-entry electric
   gradient LUT. The same pipeline feeds the dither ribbon, the interference
   strip and the four card canvases. One rAF loop, no per-frame allocation in
   the pixel hot path, IntersectionObserver culling, hidden-tab pause, and a
   single static frame under prefers-reduced-motion. */
(function () {
  'use strict';

  var doc = document;
  var win = window;
  var reduceQuery = win.matchMedia
    ? win.matchMedia('(prefers-reduced-motion: reduce)')
    : { matches: false, addEventListener: null, addListener: null };

  /* ------------------------------------------------------------------ BAYER
     Exact 4x4 ordered-dither matrix from the reference. Thresholds are
     normalised to 0..1 so they compare directly with luminance. */
  var BAYER_4X4 = [
    [0 / 16, 8 / 16, 2 / 16, 10 / 16],
    [12 / 16, 4 / 16, 14 / 16, 6 / 16],
    [3 / 16, 11 / 16, 1 / 16, 9 / 16],
    [15 / 16, 7 / 16, 13 / 16, 5 / 16]
  ];

  /* 256-entry RGB lookup table: two linear segments joined at t=0.5. */
  function buildGradientLUT(c0, c1, c2) {
    var lut = new Uint8Array(256 * 3);
    for (var i = 0; i < 256; i++) {
      var t = i / 255;
      var k, r, g, b;
      if (t < 0.5) {
        k = t * 2;
        r = c0[0] + (c1[0] - c0[0]) * k;
        g = c0[1] + (c1[1] - c0[1]) * k;
        b = c0[2] + (c1[2] - c0[2]) * k;
      } else {
        k = (t - 0.5) * 2;
        r = c1[0] + (c2[0] - c1[0]) * k;
        g = c1[1] + (c2[1] - c1[1]) * k;
        b = c1[2] + (c2[2] - c1[2]) * k;
      }
      var idx = i * 3;
      lut[idx] = Math.round(r);
      lut[idx + 1] = Math.round(g);
      lut[idx + 2] = Math.round(b);
    }
    return lut;
  }

  /* #5eb8ff -> #7c8dff -> #a875ff on #060811, and the inverted set. */
  var DARK_BG = [6, 8, 17];
  var LIGHT_BG = [238, 242, 255];
  var DARK_LUT = buildGradientLUT([94, 184, 255], [124, 141, 255], [168, 117, 255]);
  var LIGHT_LUT = buildGradientLUT([29, 78, 216], [79, 70, 229], [124, 58, 237]);

  var pal = { bg: DARK_BG, lut: DARK_LUT, light: false };

  function syncPalette() {
    var light = doc.documentElement.classList.contains('is-inverted') ||
      (doc.body && doc.body.classList.contains('is-inverted'));
    if (light !== pal.light) {
      pal.light = light;
      pal.bg = light ? LIGHT_BG : DARK_BG;
      pal.lut = light ? LIGHT_LUT : DARK_LUT;
    }
  }

  /* ------------------------------------------------------- PIXEL CANVAS BUF
     The canvas backing store is the reduced buffer itself (about one pixel
     per 3 CSS px). CSS scales it with image-rendering: pixelated, which is
     nearest-neighbour at every DPR and costs no per-frame upscale blit. */
  function createDitherCanvas(canvas, container, pixelScale, onResize) {
    if (!canvas || !container) return null;
    var ctx = canvas.getContext('2d', { alpha: false });
    if (!ctx) return null;

    var buf = {
      canvas: canvas,
      ctx: ctx,
      w: 4,
      h: 4,
      cssW: 0,
      cssH: 0,
      pixelScale: pixelScale,
      scaleFor: null,
      imgData: ctx.createImageData(4, 4),
      ready: false,
      lastPaint: -1e9,
      resize: function (nextW, nextH) {
        this.cssW = nextW;
        this.cssH = nextH;

        var scale = this.scaleFor ? this.scaleFor(nextW, nextH) : this.pixelScale;
        this.w = Math.max(8, Math.ceil(nextW / scale));
        this.h = Math.max(8, Math.ceil(nextH / scale));
        this.canvas.width = this.w;
        this.canvas.height = this.h;
        this.ctx.imageSmoothingEnabled = false;
        this.imgData = this.ctx.createImageData(this.w, this.h);
        this.ready = true;
        if (typeof onResize === 'function') onResize(this.w, this.h);
      },
      present: function () {
        if (!this.ready) return;
        this.ctx.putImageData(this.imgData, 0, 0);
      }
    };

    var raf = null;
    function measure() {
      raf = null;
      var rect = container.getBoundingClientRect();
      var w = Math.round(rect.width);
      var h = Math.round(rect.height);
      if (w > 0 && h > 0 && (w !== buf.cssW || h !== buf.cssH)) buf.resize(w, h);
    }
    function schedule() {
      if (raf === null) raf = win.requestAnimationFrame(measure);
    }

    if (win.ResizeObserver) {
      var ro = new win.ResizeObserver(schedule);
      ro.observe(container);
    }
    win.addEventListener('resize', schedule, { passive: true });
    schedule();
    return buf;
  }

  /* -------------------------------------------------------- MASTER RAF LOOP */
  var items = [];
  var rafId = null;
  var lastNow = 0;
  var fpsCount = 0;
  var fpsMark = 0;
  var fpsEl = null;
  var heroModeBtns = [];
  var heroFrame = null;
  var heroItem = null;
  var staticRaf = null;

  function anyVisible() {
    for (var i = 0; i < items.length; i++) {
      var it = items[i];
      /* Static modules (interval >= 1e8) keep the loop alive only until their
         one pending frame is painted. Then the page idles. */
      if (it.visible && it.buf && it.buf.ready &&
          (it.minInterval < 100000000 || it.buf.lastPaint < 0)) return true;
    }
    return false;
  }

  function updateFps(now) {
    if (!fpsEl || !engine.visible) return;
    fpsCount++;
    if (!fpsMark) fpsMark = now;
    if (now - fpsMark >= 600) {
      var fps = Math.round(fpsCount * 1000 / (now - fpsMark));
      if (fps > 144) fps = 144;
      fpsEl.textContent = fps + ' FPS // BAYER 4\u00d74';
      fpsCount = 0;
      fpsMark = now;
    }
  }

  function frame(now) {
    rafId = null;
    if (doc.hidden) return;
    if (!lastNow) lastNow = now;
    var dt = Math.min(0.05, (now - lastNow) * 0.001);
    lastNow = now;
    var time = now * 0.001;

    syncPalette();
    engine.time += dt * engine.speed;

    for (var i = 0; i < items.length; i++) {
      var it = items[i];
      if (!it.visible || !it.buf || !it.buf.ready) continue;
      if (it.always || now - it.buf.lastPaint >= it.minInterval) {
        it.render(time, dt);
        it.buf.lastPaint = now;
      }
    }

    updateFps(now);
    if (!anyVisible()) return;
    rafId = win.requestAnimationFrame(frame);
  }

  function ensureLoop() {
    if (reduceQuery.matches) return;
    if (rafId === null && !doc.hidden && anyVisible()) {
      lastNow = win.performance.now();
      rafId = win.requestAnimationFrame(frame);
    }
  }

  function renderStatic() {
    syncPalette();
    engine.time = 0.6;
    for (var i = 0; i < items.length; i++) {
      var it = items[i];
      if (it.visible && it.buf && it.buf.ready) it.render(0.6, 0);
    }
    if (fpsEl) fpsEl.textContent = 'STATIC // BAYER 4\u00d74';
  }

  function scheduleStatic() {
    if (staticRaf !== null) return;
    staticRaf = win.requestAnimationFrame(function () {
      staticRaf = null;
      if (reduceQuery.matches) renderStatic();
      else ensureLoop();
    });
  }

  /* ------------------------------------------------------------ HERO ENGINE */
  var engine = {
    time: 0.6,
    speed: 1,
    dispersion: 1.52,
    mode: 'refract',
    isDragging: false,
    prevX: 0,
    prevY: 0,
    targetRotX: 0.24,
    targetRotY: 0.7,
    curRotX: 0.24,
    curRotY: 0.7,
    parallaxX: 0,
    parallaxY: 0,
    visible: true
  };

  /* --- torus knot mesh (p=2, q=3), built once ---------------------------- */
  var KNOT = (function () {
    var U = 68;
    var V = 12;
    var verts = [];
    var normals = [];
    var tris = [];
    var P = 2, Q = 3, R = 1.08, tube = 0.36;

    function center(u) {
      var cu = Math.cos(u), su = Math.sin(u);
      var qp = (Q / P) * u;
      var cs = Math.cos(qp), ss = Math.sin(qp);
      var rad = R + 0.44 * cs;
      return [rad * cu * 1.25, rad * su * 0.86, 0.48 * ss];
    }

    for (var i = 0; i <= U; i++) {
      var u = (i / U) * Math.PI * 2 * P;
      var c = center(u);
      var cn = center(u + 0.01);

      var tx = cn[0] - c[0], ty = cn[1] - c[1], tz = cn[2] - c[2];
      var tLen = Math.sqrt(tx * tx + ty * ty + tz * tz) || 1;
      tx /= tLen; ty /= tLen; tz /= tLen;

      var bx = -ty, by = tx, bz = 0;
      var bLen = Math.sqrt(bx * bx + by * by + bz * bz);
      if (bLen < 0.001) {
        bx = 0; by = -tz; bz = ty;
        bLen = Math.sqrt(bx * bx + by * by + bz * bz) || 1;
      }
      bx /= bLen; by /= bLen; bz /= bLen;

      var nx0 = by * tz - bz * ty;
      var ny0 = bz * tx - bx * tz;
      var nz0 = bx * ty - by * tx;

      for (var j = 0; j <= V; j++) {
        var v = (j / V) * Math.PI * 2;
        var cv = Math.cos(v), sv = Math.sin(v);
        var vx = nx0 * cv + bx * sv;
        var vy = ny0 * cv + by * sv;
        var vz = nz0 * cv + bz * sv;
        verts.push(c[0] + vx * tube, c[1] + vy * tube, c[2] + vz * tube);
        normals.push(vx, vy, vz);
      }
    }

    var stride = V + 1;
    for (var a = 0; a < U; a++) {
      for (var b = 0; b < V; b++) {
        var i0 = a * stride + b;
        var i1 = (a + 1) * stride + b;
        var i2 = (a + 1) * stride + (b + 1);
        var i3 = a * stride + (b + 1);
        tris.push(i0, i1, i3, i1, i2, i3);
      }
    }

    return {
      verts: new Float32Array(verts),
      normals: new Float32Array(normals),
      tris: new Uint16Array(tris),
      count: verts.length / 3
    };
  })();

  var knotProjX = new Float32Array(KNOT.count);
  var knotProjY = new Float32Array(KNOT.count);
  var knotProjZ = new Float32Array(KNOT.count);
  var knotRotNX = new Float32Array(KNOT.count);
  var knotRotNY = new Float32Array(KNOT.count);
  var knotRotNZ = new Float32Array(KNOT.count);

  /* --- twisted ribbon + 12 floating spheres (mode 2) --------------------- */
  var RIB_U = 42;
  var RIB_V = 6;
  var RIB_COUNT = (RIB_U + 1) * (RIB_V + 1);
  var ribProjX = new Float32Array(RIB_COUNT);
  var ribProjY = new Float32Array(RIB_COUNT);
  var ribProjZ = new Float32Array(RIB_COUNT);
  var ribRotNX = new Float32Array(RIB_COUNT);
  var ribRotNY = new Float32Array(RIB_COUNT);
  var ribRotNZ = new Float32Array(RIB_COUNT);
  var ribTris = (function () {
    var out = [];
    var stride = RIB_V + 1;
    for (var i = 0; i < RIB_U; i++) {
      for (var j = 0; j < RIB_V; j++) {
        var a = i * stride + j;
        var b = (i + 1) * stride + j;
        var c = (i + 1) * stride + (j + 1);
        var d = i * stride + (j + 1);
        out.push(a, b, d, b, c, d);
      }
    }
    return new Uint16Array(out);
  })();

  var SPHERE_N = 12;
  var sphereX = new Float32Array(SPHERE_N);
  var sphereY = new Float32Array(SPHERE_N);
  var sphereZ = new Float32Array(SPHERE_N);
  var sphereR = new Float32Array(SPHERE_N);
  var sphereSpeed = new Float32Array(SPHERE_N);
  var spherePhase = new Float32Array(SPHERE_N);
  (function () {
    for (var i = 0; i < SPHERE_N; i++) {
      sphereX[i] = ((i / (SPHERE_N - 1)) - 0.5) * 4.4 + Math.sin(i * 2.1) * 0.4;
      sphereY[i] = Math.cos(i * 1.7) * 1.35;
      sphereZ[i] = Math.sin(i * 3.1) * 1.1;
      sphereR[i] = 0.16 + (i % 4) * 0.065;
      sphereSpeed[i] = 0.7 + (i % 5) * 0.25;
      spherePhase[i] = i * 1.13;
    }
  })();

  /* --- z-buffer + background state (resized, never per frame) ------------ */
  var zBuf = new Float32Array(16);
  var nxBuf = new Float32Array(16);
  var nyBuf = new Float32Array(16);
  var nzBuf = new Float32Array(16);
  var maskBuf = new Uint8Array(16);

  var bg = {
    tiles: [],
    rowOff: new Int32Array(3),
    rowAt: null,
    filled: false,
    lum: new Uint8Array(16),
    step: 16,
    dot: 8,
    ba0: 0, bb0: 1, bc0: 0,
    ba1: 0, bb1: 1, bc1: 0,
    half: 2
  };

  function buildHeroBackground(w, h) {
    var fontSize = Math.max(9, Math.round(
      w > h
        ? Math.min(w * 0.082, h * 0.16)
        : Math.min(w * 0.11, h * 0.055)
    ));
    var font = '900 ' + fontSize + 'px "Unbounded", "Inter", sans-serif';
    var defs = [
      { text: 'STELLEREUM \u2022 ', y: 0.26, speed: -24 },
      { text: 'PQ \u2022 5757 \u2022 ', y: 0.50, speed: 19 },
      { text: 'BAYER 4\u00d74 \u2022 ', y: 0.74, speed: -17 }
    ];
    var scratch = doc.createElement('canvas');
    var sctx = scratch.getContext('2d');
    var tiles = [];

    for (var i = 0; i < defs.length; i++) {
      sctx.font = font;
      var tw = Math.max(1, Math.ceil(sctx.measureText(defs[i].text).width));
      var th = Math.max(1, Math.ceil(fontSize * 1.35));
      scratch.width = tw;
      scratch.height = th;
      sctx = scratch.getContext('2d');
      sctx.font = font;
      sctx.fillStyle = '#ffffff';
      sctx.textBaseline = 'middle';
      sctx.fillText(defs[i].text, 0, th / 2);

      var data = sctx.getImageData(0, 0, tw, th).data;
      var mask = new Uint8Array(tw * th);
      for (var p = 0, q = 3; p < mask.length; p++, q += 4) {
        mask[p] = data[q] > 96 ? 1 : 0;
      }

      tiles.push({
        mask: mask,
        w: tw,
        h: th,
        y: Math.round(defs[i].y * h - th / 2),
        speed: defs[i].speed
      });
    }

    bg.tiles = tiles;
    bg.filled = false;

    /* One lookup per scanline instead of a three-tile loop per pixel. */
    var rowAt = new Int8Array(h);
    rowAt.fill(-1);
    for (var r = 0; r < tiles.length; r++) {
      var y0 = Math.max(0, tiles[r].y);
      var y1 = Math.min(h - 1, tiles[r].y + tiles[r].h - 1);
      for (var yy = y0; yy <= y1; yy++) rowAt[yy] = r;
    }
    bg.rowAt = rowAt;

    bg.step = Math.max(10, Math.round(w / 24));
    bg.dot = bg.step >> 1;

    var cx = w * 0.5;
    var cy = h * 0.5;
    var L = Math.min(w, h) * 0.48;
    var half = Math.max(1.2, (h * 0.022) * 0.5);
    var dx = 2 * L;
    var dy = 1.44 * L;
    var len = Math.sqrt(dx * dx + dy * dy) || 1;

    bg.ba0 = dy / len;
    bg.bb0 = -dx / len;
    bg.bc0 = -(bg.ba0 * (cx - L) + bg.bb0 * (cy - L * 0.72));

    bg.ba1 = -dy / len;
    bg.bb1 = -dx / len;
    bg.bc1 = -(bg.ba1 * (cx - L) + bg.bb1 * (cy + L * 0.72));
    bg.half = half;
  }

  /* Reference-style background luminance pass, written into a reusable
     buffer. One allocation on resize, none in the loop. */
  function fillHeroBackground(w, h) {
    var tiles = bg.tiles;
    var rowAt = bg.rowAt;
    var out = bg.lum;
    var step = bg.step;
    var dot = bg.dot;
    var half = bg.half;
    var ba0 = bg.ba0, bb0 = bg.bb0, bc0 = bg.bc0;
    var ba1 = bg.ba1, bb1 = bg.bb1, bc1 = bg.bc1;
    var rowOff = bg.rowOff;
    var idx = 0;

    for (var y = 0; y < h; y++) {
      var row = rowAt[y];
      var tile = row >= 0 ? tiles[row] : null;
      var off = row >= 0 ? rowOff[row] : 0;
      var useRow = (y % step) === dot;

      for (var x = 0; x < w; x++) {
        var lum = 0;
        if (useRow && (x % step) === dot) lum = 0.12;
        if (Math.abs(ba0 * x + bb0 * y + bc0) < half) lum = 0.56;
        if (Math.abs(ba1 * x + bb1 * y + bc1) < half) lum = 0.56;

        if (tile) {
          var ty = y - tile.y;
          if (ty >= 0 && ty < tile.h) {
            var tx = (x + off) % tile.w;
            if (tile.mask[ty * tile.w + tx]) lum = 0.64;
          }
        }
        out[idx++] = (lum * 255) | 0;
      }
    }
  }

  function updateRowOffsets(time) {
    var changed = false;
    for (var i = 0; i < bg.tiles.length; i++) {
      var t = bg.tiles[i];
      var o = Math.floor(time * t.speed) % t.w;
      if (o < 0) o += t.w;
      if (bg.rowOff[i] !== o) { bg.rowOff[i] = o; changed = true; }
    }
    return changed;
  }

  function rasterizeTriangle(
    w, h,
    x0, y0, z0, n0x, n0y, n0z,
    x1, y1, z1, n1x, n1y, n1z,
    x2, y2, z2, n2x, n2y, n2z,
    doubleSided
  ) {
    var area = (x1 - x0) * (y2 - y0) - (y1 - y0) * (x2 - x0);
    if (!doubleSided && area <= 0) return;
    if (Math.abs(area) < 0.001) return;

    var flipN = area < 0 ? -1 : 1;
    var invArea = 1 / area;

    var minX = Math.max(0, Math.floor(Math.min(x0, x1, x2)));
    var maxX = Math.min(w - 1, Math.ceil(Math.max(x0, x1, x2)));
    var minY = Math.max(0, Math.floor(Math.min(y0, y1, y2)));
    var maxY = Math.min(h - 1, Math.ceil(Math.max(y0, y1, y2)));

    for (var py = minY; py <= maxY; py++) {
      var y = py + 0.5;
      var rowOff = py * w;
      for (var px = minX; px <= maxX; px++) {
        var x = px + 0.5;
        var w0 = ((x1 - x) * (y2 - y) - (y1 - y) * (x2 - x)) * invArea;
        var w1 = ((x2 - x) * (y0 - y) - (y2 - y) * (x0 - x)) * invArea;
        var w2 = 1 - w0 - w1;
        if (w0 < 0 || w1 < 0 || w2 < 0) continue;

        var z = w0 * z0 + w1 * z1 + w2 * z2;
        var idx = rowOff + px;
        if (z > zBuf[idx]) {
          zBuf[idx] = z;
          nxBuf[idx] = (w0 * n0x + w1 * n1x + w2 * n2x) * flipN;
          nyBuf[idx] = (w0 * n0y + w1 * n1y + w2 * n2y) * flipN;
          nzBuf[idx] = (w0 * n0z + w1 * n1z + w2 * n2z) * flipN;
          maskBuf[idx] = 1;
        }
      }
    }
  }

  function heroReady(buf) {
    if (!buf || !buf.ready) return false;
    var size = buf.w * buf.h;
    if (zBuf.length !== size) {
      zBuf = new Float32Array(size);
      nxBuf = new Float32Array(size);
      nyBuf = new Float32Array(size);
      nzBuf = new Float32Array(size);
      maskBuf = new Uint8Array(size);
      bg.lum = new Uint8Array(size);
      bg.filled = false;
    }
    return true;
  }

  function renderHero(dt, timeSec) {
    var buf = heroItem && heroItem.buf;
    if (!heroReady(buf) || !engine.visible) return;

    var w = buf.w;
    var h = buf.h;

    if (!reduceQuery.matches && !engine.isDragging) {
      engine.targetRotY += dt * 0.30 * engine.speed;
    }

    var scrollTilt = 0;
    var sy = win.scrollY || win.pageYOffset || 0;
    if (sy > 0) scrollTilt = Math.min(1, sy / Math.max(1, win.innerHeight)) * 0.28;

    /* Scroll parallax: the stage object sinks and recedes slightly while the
       copy travels, so the 100vh panel reads as depth, not a flat video. */
    var scrollDrop = sy > 0 ? Math.min(1, sy / Math.max(1, win.innerHeight)) : 0;
    halfH -= scrollDrop * h * 0.05;
    fov *= 1 - scrollDrop * 0.07;

    var wantX = engine.targetRotX + engine.parallaxY * 0.26 + scrollTilt;
    var wantY = engine.targetRotY + engine.parallaxX * 0.34;
    engine.curRotX += (wantX - engine.curRotX) * 0.08;
    engine.curRotY += (wantY - engine.curRotY) * 0.08;

    if (reduceQuery.matches) {
      engine.curRotX = 0.28;
      engine.curRotY = 0.7;
    }

    var rotX = engine.curRotX;
    var rotY = engine.curRotY;
    var rotZ = Math.sin(engine.time * 0.45) * 0.14;

    var cx = Math.cos(rotX), sx = Math.sin(rotX);
    var cy = Math.cos(rotY), sy2 = Math.sin(rotY);
    var cz = Math.cos(rotZ), sz = Math.sin(rotZ);

    zBuf.fill(-999);
    maskBuf.fill(0);

    var halfW = w * 0.5;
    var halfH = h * 0.5;
    var wide = w > h * 1.08;
    /* Full-bleed composition: on landscape screens the knot is pushed to
       the clear right side and scaled to ~85% of the viewport height. On
       portrait it is cropped edge-to-edge behind the display type. */
    var fov = wide ? Math.min(w, h) * 1.08 : h * 0.58;
    var camZ = wide ? 4.0 : 4.2;
    halfW = wide ? w * 0.71 : w * 0.5;
    halfH = wide ? h * 0.5 : h * 0.34;

    if (engine.mode === 'refract') {
      /* Static background rows are reused until their sub-pixel scroll
         actually changes. Cuts the per-frame work roughly in half. */
      if (updateRowOffsets(timeSec) || !bg.filled) {
        fillHeroBackground(w, h);
        bg.filled = true;
      }

      var verts = KNOT.verts;
      var norms = KNOT.normals;
      for (var i = 0; i < KNOT.count; i++) {
        var vi = i * 3;
        var px = verts[vi], py = verts[vi + 1], pz = verts[vi + 2];
        var q0x = norms[vi], q0y = norms[vi + 1], q0z = norms[vi + 2];

        var x1 = px * cy + pz * sy2;
        var z1 = -px * sy2 + pz * cy;
        var y2 = py * cx - z1 * sx;
        var z2 = py * sx + z1 * cx;
        var x3 = x1 * cz - y2 * sz;
        var y3 = x1 * sz + y2 * cz;

        var persp = fov / (camZ - z2);
        knotProjX[i] = halfW + x3 * persp;
        knotProjY[i] = halfH - y3 * persp;
        knotProjZ[i] = z2;

        var nx1 = q0x * cy + q0z * sy2;
        var nz1 = -q0x * sy2 + q0z * cy;
        var ny2 = q0y * cx - nz1 * sx;
        var nz2 = q0y * sx + nz1 * cx;
        knotRotNX[i] = nx1 * cz - ny2 * sz;
        knotRotNY[i] = nx1 * sz + ny2 * cz;
        knotRotNZ[i] = nz2;
      }

      var tris = KNOT.tris;
      for (var t = 0; t < tris.length; t += 3) {
        var a = tris[t], b = tris[t + 1], c = tris[t + 2];
        rasterizeTriangle(
          w, h,
          knotProjX[a], knotProjY[a], knotProjZ[a], knotRotNX[a], knotRotNY[a], knotRotNZ[a],
          knotProjX[b], knotProjY[b], knotProjZ[b], knotRotNX[b], knotRotNY[b], knotRotNZ[b],
          knotProjX[c], knotProjY[c], knotProjZ[c], knotRotNX[c], knotRotNY[c], knotRotNZ[c],
          false
        );
      }
    } else {
      var tNow = engine.time;
      var vi2 = 0;
      for (var ri = 0; ri <= RIB_U; ri++) {
        var u = (ri / RIB_U - 0.5) * 6.4;
        var twist = u * 0.55 + tNow * 0.45;
        var ct = Math.cos(twist), st = Math.sin(twist);
        var waveY = Math.sin(u * 1.15 + tNow * 1.35) * 0.42;
        var waveZ = Math.cos(u * 0.85 + tNow * 1.05) * 0.45;

        for (var rj = 0; rj <= RIB_V; rj++) {
          var rv = (rj / RIB_V - 0.5) * 1.18;
          var rpx = u;
          var rpy = rv * ct + waveY;
          var rpz = rv * st + waveZ;

          var rn0x = -Math.cos(u * 1.15 + tNow * 1.35) * 0.25;
          var rn0y = -st;
          var rn0z = ct;

          var rx = rotX * 0.35;
          var ry = Math.sin(tNow * 0.35) * 0.14 + engine.parallaxX * 0.2;
          var crx = Math.cos(rx), srx = Math.sin(rx);
          var cry = Math.cos(ry), sry = Math.sin(ry);

          var rx1 = rpx * cry + rpz * sry;
          var rz1 = -rpx * sry + rpz * cry;
          var ry2 = rpy * crx - rz1 * srx;
          var rz2 = rpy * srx + rz1 * crx;

          var rpersp = fov / (camZ + 0.6 - rz2);
          ribProjX[vi2] = halfW + rx1 * rpersp;
          ribProjY[vi2] = halfH - ry2 * rpersp;
          ribProjZ[vi2] = rz2;

          var rnx1 = rn0x * cry + rn0z * sry;
          var rnz1 = -rn0x * sry + rn0z * cry;
          ribRotNX[vi2] = rnx1;
          ribRotNY[vi2] = rn0y * crx - rnz1 * srx;
          ribRotNZ[vi2] = rn0y * srx + rnz1 * crx;
          vi2++;
        }
      }

      for (var rt = 0; rt < ribTris.length; rt += 3) {
        var ra = ribTris[rt], rb = ribTris[rt + 1], rc = ribTris[rt + 2];
        rasterizeTriangle(
          w, h,
          ribProjX[ra], ribProjY[ra], ribProjZ[ra], ribRotNX[ra], ribRotNY[ra], ribRotNZ[ra],
          ribProjX[rb], ribProjY[rb], ribProjZ[rb], ribRotNX[rb], ribRotNY[rb], ribRotNZ[rb],
          ribProjX[rc], ribProjY[rc], ribProjZ[rc], ribRotNX[rc], ribRotNY[rc], ribRotNZ[rc],
          true
        );
      }

      for (var sp = 0; sp < SPHERE_N; sp++) {
        var spy = sphereY[sp] + Math.sin(tNow * sphereSpeed[sp] + spherePhase[sp]) * 0.32;
        var spersp = fov / (camZ + 0.6 - sphereZ[sp]);
        var scx = halfW + sphereX[sp] * spersp;
        var scy = halfH - spy * spersp;
        var sr = sphereR[sp] * spersp;

        var sminX = Math.max(0, Math.floor(scx - sr));
        var smaxX = Math.min(w - 1, Math.ceil(scx + sr));
        var sminY = Math.max(0, Math.floor(scy - sr));
        var smaxY = Math.min(h - 1, Math.ceil(scy + sr));

        for (var py = sminY; py <= smaxY; py++) {
          var dy = (py - scy) / sr;
          var dy2 = dy * dy;
          var rowOff2 = py * w;
          for (var px = sminX; px <= smaxX; px++) {
            var dx = (px - scx) / sr;
            var d2 = dx * dx + dy2;
            if (d2 > 1) continue;
            var dz = Math.sqrt(1 - d2);
            var z = sphereZ[sp] + dz * sphereR[sp];
            var idx2 = rowOff2 + px;
            if (z > zBuf[idx2]) {
              zBuf[idx2] = z;
              nxBuf[idx2] = dx;
              nyBuf[idx2] = -dy;
              nzBuf[idx2] = dz;
              maskBuf[idx2] = 1;
            }
          }
        }
      }
    }

    /* Bayer 4x4 threshold -> electric gradient LUT. */
    var out = buf.imgData.data;
    var lut = pal.lut;
    var bcol = pal.bg;
    var disp = engine.dispersion;
    var bendPx = 14 * disp;
    var invW = 1 / Math.max(1, w - 1);
    var invH = 1 / Math.max(1, h - 1);
    var timeShift = Math.sin(timeSec * 0.45) * 0.18;
    var outIdx = 0;
    var refr = engine.mode === 'refract';

    for (var y = 0; y < h; y++) {
      var bayerRow = BAYER_4X4[y & 3];
      var rowOff3 = y * w;
      var ny = y * invH;

      for (var x = 0; x < w; x++) {
        var idx3 = rowOff3 + x;
        var lum = 0;
        var gradShift = 0;

        if (maskBuf[idx3]) {
          var mx = nxBuf[idx3], my = nyBuf[idx3], mz = nzBuf[idx3];
          var nLen = Math.sqrt(mx * mx + my * my + mz * mz) || 1;
          mx /= nLen; my /= nLen; mz /= nLen;

          var ndotv = Math.max(0, Math.min(1, Math.abs(mz)));
          var fres = 1 - ndotv;
          /* Reference uses pow(fres, 2.2); x^2.25 via two sqrts is visually
             identical at this buffer size and keeps the hot path cheap. */
          var fresnel = fres * fres * Math.sqrt(Math.sqrt(fres));
          var l1 = Math.max(0, mx * 0.48 + my * 0.62 + mz * 0.62);
          var l2 = Math.max(0, -mx * 0.55 - my * 0.32 + mz * 0.77);
          var l1_2 = l1 * l1;
          var l1_4 = l1_2 * l1_2;
          var l1_8 = l1_4 * l1_4;
          var l2_2 = l2 * l2;
          var l2_3 = l2_2 * l2;
          var spec = (l1_8 * l1_2) * 0.95 + (l2_3 * l2_3) * 0.45;
          gradShift = (1 - ndotv) * 0.32 + mx * 0.18;

          if (refr) {
            var sx1 = Math.round(x + mx * bendPx);
            var sy1 = Math.round(y - my * bendPx);
            var sx2 = Math.round(x + mx * bendPx * 1.45);
            var sy2 = Math.round(y - my * bendPx * 1.45);
            if (sx1 < 0) sx1 = 0; else if (sx1 > w - 1) sx1 = w - 1;
            if (sy1 < 0) sy1 = 0; else if (sy1 > h - 1) sy1 = h - 1;
            if (sx2 < 0) sx2 = 0; else if (sx2 > w - 1) sx2 = w - 1;
            if (sy2 < 0) sy2 = 0; else if (sy2 > h - 1) sy2 = h - 1;

            var bg1 = bg.lum[sy1 * w + sx1] * 0.0039215686;
            var bg2 = bg.lum[sy2 * w + sx2] * 0.0039215686;
            var refracted = bg1 * 0.62 + bg2 * 0.38;
            lum = refracted * 0.78 + fresnel * 0.74 + spec * 0.85 + 0.08;
          } else {
            var stripe = Math.sin((mx * 4.2 + my * 3.1 + engine.time * 0.9) * disp) * 0.14;
            lum = 0.22 + l1 * 0.48 + fresnel * 0.64 + spec * 0.82 + stripe;
          }
        } else if (refr) {
          lum = bg.lum[idx3] * 0.0039215686 * 0.92;
        } else {
          lum = (x % 16 === 0 && y % 16 === 0) ? 0.38 : 0;
        }

        if (lum > bayerRow[x & 3]) {
          var gT = x * invW * 0.68 + ny * 0.32 + timeShift + gradShift;
          if (gT < 0) gT = 0; else if (gT > 1) gT = 1;
          var li = ((gT * 255) | 0) * 3;
          out[outIdx++] = lut[li];
          out[outIdx++] = lut[li + 1];
          out[outIdx++] = lut[li + 2];
          out[outIdx++] = 255;
        } else {
          out[outIdx++] = bcol[0];
          out[outIdx++] = bcol[1];
          out[outIdx++] = bcol[2];
          out[outIdx++] = 255;
        }
      }
    }

    buf.present();
  }

  /* ------------------------------------------------------ SECONDARY MODULES */
  var ribbonItem = null;
  var interfItem = null;
  var slabItem = null;
  var cardItems = [];

  function writeElectricPixel(data, idx, lit, gradT, bcol, lut) {
    if (lit) {
      var t = gradT;
      if (t < 0) t = 0; else if (t > 1) t = 1;
      var li = ((t * 255) | 0) * 3;
      data[idx] = lut[li];
      data[idx + 1] = lut[li + 1];
      data[idx + 2] = lut[li + 2];
      data[idx + 3] = 255;
    } else {
      data[idx] = bcol[0];
      data[idx + 1] = bcol[1];
      data[idx + 2] = bcol[2];
      data[idx + 3] = 255;
    }
  }

  function renderRibbon(time) {
    var buf = ribbonItem && ribbonItem.buf;
    if (!buf || !buf.ready) return;
    var w = buf.w, h = buf.h;
    var data = buf.imgData.data;
    var bcol = pal.bg, lut = pal.lut;
    var invW = 1 / Math.max(1, w - 1);
    var wave = Math.sin(time * 0.9) * 0.09;
    var idx = 0;

    for (var y = 0; y < h; y++) {
      var bayerRow = BAYER_4X4[y & 3];
      for (var x = 0; x < w; x++) {
        var nx = x * invW;
        var v = nx * 0.86 + Math.sin(nx * 7.5 + time * 0.8) * 0.06 + wave;
        var g = nx * 0.86 + Math.sin(time * 0.55) * 0.14;
        writeElectricPixel(data, idx, v > bayerRow[x & 3], g, bcol, lut);
        idx += 4;
      }
    }
    buf.present();
  }

  function renderInterference(time) {
    var buf = interfItem && interfItem.buf;
    if (!buf || !buf.ready) return;
    var w = buf.w, h = buf.h;
    var data = buf.imgData.data;
    var bcol = pal.bg, lut = pal.lut;
    var invW = 1 / Math.max(1, w - 1);
    var invH = 1 / Math.max(1, h - 1);
    var warp = 0.34 + Math.sin(time * 0.29) * 0.22;
    var freq = 10 + Math.abs(warp) * 24;
    var shift = time * 1.8 * engine.speed + warp * 5;
    var idx = 0;

    for (var y = 0; y < h; y++) {
      var ny = y * invH;
      var bayerRow = BAYER_4X4[y & 3];
      for (var x = 0; x < w; x++) {
        var nx = x * invW;
        var w1 = Math.sin(nx * freq + shift + Math.sin(ny * 6) * (0.8 + Math.abs(warp) * 2.2));
        var w2 = Math.cos(nx * (freq * 0.55) - shift * 0.7 + ny * 9);
        var v = (w1 * 0.55 + w2 * 0.45) * 0.5 + 0.5;
        var g = nx * 0.8 + ny * 0.2 + Math.sin(time * 0.7) * 0.12;
        writeElectricPixel(data, idx, v > bayerRow[x & 3], g, bcol, lut);
        idx += 4;
      }
    }
    buf.present();
  }

  /* Full-width slab under the hero: crossed beams, a walking moire field
     and a 16px pixel lattice, all thresholded with the same Bayer matrix. */
  function renderSlab(time) {
    var buf = slabItem && slabItem.buf;
    if (!buf || !buf.ready) return;
    var w = buf.w, h = buf.h;
    var data = buf.imgData.data;
    var bcol = pal.bg, lut = pal.lut;
    var invW = 1 / Math.max(1, w - 1);
    var invH = 1 / Math.max(1, h - 1);
    var idx = 0;

    for (var y = 0; y < h; y++) {
      var ny = y * invH;
      var bayerRow = BAYER_4X4[y & 3];
      for (var x = 0; x < w; x++) {
        var nx = x * invW;
        var beam = Math.sin((nx * 1.6 + ny * 0.9) * 18 - time * 1.25);
        var beam2 = Math.sin((nx * 2.1 - ny * 1.4) * 13 + time * 0.9);
        var grid = ((x >> 3) + (y >> 3)) & 1 ? 0.16 : 0;
        var v = (beam * 0.5 + 0.5) * 0.52 + (beam2 * 0.5 + 0.5) * 0.34 + grid + 0.06;
        var g = nx * 0.78 + ny * 0.22 + Math.sin(time * 0.4) * 0.1;
        writeElectricPixel(data, idx, v > bayerRow[x & 3], g, bcol, lut);
        idx += 4;
      }
    }
    buf.present();
  }

  /* Precomputed 3D satellite points for card 03 (240 leaves, no objects). */
  var SAT_N = 240;
  var satSX = new Float32Array(SAT_N);
  var satSY = new Float32Array(SAT_N);
  var satSZ = new Float32Array(SAT_N);
  var satTX = new Float32Array(SAT_N);
  var satTY = new Float32Array(SAT_N);
  var satTZ = new Float32Array(SAT_N);
  (function () {
    var golden = Math.PI * (3 - Math.sqrt(5));
    for (var i = 0; i < SAT_N; i++) {
      var t = i / (SAT_N - 1);
      var y = 1 - 2 * t;
      var r = Math.sqrt(Math.max(0, 1 - y * y));
      var th = golden * i;
      var u = ((i % 24) / 24) * Math.PI * 2;
      var v = (Math.floor(i / 24) / 10) * Math.PI * 2;
      satSX[i] = Math.cos(th) * r;
      satSY[i] = y;
      satSZ[i] = Math.sin(th) * r;
      satTX[i] = (0.75 + 0.32 * Math.cos(v)) * Math.cos(u);
      satTY[i] = 0.32 * Math.sin(v);
      satTZ[i] = (0.75 + 0.32 * Math.cos(v)) * Math.sin(u);
    }
  })();

  function renderCard(index, time, meta) {
    var item = cardItems[index];
    if (!item || !item.buf || !item.buf.ready || !item.visible) return;
    var buf = item.buf;
    var w = buf.w, h = buf.h;
    var data = buf.imgData.data;
    var bcol = pal.bg, lut = pal.lut;
    var tShift = Math.sin(time * 0.5) * 0.14;
    var invW = 1 / Math.max(1, w - 1);
    var invH = 1 / Math.max(1, h - 1);
    var idx, x, y, nx, ny, bayerRow;

    if (index === 0) {
      /* Radial pulse rings. */
      var aspect = w / h;
      var ccx = meta.hover ? meta.mx : 0.65 + Math.sin(time * 0.6) * 0.12;
      var ccy = meta.hover ? meta.my : 0.48 + Math.cos(time * 0.5) * 0.10;
      idx = 0;
      for (y = 0; y < h; y++) {
        ny = y * invH;
        bayerRow = BAYER_4X4[y & 3];
        for (x = 0; x < w; x++) {
          nx = x * invW;
          var d1 = Math.sqrt((nx - ccx) * (nx - ccx) * aspect * aspect + (ny - ccy) * (ny - ccy));
          var d2 = Math.sqrt((nx - 0.25) * (nx - 0.25) * aspect * aspect + (ny - 0.35) * (ny - 0.35));
          var v0 = (Math.sin(d1 * 28 - time * 2.6) * 0.55 + Math.sin(d2 * 18 + time * 1.4) * 0.45) * 0.48 + 0.48;
          writeElectricPixel(data, idx, v0 > bayerRow[x & 3], nx * 0.65 + ny * 0.35 + tShift, bcol, lut);
          idx += 4;
        }
      }
    } else if (index === 1) {
      /* Kinetic isometric grid. */
      var skew = meta.hover ? (meta.mx - 0.5) * 1.8 : Math.sin(time * 0.7) * 0.5;
      idx = 0;
      for (y = 0; y < h; y++) {
        ny = y * invH;
        bayerRow = BAYER_4X4[y & 3];
        for (x = 0; x < w; x++) {
          nx = x * invW;
          var gx = Math.floor((nx + ny * skew) * 9 + time * 0.5);
          var gy = Math.floor(ny * 5);
          var wave = Math.sin((nx * 10 - ny * 4) + time * 1.6) * 0.5 + 0.5;
          var v1 = ((gx ^ gy) & 1) ? wave * 0.85 : wave * 0.35;
          writeElectricPixel(data, idx, v1 > bayerRow[x & 3], nx * 0.7 + ny * 0.3 - tShift, bcol, lut);
          idx += 4;
        }
      }
    } else if (index === 2) {
      /* Flowing silk interference. */
      var amp = meta.hover ? 0.28 : 0.16;
      idx = 0;
      for (y = 0; y < h; y++) {
        ny = y * invH;
        bayerRow = BAYER_4X4[y & 3];
        for (x = 0; x < w; x++) {
          nx = x * invW;
          var bend = Math.sin(nx * 6.5 + time * 1.1) * amp + Math.cos(nx * 3.1 - time * 0.7) * 0.1;
          var band = Math.sin((ny + bend) * 24 - time * 1.5);
          var v2 = band * 0.48 + 0.5;
          writeElectricPixel(data, idx, v2 > bayerRow[x & 3], nx * 0.55 + ny * 0.45 + tShift, bcol, lut);
          idx += 4;
        }
      }
    } else {
      /* Generative 3D satellite vector field. */
      for (var c = 0; c < data.length; c += 4) {
        data[c] = bcol[0]; data[c + 1] = bcol[1]; data[c + 2] = bcol[2]; data[c + 3] = 255;
      }
      var morph = meta.hover ? 1 : (Math.sin(time * 0.7) * 0.5 + 0.5);
      var rotY = time * (meta.hover ? 1.5 : 0.65);
      var rotX = 0.4 + (meta.hover ? (meta.my - 0.5) * 0.9 : 0);
      var ccy2 = Math.cos(rotY), ssy = Math.sin(rotY);
      var ccx2 = Math.cos(rotX), ssx = Math.sin(rotX);
      var scale = Math.min(w, h) * 0.42;
      var ox = w * 0.58;
      var oy = h * 0.5;

      for (var s = 0; s < SAT_N; s++) {
        var px = satSX[s] + (satTX[s] - satSX[s]) * morph;
        var py = satSY[s] + (satTY[s] - satSY[s]) * morph;
        var pz = satSZ[s] + (satTZ[s] - satSZ[s]) * morph;

        var x1 = px * ccy2 - pz * ssy;
        var z1 = px * ssy + pz * ccy2;
        var y2 = py * ccx2 - z1 * ssx;
        var z2 = py * ssx + z1 * ccx2;

        var persp = 2.4 / (2.4 - z2);
        var sxp = Math.round(ox + x1 * scale * persp);
        var syp = Math.round(oy + y2 * scale * persp);
        var sz = z2 > 0.15 ? 2 : 1;

        var gT = sxp * invW + (z2 + 1) * 0.15 + tShift;
        if (gT < 0) gT = 0; else if (gT > 1) gT = 1;
        var li = ((gT * 255) | 0) * 3;

        for (var dy = 0; dy < sz; dy++) {
          for (var dx = 0; dx < sz; dx++) {
            var xx = sxp + dx;
            var yy = syp + dy;
            if (xx >= 0 && xx < w && yy >= 0 && yy < h) {
              var pIdx = (yy * w + xx) * 4;
              data[pIdx] = lut[li];
              data[pIdx + 1] = lut[li + 1];
              data[pIdx + 2] = lut[li + 2];
            }
          }
        }
      }
    }

    buf.present();
  }

  /* ------------------------------------------------------------- INTERACTION */
  function clamp(n, lo, hi) { return n < lo ? lo : (n > hi ? hi : n); }

  function bindHeroInteraction(canvas) {
    function down(cx, cy) {
      if (reduceQuery.matches) return;
      engine.isDragging = true;
      engine.prevX = cx;
      engine.prevY = cy;
      if (heroFrame) heroFrame.classList.add('is-dragging');
    }
    function move(cx, cy) {
      if (reduceQuery.matches) return;
      if (!engine.isDragging) return;
      var dx = cx - engine.prevX;
      var dy = cy - engine.prevY;
      engine.targetRotY += dx * 0.01;
      engine.targetRotX = clamp(engine.targetRotX + dy * 0.01, -1.1, 1.1);
      engine.prevX = cx;
      engine.prevY = cy;
      ensureLoop();
    }
    function up() {
      engine.isDragging = false;
      if (heroFrame) heroFrame.classList.remove('is-dragging');
    }

    if (win.PointerEvent) {
      canvas.addEventListener('pointerdown', function (e) {
        if (e.button !== undefined && e.button !== 0) return;
        down(e.clientX, e.clientY);
        if (canvas.setPointerCapture && e.pointerId !== undefined) {
          try { canvas.setPointerCapture(e.pointerId); } catch (err) {}
        }
      });
      win.addEventListener('pointermove', function (e) {
        if (e.pointerType === 'touch') return;
        engine.parallaxX = (e.clientX / Math.max(1, win.innerWidth) - 0.5) * 2;
        engine.parallaxY = (e.clientY / Math.max(1, win.innerHeight) - 0.5) * 2;
        move(e.clientX, e.clientY);
      }, { passive: true });
      win.addEventListener('pointerup', up);
      win.addEventListener('pointercancel', up);
    } else {
      canvas.addEventListener('mousedown', function (e) { down(e.clientX, e.clientY); });
      win.addEventListener('mousemove', function (e) {
        engine.parallaxX = (e.clientX / Math.max(1, win.innerWidth) - 0.5) * 2;
        engine.parallaxY = (e.clientY / Math.max(1, win.innerHeight) - 0.5) * 2;
        move(e.clientX, e.clientY);
      }, { passive: true });
      win.addEventListener('mouseup', up);
      canvas.addEventListener('touchstart', function (e) {
        if (e.touches.length === 1) down(e.touches[0].clientX, e.touches[0].clientY);
      }, { passive: true });
      win.addEventListener('touchmove', function (e) {
        if (e.touches.length === 1) move(e.touches[0].clientX, e.touches[0].clientY);
      }, { passive: true });
      win.addEventListener('touchend', up);
    }

    function setHeroMode(mode) {
      var ribbon = mode === 'ribbon';
      engine.mode = ribbon ? 'ribbon' : 'refract';
      heroModeBtns.forEach(function (btn) {
        var on = btn.getAttribute('data-hero-mode') === engine.mode;
        btn.setAttribute('aria-pressed', on ? 'true' : 'false');
        btn.classList.toggle('is-active', on);
      });
      if (reduceQuery.matches) renderStatic();
      else ensureLoop();
    }

    heroModeBtns.forEach(function (btn) {
      btn.addEventListener('click', function () {
        setHeroMode(btn.getAttribute('data-hero-mode'));
      });
    });
  }

  /* --------------------------------------------------------------- WATCHERS */
  function watch(item, el) {
    if (!el) return;
    if (!('IntersectionObserver' in win)) {
      item.visible = true;
      return;
    }
    var io = new win.IntersectionObserver(function (entries) {
      item.visible = entries[0].isIntersecting;
      if (item === heroItem) engine.visible = item.visible;
      if (item.visible) {
        item.buf.lastPaint = -1e9;
        if (reduceQuery.matches) scheduleStatic();
        else ensureLoop();
      }
    }, { threshold: 0.01 });
    io.observe(el);
  }

  /* ------------------------------------------------------------------- BOOT */
  function setupHero() {
    var canvas = doc.getElementById('hero-canvas');
    var frameEl = doc.getElementById('hero-stage');
    if (!canvas || !frameEl) return;

    heroFrame = frameEl;
    fpsEl = doc.getElementById('hero-fps');
    heroModeBtns = Array.prototype.slice.call(doc.querySelectorAll('[data-hero-mode]'));

    var buf = createDitherCanvas(canvas, frameEl, 3, function (w, h) {
      heroReady(buf);
      buildHeroBackground(w, h);
      buf.lastPaint = -1e9;
      scheduleStatic();
    });
    if (!buf) return;
    /* Keep the hero pixel grid coarse (the technique) while capping the
       buffer on 4K panels. One scale for the whole stage. */
    buf.scaleFor = function (cssW, cssH) {
      var area = cssW * cssH;
      if (cssW < 420) return 2;
      if (area > 1000000) return 4;
      if (area > 460000) return 3;
      return 2;
    };

    heroItem = {
      buf: buf,
      visible: true,
      always: true,
      minInterval: 0,
      render: function (t, dt) { renderHero(dt, t); }
    };
    items.push(heroItem);

    bindHeroInteraction(canvas);
    watch(heroItem, frameEl);
  }

  function setupRibbon() {
    var canvas = doc.getElementById('ribbon-canvas');
    var wrap = doc.getElementById('ribbon-wrap');
    if (!canvas || !wrap) return;

    var buf = createDitherCanvas(canvas, wrap, 2, function () {
      buf.lastPaint = -1e9;
      scheduleStatic();
    });
    if (!buf) return;
    ribbonItem = {
      buf: buf,
      visible: false,
      minInterval: 40,
      render: function (t) { renderRibbon(t); }
    };
    items.push(ribbonItem);
    watch(ribbonItem, wrap);
  }

  function setupInterference() {
    var canvas = doc.getElementById('interference-canvas');
    var wrap = doc.getElementById('interference-wrap');
    if (!canvas || !wrap) return;

    var buf = createDitherCanvas(canvas, wrap, 2, function () {
      buf.lastPaint = -1e9;
      scheduleStatic();
    });
    if (!buf) return;
    interfItem = {
      buf: buf,
      /* One still frame: the protocol/stack section is typographic, not a
         dashboard. The large slab and the stage carry the live motion. */
      visible: false,
      minInterval: 1e9,
      render: function (t) { renderInterference(t); }
    };
    items.push(interfItem);
    watch(interfItem, wrap);
  }

  function setupSlab() {
    var canvas = doc.getElementById('slab-canvas');
    var wrap = doc.getElementById('slab-wrap');
    if (!canvas || !wrap) return;

    var buf = createDitherCanvas(canvas, wrap, 3, function () {
      buf.lastPaint = -1e9;
      scheduleStatic();
    });
    if (!buf) return;
    slabItem = {
      buf: buf,
      visible: false,
      minInterval: 55,
      render: function (t) { renderSlab(t); }
    };
    items.push(slabItem);
    watch(slabItem, wrap);
  }

  function setupCards() {
    for (var i = 0; i < 4; i++) {
      var canvas = doc.getElementById('card-canvas-' + i);
      var wrap = canvas ? canvas.parentElement : null;
      if (!canvas || !wrap) continue;

      var item = {
        buf: null,
        visible: false,
        /* The protocol/stack cards are deliberately still: one frame on
           resize or palette change, never a loop. Motion belongs to the
           stage and the two signal strips, not to six equal cards. */
        minInterval: 1e9,
        meta: { hover: false, mx: 0.5, my: 0.5 },
        index: i,
        render: null
      };

      (function (idx, obj) {
        obj.render = function (t) { renderCard(idx, t, obj.meta); };
      })(i, item);

      item.buf = createDitherCanvas(canvas, wrap, 3, function () {
        item.buf.lastPaint = -1e9;
        scheduleStatic();
      });
      if (!item.buf) continue;

      cardItems[i] = item;
      items.push(item);
      watch(item, wrap);
    }
  }

  function onReduceChange() {
    if (reduceQuery.matches) {
      if (rafId !== null) {
        win.cancelAnimationFrame(rafId);
        rafId = null;
      }
      renderStatic();
    } else {
      if (fpsEl) fpsEl.textContent = 'FPS // BAYER 4\u00d74';
      ensureLoop();
    }
  }

  function boot() {
    doc.documentElement.classList.add('dither-ready');
    syncPalette();
    setupHero();
    setupRibbon();
    setupInterference();
    setupSlab();
    setupCards();

    doc.addEventListener('visibilitychange', function () {
      if (doc.hidden) {
        if (rafId !== null) {
          win.cancelAnimationFrame(rafId);
          rafId = null;
        }
      } else {
        if (reduceQuery.matches) renderStatic();
        else ensureLoop();
      }
    });

    if (reduceQuery.addEventListener) reduceQuery.addEventListener('change', onReduceChange);
    else if (reduceQuery.addListener) reduceQuery.addListener(onReduceChange);

    if (win.MutationObserver) {
      var mo = new win.MutationObserver(function () {
        syncPalette();
        for (var i = 0; i < items.length; i++) items[i].buf.lastPaint = -1e9;
        if (reduceQuery.matches) scheduleStatic();
        else ensureLoop();
      });
      mo.observe(doc.documentElement, { attributes: true, attributeFilter: ['class'] });
    }

    if (reduceQuery.matches) scheduleStatic();
    else ensureLoop();
  }

  if (doc.readyState === 'loading') doc.addEventListener('DOMContentLoaded', boot);
  else boot();

  /* Small read-only probe for the verification pass (no animation work). */
  win.StellDither = {
    mode: function () { return engine.mode; },
    running: function () { return rafId !== null; },
    heroVisible: function () { return engine.visible; },
    stats: function () {
      var out = [];
      for (var i = 0; i < items.length; i++) {
        var it = items[i];
        if (!it.buf) continue;
        out.push({
          cssW: it.buf.cssW,
          cssH: it.buf.cssH,
          w: it.buf.w,
          h: it.buf.h,
          scale: it.buf.scaleFor ? it.buf.scaleFor(it.buf.cssW, it.buf.cssH) : it.buf.pixelScale,
          visible: it.visible,
          painted: it.buf.lastPaint > 0,
          always: !!it.always,
          interval: it.minInterval
        });
      }
      return out;
    }
  };
})();
