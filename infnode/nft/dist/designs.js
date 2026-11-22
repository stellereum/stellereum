 
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CARD_SIZE = exports.designs = void 0;
exports.randomPopConfig = randomPopConfig;
exports.drawDesign = drawDesign;
// TON marketplace convention (Getgems etc.): NFT item image ~1000x1000, square.
const W = 1000;
const H = 1000;
const SERIF = 'Fraunces, Georgia, serif';
const MONO = '"Space Mono", ui-monospace, monospace';
// Roboto — the actual font Fragment (Telegram's username NFT marketplace) uses.
const TG_SANS = 'Roboto, "SF Pro Display", system-ui, sans-serif';
function roundRect(ctx, x, y, w, h, r) {
    ctx.beginPath();
    ctx.moveTo(x + r, y);
    ctx.arcTo(x + w, y, x + w, y + h, r);
    ctx.arcTo(x + w, y + h, x, y + h, r);
    ctx.arcTo(x, y + h, x, y, r);
    ctx.arcTo(x, y, x + w, y, r);
    ctx.closePath();
}
function drawGrain(ctx, alpha = 0.035) {
    const imgData = ctx.getImageData(0, 0, W, H);
    const d = imgData.data;
    for (let i = 0; i < d.length; i += 4) {
        const n = (Math.random() - 0.5) * 255 * alpha;
        d[i] += n;
        d[i + 1] += n;
        d[i + 2] += n;
    }
    ctx.putImageData(imgData, 0, 0);
}
function fitText(ctx, text, maxWidth, baseSize, weight = 700) {
    let size = baseSize;
    ctx.font = `${weight} ${size}px ${SERIF}`;
    while (ctx.measureText(text).width > maxWidth && size > 16) {
        size -= 2;
        ctx.font = `${weight} ${size}px ${SERIF}`;
    }
    return size;
}
function truncateMiddle(ctx, text, maxWidth) {
    if (ctx.measureText(text).width <= maxWidth)
        return text;
    const ellipsis = '...';
    let head = Math.ceil(text.length / 2);
    let tail = Math.floor(text.length / 2);
    while (head + tail > 0) {
        const candidate = text.slice(0, head) + ellipsis + text.slice(text.length - tail);
        if (ctx.measureText(candidate).width <= maxWidth)
            return candidate;
        if (head > tail)
            head -= 1;
        else
            tail -= 1;
    }
    return ellipsis;
}
function chrome(ctx, color, label) {
    ctx.fillStyle = color;
    ctx.font = `700 18px ${MONO}`;
    ctx.textAlign = 'left';
    ctx.textBaseline = 'top';
    ctx.fillText(label, 44, 40);
    ctx.textAlign = 'right';
    ctx.fillText('№ 0001', W - 44, 40);
}
// Shared "Bold Tag" style: gradient bg + drifting blobs, a fixed-size username plate
// (long names truncate in the middle with an ellipsis), the provider tag below the
// plate, and the full username reappearing faint at the very bottom of the image.
function drawPop(ctx, cfg, input, t) {
    const { username, provider } = input;
    const cx = W / 2;
    const cy = H / 2;
    const [c1, c2, gx0, gy0, gx1, gy1] = cfg.gradient;
    const g = ctx.createLinearGradient(gx0 * W, gy0 * H, gx1 * W, gy1 * H);
    g.addColorStop(0, c1);
    g.addColorStop(1, c2);
    ctx.fillStyle = g;
    ctx.fillRect(0, 0, W, H);
    for (const s of cfg.shapes) {
        const drift = s.drift ?? 0;
        ctx.save();
        ctx.beginPath();
        if (s.type === 'circle') {
            const ox = s.x * W + Math.sin(t * 0.4) * drift;
            const oy = s.y * H + Math.cos(t * 0.35) * drift;
            ctx.arc(ox, oy, s.r, 0, Math.PI * 2);
        }
        else {
            const ox = s.x * W + Math.sin(t * 0.3) * drift;
            const oy = s.y * H;
            ctx.arc(ox, oy, s.r, s.a0, s.a1);
        }
        ctx.fillStyle = s.color;
        ctx.fill();
        ctx.restore();
    }
    if (cfg.grain)
        drawGrain(ctx, 0.025);
    chrome(ctx, cfg.chromeColor, 'TON NFT');
    const nameSize = 80;
    const barW = W - 120;
    const barH = nameSize + 90;
    const barX = 60;
    const barY = cy - barH / 2 - 90;
    ctx.save();
    ctx.shadowColor = 'rgba(0,0,0,0.35)';
    ctx.shadowBlur = 30;
    ctx.shadowOffsetY = 14;
    roundRect(ctx, barX, barY, barW, barH, 30);
    const barGrad = ctx.createLinearGradient(barX, barY, barX + barW, barY + barH);
    barGrad.addColorStop(0, cfg.plateBg[0]);
    barGrad.addColorStop(1, cfg.plateBg[1]);
    ctx.fillStyle = barGrad;
    ctx.fill();
    ctx.restore();
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillStyle = cfg.plateText;
    ctx.font = `900 ${nameSize}px ${TG_SANS}`;
    const displayName = truncateMiddle(ctx, username, barW - 80);
    ctx.fillText(displayName, cx, barY + barH / 2);
    let tagSize = 56;
    ctx.font = `700 ${tagSize}px ${MONO}`;
    while (ctx.measureText(provider).width > barW - 40 && tagSize > 24) {
        tagSize -= 2;
        ctx.font = `700 ${tagSize}px ${MONO}`;
    }
    ctx.textBaseline = 'alphabetic';
    ctx.fillStyle = cfg.providerText;
    ctx.fillText(provider, cx, barY + barH + 60);
    const fullNameSize = fitText(ctx, username, W - 160, 26, 500);
    ctx.font = `500 ${fullNameSize}px ${MONO}`;
    ctx.fillStyle = cfg.fullNameColor;
    ctx.fillText(username, cx, H - 44);
}
const CONFIGS = {
    coralpop: {
        id: 'coralpop',
        gradient: ['#ff6b52', '#ff6b52', 0, 0, 0, 1],
        shapes: [
            { type: 'circle', x: 0.14, y: 0.86, r: 260, color: '#e8492f', drift: 6 },
            { type: 'circle', x: 0.92, y: 0.1, r: 200, color: '#ffa07a', drift: 8 },
        ],
        plateBg: ['rgba(30,8,4,0.9)', 'rgba(50,15,8,0.9)'],
        plateText: '#ffe4d6',
        providerText: 'rgba(255,228,214,0.85)',
        chromeColor: 'rgba(70,20,10,0.7)',
        fullNameColor: 'rgba(61,15,8,0.55)',
    },
    citruspop: {
        id: 'citruspop',
        gradient: ['#f6e05e', '#8bc34a', 0, 0, 1, 1],
        shapes: [
            { type: 'circle', x: 0.16, y: 0.18, r: 300, color: 'rgba(255,255,255,0.28)', drift: 10 },
            { type: 'circle', x: 0.9, y: 0.92, r: 170, color: '#3f7d20', drift: 6 },
        ],
        plateBg: ['rgba(15,28,5,0.9)', 'rgba(20,40,8,0.9)'],
        plateText: '#ecffd6',
        providerText: 'rgba(236,255,214,0.85)',
        chromeColor: 'rgba(28,61,10,0.65)',
        fullNameColor: 'rgba(28,61,10,0.55)',
        grain: true,
    },
    grapepop: {
        id: 'grapepop',
        gradient: ['#7b2ff7', '#c026d3', 0, 0, 1, 0.2],
        shapes: [
            { type: 'arc', x: 0.5, y: 1.05, r: 480, a0: Math.PI, a1: 0, color: 'rgba(0,0,0,0.22)' },
            { type: 'circle', x: 0.22, y: 0.28, r: 140, color: 'rgba(255,255,255,0.18)', drift: 8 },
        ],
        plateBg: ['rgba(30,10,45,0.85)', 'rgba(45,10,55,0.85)'],
        plateText: '#fdf4ff',
        providerText: 'rgba(253,244,255,0.85)',
        chromeColor: 'rgba(253,244,255,0.65)',
        fullNameColor: 'rgba(253,244,255,0.5)',
    },
    oceanpop: {
        id: 'oceanpop',
        gradient: ['#0f766e', '#22d3ee', 0, 1, 1, 0],
        shapes: [
            { type: 'arc', x: 0.5, y: -0.05, r: 460, a0: 0, a1: Math.PI, color: 'rgba(255,255,255,0.14)' },
            { type: 'circle', x: 0.85, y: 0.8, r: 130, color: 'rgba(6,60,55,0.35)', drift: 6 },
        ],
        plateBg: ['rgba(2,25,22,0.9)', 'rgba(4,45,40,0.9)'],
        plateText: '#d5fff8',
        providerText: 'rgba(213,255,248,0.85)',
        chromeColor: 'rgba(4,48,43,0.6)',
        fullNameColor: 'rgba(4,48,43,0.55)',
        grain: true,
    },
    blushpop: {
        id: 'blushpop',
        gradient: ['#ffd1dc', '#ff8fab', 0, 0, 0.3, 1],
        shapes: [
            { type: 'circle', x: 0.78, y: 0.22, r: 260, color: 'rgba(255,255,255,0.3)', drift: 8 },
            { type: 'circle', x: 0.2, y: 0.9, r: 200, color: '#e05780', drift: 5 },
        ],
        plateBg: ['rgba(50,8,24,0.88)', 'rgba(65,10,32,0.88)'],
        plateText: '#ffe6ee',
        providerText: 'rgba(255,230,238,0.85)',
        chromeColor: 'rgba(107,15,43,0.6)',
        fullNameColor: 'rgba(107,15,43,0.5)',
    },
    boldtag: {
        id: 'boldtag',
        gradient: ['#2dd4bf', '#7c3aed', 0, 0, 0.9, 1],
        shapes: [
            { type: 'circle', x: 0.85, y: 0.15, r: 230, color: 'rgba(255,255,255,0.16)', drift: 8 },
            { type: 'circle', x: 0.1, y: 0.9, r: 200, color: 'rgba(0,0,0,0.18)', drift: 6 },
        ],
        plateBg: ['rgba(10,10,15,0.92)', 'rgba(30,15,45,0.92)'],
        plateText: '#ffffff',
        providerText: 'rgba(255,255,255,0.92)',
        chromeColor: 'rgba(255,255,255,0.7)',
        fullNameColor: 'rgba(255,255,255,0.45)',
    },
};
const RANDOM_LAYOUTS = [
    {
        // coral-like
        shapes: [
            { type: 'circle', x: 0.14, y: 0.86, r: 260, kind: 'dark', alpha: 0.32, drift: 6 },
            { type: 'circle', x: 0.92, y: 0.1, r: 200, kind: 'light', alpha: 0.3, drift: 8 },
        ],
        gradientDir: [0, 0, 0, 1],
    },
    {
        // citrus-like
        shapes: [
            { type: 'circle', x: 0.16, y: 0.18, r: 300, kind: 'light', alpha: 0.28, drift: 10 },
            { type: 'circle', x: 0.9, y: 0.92, r: 170, kind: 'dark', alpha: 0.3, drift: 6 },
        ],
        gradientDir: [0, 0, 1, 1],
        grain: true,
    },
    {
        // grape-like
        shapes: [
            { type: 'arc', x: 0.5, y: 1.05, r: 480, a0: Math.PI, a1: 0, kind: 'dark', alpha: 0.22 },
            { type: 'circle', x: 0.22, y: 0.28, r: 140, kind: 'light', alpha: 0.18, drift: 8 },
        ],
        gradientDir: [0, 0, 1, 0.2],
    },
    {
        // ocean-like
        shapes: [
            { type: 'arc', x: 0.5, y: -0.05, r: 460, a0: 0, a1: Math.PI, kind: 'light', alpha: 0.16 },
            { type: 'circle', x: 0.85, y: 0.8, r: 130, kind: 'dark', alpha: 0.32, drift: 6 },
        ],
        gradientDir: [0, 1, 1, 0],
        grain: true,
    },
    {
        // blush-like
        shapes: [
            { type: 'circle', x: 0.78, y: 0.22, r: 260, kind: 'light', alpha: 0.3, drift: 8 },
            { type: 'circle', x: 0.2, y: 0.9, r: 200, kind: 'dark', alpha: 0.28, drift: 5 },
        ],
        gradientDir: [0, 0, 0.3, 1],
    },
];
function rand(min, max) {
    return min + Math.random() * (max - min);
}
function randomPopConfig() {
    const layout = RANDOM_LAYOUTS[Math.floor(Math.random() * RANDOM_LAYOUTS.length)];
    const h1 = rand(0, 360);
    const analogous = Math.random() < 0.5;
    const h2 = analogous ? h1 + rand(-35, 35) : h1 + rand(120, 200) * (Math.random() < 0.5 ? 1 : -1);
    const s1 = rand(58, 88);
    const l1 = rand(48, 66);
    const s2 = rand(55, 85);
    const l2 = rand(32, 54);
    const c1 = `hsl(${h1.toFixed(0)}, ${s1.toFixed(0)}%, ${l1.toFixed(0)}%)`;
    const c2 = `hsl(${h2.toFixed(0)}, ${s2.toFixed(0)}%, ${l2.toFixed(0)}%)`;
    // Plate is always a tinted-dark glass panel with light text — reads consistently
    // regardless of the background gradient's own brightness.
    const plateBg = [
        `hsla(${h1.toFixed(0)}, 45%, 10%, 0.9)`,
        `hsla(${h2.toFixed(0)}, 40%, 16%, 0.9)`,
    ];
    const plateText = '#ffffff';
    const providerText = 'rgba(255,255,255,0.92)';
    const chromeColor = 'rgba(255,255,255,0.7)';
    const fullNameColor = 'rgba(255,255,255,0.45)';
    const shapes = layout.shapes.map((s) => {
        const color = s.kind === 'light' ? `rgba(255,255,255,${s.alpha})` : `rgba(0,0,0,${s.alpha})`;
        if (s.type === 'circle') {
            return { type: 'circle', x: s.x, y: s.y, r: s.r, color, drift: s.drift };
        }
        return { type: 'arc', x: s.x, y: s.y, r: s.r, a0: s.a0 ?? 0, a1: s.a1 ?? Math.PI, color, drift: s.drift };
    });
    return {
        id: 'randompop',
        gradient: [c1, c2, ...layout.gradientDir],
        shapes,
        plateBg,
        plateText,
        providerText,
        chromeColor,
        fullNameColor,
        grain: layout.grain,
    };
}
exports.designs = [
    { id: 'coralpop', name: 'Coral Pop', description: 'Коралловый флэт, плашка с юзернеймом по центру, тег снизу под ней', plate: true, animated: true },
    { id: 'citruspop', name: 'Citrus Pop', description: 'Жёлто-лаймовый градиент по диагонали, плашка с юзернеймом, тег снизу', plate: true, animated: true },
    { id: 'grapepop', name: 'Grape Pop', description: 'Фиолетово-пурпурный градиент, тёмная дуга снизу как горизонт, плашка с юзернеймом', plate: true, animated: true },
    { id: 'oceanpop', name: 'Ocean Pop', description: 'Изумрудно-бирюзовый градиент, светлая дуга-волна сверху, плашка с юзернеймом', plate: true, animated: true },
    { id: 'blushpop', name: 'Blush Pop', description: 'Розово-пудровый градиент, два пятна по диагонали, плашка с юзернеймом', plate: true, animated: true },
    { id: 'boldtag', name: 'Bold Tag', description: 'Бирюзово-фиолетовый градиент, крупная плашка с юзернеймом Roboto 900', plate: true, animated: true },
    { id: 'randompop', name: '🎲 Random Mix', description: 'Каждый клик — случайный макет + случайный градиент, тот же стиль плашки. Уникальная карточка каждый раз', plate: true, animated: true },
];
function drawDesign(ctx, id, input, t = 0, overrideConfig) {
    ctx.clearRect(0, 0, W, H);
    if (overrideConfig) {
        drawPop(ctx, overrideConfig, input, t);
        return;
    }
    const cfg = CONFIGS[id];
    if (cfg)
        drawPop(ctx, cfg, input, t);
}
exports.CARD_SIZE = { W, H };

