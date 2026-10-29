 
// nft-card-service — рендер NFT-карточек InfMail.
//
// Использует ТОТ ЖЕ designs.ts из nft-card-studio (скомпилированный в dist/)
// + node-canvas (эмуляция браузерного Canvas API). Стиль 100% идентичен студии,
// каждый вызов — случайный вариант (randomPopConfig: 5 layouts + рандомный градиент).
//
// LSB вшивается через pngjs (декодируем PNG → модифицируем RGBA → перекодируем),
// т.к. node-canvas putImageData теряет изменения на canvas 1000×1000.
//
// API:
//   POST /render  { username, tokenId, provider? }  -> image/png
//   POST /render-lsb { username, tokenId, provider?, payload, signature(hex) } -> image/png (LSB)
//   GET  /healthz

const http = require('http')
const { createCanvas } = require('canvas')
const { PNG } = require('pngjs')
const { randomPopConfig, drawDesign, CARD_SIZE } = require('./dist/designs.js')

const { W, H } = CARD_SIZE
const MAGIC = Buffer.from('IMLS')
const VERSION = 0x01

function renderCard(username, tokenId, provider) {
  const canvas = createCanvas(W, H)
  const ctx = canvas.getContext('2d')
  const cfg = randomPopConfig()
  const input = { username, provider: provider || `@${username} · infmail` }
  drawDesign(ctx, cfg.id, input, 0, cfg)
  return canvas
}

// LSB через pngjs: декодируем PNG в RGBA, вшиваем биты, перекодируем.
function embedLsbViaPng(pngBuffer, payloadBytes, sigHex) {
  const png = PNG.sync.read(pngBuffer)
  const p = png.data
  const sig = Buffer.from(sigHex, 'hex')
  if (sig.length !== 64) throw new Error('signature must be 64 bytes hex')

  function writeBits(startBit, data) {
    for (let j = 0; j < data.length; j++) {
      for (let i = 0; i < 8; i++) {
        const bit = (data[j] >> (7 - i)) & 1
        p[startBit + j * 8 + i] = (p[startBit + j * 8 + i] & 0xfe) | bit
      }
    }
  }

  const header = Buffer.concat([
    MAGIC,
    Buffer.from([VERSION]),
    Buffer.from([(payloadBytes.length >> 8) & 0xff, payloadBytes.length & 0xff]),
  ])
  writeBits(0, header)
  writeBits((4 + 1 + 2) * 8, payloadBytes)
  writeBits((4 + 1 + 2 + payloadBytes.length) * 8, sig)
  return PNG.sync.write(png)
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let body = ''
    req.on('data', (c) => { body += c; if (body.length > 1024 * 1024) { reject(new Error('body too large')); req.destroy() } })
    req.on('end', () => { try { resolve(JSON.parse(body || '{}')) } catch (e) { reject(e) } })
    req.on('error', reject)
  })
}

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === 'GET' && req.url === '/healthz') {
      res.writeHead(200, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ ok: true, service: 'nft-card-service' }))
      return
    }
    if (req.method === 'POST' && req.url === '/render') {
      const data = await readJson(req)
      const { username, tokenId, provider } = data
      if (!username || tokenId === undefined) { res.writeHead(400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'username and tokenId required' })); return }
      const buf = renderCard(String(username), Number(tokenId), provider).toBuffer('image/png')
      res.writeHead(200, { 'Content-Type': 'image/png', 'Content-Length': buf.length })
      res.end(buf)
      return
    }
    if (req.method === 'POST' && req.url === '/render-lsb') {
      const data = await readJson(req)
      const { username, tokenId, provider, payload, signature } = data
      if (!username || tokenId === undefined || !payload || !signature) { res.writeHead(400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'username, tokenId, payload, signature required' })); return }
      const basePng = renderCard(String(username), Number(tokenId), provider).toBuffer('image/png')
      const out = embedLsbViaPng(basePng, Buffer.from(payload, 'utf8'), signature)
      res.writeHead(200, { 'Content-Type': 'image/png', 'Content-Length': out.length })
      res.end(out)
      return
    }
    res.writeHead(404, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({ error: 'not found' }))
  } catch (e) {
    res.writeHead(500, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({ error: String(e && e.message || e) }))
  }
})

const PORT = Number(process.env.NFT_CARD_PORT || 9200)
server.listen(PORT, '127.0.0.1', () => {
  console.log(`nft-card-service listening on http://127.0.0.1:${PORT}`)
})

