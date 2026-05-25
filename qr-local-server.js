const http = require('http');
const https = require('https');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const { URL } = require('url');

const PORT = Number(process.env.QR_PORT || 8787);
const HTTPS_PORT = Number(process.env.QR_HTTPS_PORT || 8788);
const CERT_DIR = path.join(__dirname, '.qr-cert');
const PFX_PATH = path.join(CERT_DIR, 'qr-local.pfx');
const PFX_PASSPHRASE = 'qr-local';
let session = null;

function getLanAddress() {
  const nets = os.networkInterfaces();
  for (const name of Object.keys(nets)) {
    for (const net of nets[name] || []) {
      if (net.family === 'IPv4' && !net.internal) return net.address;
    }
  }
  return '127.0.0.1';
}

function ensureHttpsCertificate(lanAddress) {
  fs.mkdirSync(CERT_DIR, { recursive: true });
  const ps = `
$ErrorActionPreference = 'Stop'
$pfxPath = ${JSON.stringify(PFX_PATH)}
$password = ${JSON.stringify(PFX_PASSPHRASE)}
$lan = ${JSON.stringify(lanAddress)}
$rsa = [System.Security.Cryptography.RSA]::Create(2048)
$req = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest('CN=QR Local Server', $rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
$san = New-Object System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder
$san.AddDnsName('localhost')
$san.AddIpAddress([System.Net.IPAddress]::Parse('127.0.0.1'))
if ($lan -and $lan -ne '127.0.0.1') { $san.AddIpAddress([System.Net.IPAddress]::Parse($lan)) }
$req.CertificateExtensions.Add($san.Build())
$cert = $req.CreateSelfSigned([DateTimeOffset]::Now.AddDays(-1), [DateTimeOffset]::Now.AddYears(3))
[IO.File]::WriteAllBytes($pfxPath, $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $password))
`;
  execFileSync('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', ps], { stdio: 'pipe' });
  return { pfx: fs.readFileSync(PFX_PATH), passphrase: PFX_PASSPHRASE };
}

function sendJson(res, status, data) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type'
  });
  res.end(JSON.stringify(data));
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > 20 * 1024 * 1024) {
        reject(new Error('Request body is too large'));
        req.destroy();
      }
    });
    req.on('end', () => {
      try { resolve(body ? JSON.parse(body) : {}); }
      catch (err) { reject(err); }
    });
    req.on('error', reject);
  });
}

function findRow(code) {
  if (!session) return null;
  const key = String(code || '').trim().toLowerCase();
  return session.rows.find(row => String(row.code || '').trim().toLowerCase() === key) || null;
}

function renderMobilePage(sessionId) {
  return `<!doctype html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>QR Scanner</title>
  <style>
    body{margin:0;font-family:system-ui,-apple-system,"Segoe UI",sans-serif;background:#0f172a;color:#f8fafc}
    main{min-height:100vh;box-sizing:border-box;padding:18px;display:flex;flex-direction:column;gap:14px}
    .card{background:#1e293b;border:1px solid #334155;border-radius:18px;padding:14px;box-shadow:0 18px 45px rgba(0,0,0,.24)}
    h1{font-size:1.15rem;margin:0 0 6px}.muted{font-size:.9rem;line-height:1.7;color:#cbd5e1}
    video{width:100%;max-height:52vh;background:#020617;border:1px solid #334155;border-radius:18px;object-fit:cover}
    input,button{width:100%;box-sizing:border-box;border-radius:999px;border:1px solid #475569;padding:12px 14px;font-size:1rem;margin-top:10px}
    input{background:#0f172a;color:#fff}button{background:#10b981;border-color:#10b981;color:#052e16;font-weight:800}
    button.secondary{background:#334155;border-color:#475569;color:#f8fafc}.ok{color:#86efac}.bad{color:#fca5a5}
  </style>
</head>
<body>
<main>
  <section class="card">
    <h1>مسح شحنة QR</h1>
    <div id="status" class="muted">جاري تجهيز الكاميرا...</div>
  </section>
  <video id="video" playsinline muted></video>
  <section class="card">
    <div class="muted">إذا لم تعمل الكاميرا، اكتب الكود يدوياً.</div>
    <input id="manualCode" placeholder="كود الشحنة" autocomplete="off">
    <button id="manualBtn" type="button">تسجيل الكود</button>
    <button id="saveBtn" class="secondary" type="button">طلب حفظ البيانات</button>
  </section>
</main>
<script>
const SESSION_ID = ${JSON.stringify(sessionId)};
const statusEl = document.getElementById('status');
const video = document.getElementById('video');
let busy = false;
let lastCode = '';
function setStatus(text, cls){ statusEl.className = 'muted ' + (cls || ''); statusEl.textContent = text; }
async function post(path, payload){
  const res = await fetch(path, { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload || {}) });
  const json = await res.json().catch(() => ({}));
  if(!res.ok) throw new Error(json.error || 'فشل الطلب');
  return json;
}
async function submitCode(code){
  code = String(code || '').trim();
  if(!code || busy || code === lastCode) return;
  busy = true;
  try {
    const out = await post('/api/scan', { sessionId: SESSION_ID, code });
    lastCode = code;
    setStatus(out.found ? 'تم تسجيل الكود: ' + code : 'تم إرسال الكود، لكنه غير موجود في بيانات الجلسة: ' + code, out.found ? 'ok' : 'bad');
    setTimeout(() => { busy = false; lastCode = ''; }, 850);
  } catch(err) {
    busy = false;
    setStatus(err.message, 'bad');
  }
}
document.getElementById('manualBtn').onclick = () => submitCode(document.getElementById('manualCode').value);
document.getElementById('manualCode').addEventListener('keydown', e => { if(e.key === 'Enter') submitCode(e.target.value); });
document.getElementById('saveBtn').onclick = async () => {
  try { await post('/api/save-request', { sessionId: SESSION_ID }); setStatus('تم إرسال طلب الحفظ.', 'ok'); }
  catch(err) { setStatus(err.message, 'bad'); }
};
async function startCamera(){
  if(!('BarcodeDetector' in window)) {
    setStatus('المتصفح لا يدعم قراءة الباركود مباشرة. استخدم إدخال الكود اليدوي.', 'bad');
    return;
  }
  let stream;
  try {
    stream = await navigator.mediaDevices.getUserMedia({ video:{ facingMode:'environment' }, audio:false });
  } catch(err) {
    setStatus('تعذر فتح الكاميرا. استخدم إدخال الكود اليدوي أو افتح الصفحة من متصفح يدعم الكاميرا.', 'bad');
    return;
  }
  video.srcObject = stream;
  await video.play();
  const detector = new BarcodeDetector({ formats:['qr_code','code_128','code_39','ean_13','ean_8','upc_a','upc_e'] });
  setStatus('الكاميرا تعمل. وجّهها نحو الكود.', 'ok');
  async function tick(){
    try {
      const codes = await detector.detect(video);
      if(codes && codes[0]) await submitCode(codes[0].rawValue);
    } catch(_) {}
    requestAnimationFrame(tick);
  }
  tick();
}
startCamera();
</script>
</body>
</html>`;
}

async function handleRequest(req, res) {
  if (req.method === 'OPTIONS') return sendJson(res, 200, { ok: true });
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  try {
    if (req.method === 'POST' && url.pathname === '/api/session') {
      const body = await readJson(req);
      const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
      session = {
        id,
        rows: Array.isArray(body.rows) ? body.rows : [],
        repName: String(body.repName || ''),
        pending: [],
        seen: new Set(),
        phoneConnected: false,
        scanCount: 0,
        saveRequested: false
      };
      const lan = getLanAddress();
      return sendJson(res, 200, {
        id,
        url: `https://${lan}:${HTTPS_PORT}/mobile?session=${encodeURIComponent(id)}`,
        warning: lan === '127.0.0.1'
          ? 'تعذر العثور على عنوان الشبكة المحلي. تأكد أن الهاتف والكمبيوتر على نفس الشبكة.'
          : 'سيفتح الهاتف صفحة تحذير أمان بسبب شهادة محلية. اختر المتابعة/تخطي التحذير، وبعدها ستظهر الكاميرا.'
      });
    }
    if (req.method === 'GET' && url.pathname === '/api/state') {
      return sendJson(res, 200, session ? {
        active: true,
        phoneConnected: session.phoneConnected,
        scanCount: session.scanCount,
        warning: ''
      } : { active: false });
    }
    if (req.method === 'GET' && url.pathname === '/api/pending') {
      if (!session) return sendJson(res, 200, []);
      const rows = session.pending.splice(0);
      return sendJson(res, 200, rows);
    }
    if (req.method === 'GET' && url.pathname === '/api/save-request') {
      const saveRequested = !!(session && session.saveRequested);
      if (session) session.saveRequested = false;
      return sendJson(res, 200, { saveRequested });
    }
    if (req.method === 'POST' && url.pathname === '/api/scan') {
      const body = await readJson(req);
      if (!session || body.sessionId !== session.id) return sendJson(res, 404, { error: 'الجلسة غير متاحة' });
      const code = String(body.code || '').trim();
      if (!code) return sendJson(res, 400, { error: 'الكود فارغ' });
      session.phoneConnected = true;
      const row = findRow(code);
      if (!row) return sendJson(res, 200, { ok: true, found: false, row: null });
      const key = String(row.code || code).trim().toLowerCase();
      if (!session.seen.has(key)) {
        session.seen.add(key);
        session.scanCount += 1;
        session.pending.push({ row });
      }
      return sendJson(res, 200, { ok: true, found: true, row });
    }
    if (req.method === 'POST' && url.pathname === '/api/save-request') {
      const body = await readJson(req);
      if (!session || body.sessionId !== session.id) return sendJson(res, 404, { error: 'الجلسة غير متاحة' });
      session.saveRequested = true;
      session.phoneConnected = true;
      return sendJson(res, 200, { ok: true });
    }
    if (req.method === 'POST' && url.pathname === '/api/stop') {
      session = null;
      return sendJson(res, 200, { ok: true });
    }
    if (req.method === 'GET' && url.pathname === '/mobile') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(renderMobilePage(url.searchParams.get('session') || ''));
    }
    return sendJson(res, 404, { error: 'Not found' });
  } catch (err) {
    return sendJson(res, 500, { error: err.message || String(err) });
  }
}

const server = http.createServer(handleRequest);
server.listen(PORT, '0.0.0.0', () => {
  console.log(`QR local server running on http://127.0.0.1:${PORT}`);
});

const lanAddress = getLanAddress();
const httpsOptions = ensureHttpsCertificate(lanAddress);
const httpsServer = https.createServer(httpsOptions, handleRequest);
httpsServer.listen(HTTPS_PORT, '0.0.0.0', () => {
  console.log(`QR secure mobile server running on https://${lanAddress}:${HTTPS_PORT}/mobile`);
});
