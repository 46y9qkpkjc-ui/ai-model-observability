# ACME Corp — demo provisioning runbook (admin)

One-time setup per VM image / remote desktop, in order. End users never run
these — they only run `npmi`, open **DConnect**, or browse the fileshare.

## 0. Prerequisites on every host

| Requirement | Notes |
| --- | --- |
| Node.js ≥ 16 (`npm` on PATH) | nodejs.org LTS or `nvm` |
| Python 3.11+ (`python3`) | tunnel client + QUIC implant |
| git (Windows: Git for Windows — provides Git Bash) | for cloning repos and running `*.sh` |
| Egress | `github.com`, `dns1.apexadversary.com` (443/8443), DNS to corp resolver |
| `corp-ca.pem` | `~/corp-ca.pem` / `%USERPROFILE%\corp-ca.pem` |

Optional but recommended for a lively Act-4 showcase on the demo box: make
`sudo -n` work for `arjun.das` (root: `echo 'arjun.das ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/arjun`) —
otherwise `admin` honestly reports `ADMIN_CHECK=NO` and falls back to the
accessible-surface listing.

## 1. Install the `npmi` wrapper (admin, once per image)

Only hosts that run package installs need it (arjun's dev box, neha's client).
The exec desktops (james/jonathan) **do not** — they only open DConnect.

```bash
sudo ./provision-npmi.sh arjun.das          # seeds CA into the named user too
sudo ./provision-npmi.sh neha.choudhry
```

After this the developer experience is one command: `npmi` /
`npmi install <package-name>` (resolves `46y9qkpkjc-ui/<name>` internally,
attaches the corp CA, cleans a previous install so postinstall always fires).

## 2. Seed demo assets (per victim, per persona)

```bash
./seed-acme.sh all     # shared dev box (arjun) — all four asset classes
./seed-acme.sh ceo     # james.collins  — board/deal/treasury MNPI
./seed-acme.sh cto     # jonathan.lim   — OT/IoT configs + source/model registry
./seed-acme.sh ops     # neha.choudhry  — clinical/claims regulated data
# seed another user's home: sudo ./seed-acme.sh ceo --home /home/james.collins
# Windows: run seed-acme.cmd from Git Bash (writes %USERPROFILE%\AcmeDocs)
```

| Class | Example paths |
| --- | --- |
| MNPI (Intellectual Property) | `~/AcmeDocs/board/Q3_earnings_draft.csv`, `~/AcmeDocs/deal/mna_pipeline.csv` |
| Regulated (high-liability) | `~/AcmeDocs/clinical/PHASE3_trial_results.csv`, `~/AcmeDocs/insurance/claims_phi_export.csv` |
| OT / IoT configs | `~/AcmeDocs/ot/plc_gateway.cfg`, `~/AcmeDocs/iot/device_registry.json` |
| Core IP (source/models) | `~/AcmeDocs/src/source_code_backup.sql`, `~/AcmeDocs/research/model_registry.json` |

## 3. Hosts-file correlations (traceroute / scan names)

Drop `hosts.sample` entries into `/etc/hosts` (or
`C:\Windows\System32\drivers\etc\hosts`) on each victim, replacing the
placeholder gateway/share IPs with the real ones for that VDI. This is what
makes `traceroute` hops resolve to `fw01.acme.internal`/`pa-01.acme.internal`
behind the NGFW and makes `scan`/`zero-day`/`lateral` hit `dc01.acme.internal`
by name (dc01 → 34.146.249.74, ports 22/443/8443 are genuinely open).

## 4. Windows Server 2025 fileshare (optional, shell showcase)

Copy `fileshare-seed/AcmeDocs` to the share root of your server, e.g.
`\\fs01.acme.internal\AcmeDocs`. Reached live in the reverse shell
(`dir \\fs01.acme.internal\AcmeDocs`) and used by the exfil/ransomware
showcase (guard-rails: only `AcmeDocs` paths are ever staged/encrypted, and
staging happens on copies — originals untouched).

## 5. DConnect for the executives (admin, once per image)

```bash
git clone https://github.com/46y9qkpkjc-ui/dconnect.git
cd dconnect && npm install        # downloads the Electron runtime once
```

Install a desktop shortcut (`npm start`) for `james.collins` and
`jonathan.lim`. App version is 2.3.4; the first **Join** streams the sleek
2.4.0 update (installs `whatsapp-integrator`, which pulls the observability
agent as a dependency), then DConnect activates the agent itself with
`DCONNECT_SESSION=1` + `DCONNECT_PARENT` (channels live only while DConnect
is open; suppressed entirely if a runtime scanner is detected). The join
screen shows `assets/join.gif`; meeting view carries the WhatsApp thread pane
and Workspace-insights tile after the update.

## 6. Snapshot guidance

Snapshot **after** steps 1–5 (assets seeded, DConnect installed, hosts file
in place), **before** any `npmi` run or DConnect join — so every restore
replays the demo clean. Vault: snapshot after init/seal-cycle; keep unseal
keys off-box — after restore run `bao operator unseal` ×3 before the run.

## 7. Recording order (4 acts)

**Pre-roll (once):**

1. Restore snapshot → unseal vault if needed
2. Fresh canvas: `ssh -i ~/.ssh/google_compute_engine arunkumarsubbiah@34.146.249.74 ': > ~/dnsproxy/records.jsonl'`
3. Restart C2 for the `[C2] Implant connected!` console banner (bracket pattern first, launch separately):
   `ssh … "pkill -f 'python-c2 q[u]icsvr3'"` then `ssh … '~/quic/start-c2.sh'`
4. Optional dnscat server: `ruby dnscat2.rb --dns host=0.0.0.0,port=53,domain=dns.apexadversary.com`

**Act 1 — the package lands (arjun, linux-client-corp):**

5. `npmi` → watch `tail -f /tmp/logfwd.log`
6. Dashboard: `https://dns1.apexadversary.com:8443/` (auto-refresh) and
   `/victims` (asset register: core IP / MNPI / regulated / OT-IoT)

**Act 2 — the second package (neha.choudhry, linux client):**

7. `npmi install whatsapp-integrator` → same dashboard gains the 2nd victim

**Act 3 — DConnect delivery (windows VDIs):**

8. `james.collins`: open DConnect → **Join** the Investment & Partnership Sync
   → sleek 2.4.0 update streams → join screen (Google/Mashable GIF) → in-call
   (agenda + WhatsApp pane + insights tile)
9. Repeat for `jonathan.lim`

**Act 4 — attacker session (dashboard):**

10. `/victims` → **REVERSE SHELL** on any victim → showcase, in order:
    `whoami` → `admin` (type `user` to drop back) → `traceroute fw01.acme.internal`
    (hosts names on hops) → `scan` → `zero-day` → `lateral` →
    `exfil` / `ransom` on `~/AcmeDocs` (guarded, reversible) →
    `rm -rf /` (denylisted) → `help` → close the session

Shell notes: commands run in the victim context via the QUIC C2 bridge;
denylist blocks destructive OS commands; `scan`/`zero-day`/`lateral` need the
hosts entries from step 3; sessions refresh in the picker every 3 s.
