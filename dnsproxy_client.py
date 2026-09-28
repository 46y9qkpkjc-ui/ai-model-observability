#!/usr/bin/env python3
"""dnsproxy_client v2 - TCP-over-DNS, no root/TUN. ACK/NACK reliability + DGA/CDN camouflage.

Query names:  [decoy...].<data>.<seq5>.<session16>.<zone>
  data    = b32( frame XOR keystream, hmac8 ), <=44 chars hostname-like label
  seq     = base36, server acks highest contiguous -> lost upstream frames retransmit
  decoys  = 0-2 random labels, random-looking morphology
Downstream TXT: [u32 chseq][u8 status][u32 ack][zlib?] decrypted per query seq;
  chseq gaps (drop/reorder) -> REQUEST frame retransmits the missing chunk.

   fetch URL [--out FILE] [-d POSTBODY]
   serve [--listen 127.0.0.1:8889]
Options: --server --port --zone --token --via --transport {udp,tcp,doh} [--doh URL]
Transport ladder: udp (native DNS) -> tcp (dns-over-tcp/53) -> doh (POST /dns-query)
"""
import argparse
import base64
import hashlib
import hmac
import http.server
import json
import secrets
import socket
import ssl
import struct
import sys
import time
import urllib.request
import zlib

OPEN, DATA, EOR, POLL, REQUEST, FRAG = 1, 2, 3, 4, 5, 6
ST_MORE, ST_FINAL, ST_ERR = 0, 1, 2
NO_CHSEQ = 0xFFFFFFFF

RAW_MAX = 27
PT_MAX = RAW_MAX - 8
FRAG_HDR = 5
FRAG_DATA = PT_MAX - FRAG_HDR
DNS_TMO = 5.0
DNS_RETRY = 3
POLL_GAP = 0.03
MAX_NACK = 8

B36 = "0123456789abcdefghijklmnopqrstuvwxyz"


def seq_b36(n):
    s = ""
    for _ in range(5):
        s = B36[n % 36] + s
        n //= 36
    return s


def b32e(b):
    return base64.b32encode(bytes(b)).decode("ascii").lower().rstrip("=")


def b32d(s):
    if isinstance(s, bytes):
        s = s.decode("ascii", "replace")
    s = "".join(s.split()).upper()
    return base64.b32decode(s + "=" * ((-len(s)) % 8))


def derive_key(session, token):
    return hashlib.sha256(b"labtun-v2" + token.encode() + session.encode()).digest()


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
        pt = (b"\x01" + comp) if len(comp) < len(pt) else (b"\x00" + pt)
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
    return zlib.decompress(pt[1:]) if pt[:1] == b"\x01" else pt[1:]


def build_query(qname, tid, qtype=16):
    pkt = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 1)
    for lab in qname.split("."):
        b = lab.encode("ascii")
        pkt += bytes([len(b)]) + b
    pkt += b"\x00" + struct.pack(">HH", qtype, 1)
    pkt += b"\x00" + struct.pack(">HHIH", 41, 1232, 0, 0)
    return pkt


def _recvn_py(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def parse_name(buf, pos):
    labels, end, jumped, seen = [], pos, False, set()
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


def parse_response(data):
    if len(data) < 12:
        raise ValueError("short response")
    flags = struct.unpack(">H", data[2:4])[0]
    rcode = flags & 0xF
    ancount = struct.unpack(">H", data[6:8])[0]
    qd = struct.unpack(">H", data[4:6])[0]
    pos = 12
    for _ in range(qd):
        _, pos = parse_name(data, pos)
        pos += 4
    txt = b""
    for _ in range(ancount):
        _, pos = parse_name(data, pos)
        rtype, _, _, rdlen = struct.unpack(">HHIH", data[pos:pos + 10])
        pos += 10
        rdata = data[pos:pos + rdlen]
        pos += rdlen
        if rtype == 16:
            i = 0
            while i < len(rdata):
                ln = rdata[i]
                txt += rdata[i + 1:i + 1 + ln]
                i += 1 + ln
    return rcode, txt


class Tunnel:
    def __init__(self, server, port, zone, dest=None, token="", timeout=DNS_TMO,
                 transport="udp", doh=None):
        self.dest = dest or server
        self.port = port
        self.zone = zone.rstrip(".")
        self.token = token
        self.tmo = timeout
        self.transport = transport
        self.doh = doh
        self.session = secrets.token_hex(8)
        self.key = derive_key(self.session, token)
        self.seq = secrets.randbelow(1 << 20)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(self.tmo)

    def _exchange_udp(self, pkt, tid, retries=DNS_RETRY):
        last = None
        for _ in range(retries):
            try:
                self.sock.sendto(pkt, (self.dest, self.port))
                while True:
                    data, _ = self.sock.recvfrom(4096)
                    if len(data) >= 2 and data[:2] == struct.pack(">H", tid):
                        return data
            except socket.timeout:
                last = "timeout"
            except ValueError as e:
                last = str(e)
        raise RuntimeError(f"dns query failed: {last}")

    def _exchange_tcp(self, pkt, tid):
        with socket.create_connection((self.dest, self.port), timeout=self.tmo) as s:
            s.settimeout(self.tmo)
            s.sendall(struct.pack(">H", len(pkt)) + pkt)
            hdr = _recvn_py(s, 2)
            if hdr is None:
                raise RuntimeError("tcp closed (no header)")
            data = _recvn_py(s, struct.unpack(">H", hdr)[0])
            if data is None:
                raise RuntimeError("tcp closed (no body)")
        return data

    def _exchange_doh(self, pkt, tid):
        if not self.doh:
            raise RuntimeError("doh transport needs --doh URL")
        req = urllib.request.Request(
            self.doh, data=pkt, method="POST",
            headers={"Content-Type": "application/dns-message",
                     "Accept": "application/dns-message",
                     "User-Agent": "dnsproxy/1.0"})
        with urllib.request.urlopen(req, timeout=self.tmo,
                                    context=ssl._create_unverified_context()) as r:
            return r.read()

    def _dns(self, payload_lab, seq, retries=DNS_RETRY):
        decoys = []
        for _ in range(secrets.randbelow(3)):
            n = secrets.randbelow(7) + 6
            decoys.append("".join(secrets.choice("abcdefghijklmnopqrstuvwxyz0123456789")
                                  for _ in range(n)))
        qname = ".".join(decoys + [payload_lab, seq_b36(seq), self.session, self.zone])
        tid = secrets.randbelow(65536)
        pkt = build_query(qname, tid)
        last = None
        for attempt in range(retries):
            try:
                if self.transport == "tcp":
                    data = self._exchange_tcp(pkt, tid)
                elif self.transport == "doh":
                    data = self._exchange_doh(pkt, tid)
                else:
                    data = self._exchange_udp(pkt, tid)
                if len(data) < 2 or data[:2] != struct.pack(">H", tid):
                    raise ValueError("tid mismatch")
                rcode, txt = parse_response(data)
                if rcode != 0:
                    raise ValueError(f"rcode {rcode}")
                if not txt:
                    raise ValueError("empty TXT")
                return txt
            except socket.timeout:
                last = "timeout"
            except RuntimeError as e:
                last = str(e)
                if "catastrophic" in str(e) or "needs --doh" in str(e):
                    raise
            except ValueError as e:
                last = str(e)
        raise RuntimeError(f"dns query failed ({self.transport}): {last}")

    def exchange(self, pt, retries=4):
        """Reliable upstream send of one pt; returns record (chseq,status,ack,data)."""
        seq = self.seq
        self.seq += 1
        for _ in range(retries):
            txt = self._dns(b32e(seal(self.key, 1, seq, pt)), seq)
            try:
                rec = open_seal(self.key, 2, seq, b32d(txt))
            except ValueError:
                continue
            if len(rec) < 5:
                continue
            chseq = struct.unpack(">I", rec[:4])[0]
            status, ack = rec[4], struct.unpack(">I", rec[5:9])[0]
            data = rec[9:]
            if ack < seq:
                continue
            return (None if chseq == NO_CHSEQ else chseq, status, ack, data)
        raise RuntimeError("ack not received (upstream loss)")

    def send_frame(self, frame):
        """Send a full frame (FRAG if needed); returns last record."""
        if len(frame) <= PT_MAX:
            return self.exchange(frame)
        mid = secrets.randbelow(65536)
        total = (len(frame) + FRAG_DATA - 1) // FRAG_DATA
        if total > 255:
            raise RuntimeError("frame too large")
        rec = None
        for i in range(total):
            piece = frame[i * FRAG_DATA:(i + 1) * FRAG_DATA]
            pt = struct.pack(">HB", mid, i) + bytes([total]) + piece
            pt = bytes([FRAG]) + pt
            rec = self.exchange(pt)
        return rec

    def request(self, url, method="GET", body=b"", headers=None, timeout=120.0):
        meta = {"m": method, "u": url, "cl": len(body), "k": self.token,
                "ua": (headers or {}).get("User-Agent", "dnsproxy/1.0")}
        rec = self.send_frame(bytes([OPEN]) + json.dumps(meta).encode())
        out = bytearray()
        expect = 0
        buf = {}
        final = False
        nacked = 0

        def feed(r):
            nonlocal expect, final, nacked
            chseq, status, _ack, data = r
            if status == ST_ERR:
                raise RuntimeError(f"server error: {data.decode('utf-8', 'replace')}")
            if status == ST_FINAL and chseq is None:
                final = True
            if chseq is None:
                return
            if chseq < expect:
                pass
            elif chseq == expect:
                out.extend(data)
                expect += 1
                while expect in buf:
                    out.extend(buf.pop(expect))
                    expect += 1
            else:
                buf[chseq] = data
                if status == ST_FINAL:
                    final = True

        feed(rec)
        if method == "POST" and body:
            for off in range(0, len(body), 64):
                piece = body[off:off + 64]
                feed(self.send_frame(bytes([DATA]) + struct.pack(">I", off) + piece))
        feed(self.send_frame(bytes([EOR])))

        deadline = time.time() + timeout
        while True:
            if time.time() > deadline:
                raise RuntimeError("tunnel timeout")
            if not final:
                rec = self.exchange(bytes([POLL]))
                feed(rec)
                if not rec[3] and rec[1] != ST_FINAL:
                    time.sleep(POLL_GAP)
            if final:
                hi = max(buf) if buf else expect - 1
                if expect > hi:
                    break
                if time.time() > deadline:
                    raise RuntimeError("tunnel timeout (nack)")
                r = self.send_frame(bytes([REQUEST]) + struct.pack(">I", expect))
                feed(r)
                nacked += 1
                if nacked > 64:
                    raise RuntimeError("excessive nack")
        return bytes(out)


def parse_http(raw):
    idx = raw.find(b"\r\n\r\n")
    if idx < 0:
        raise ValueError("malformed response")
    lines = raw[:idx].split(b"\r\n")
    parts = lines[0].decode("latin1").split(" ", 2)
    status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 502
    hdrs = []
    for line in lines[1:]:
        if b":" in line:
            k, v = line.split(b":", 1)
            hdrs.append((k.decode("latin1"), v.decode("latin1").strip()))
    return status, hdrs, raw[idx + 4:]


def tunnel_request(args, url, method="GET", body=b"", headers=None):
    t = Tunnel(args.server, args.port, args.zone, dest=args.via, token=args.token,
               transport=args.transport, doh=args.doh)
    raw = t.request(url, method=method, body=body, headers=headers)
    return parse_http(raw)


def cmd_fetch(args):
    method, body = "GET", b""
    if args.data is not None:
        method, body = "POST", args.data.encode()
    status, _hdrs, resp = tunnel_request(args, args.url, method=method, body=body)
    if args.out:
        with open(args.out, "wb") as f:
            f.write(resp)
        print(f"[+] {args.url} -> {args.out} ({len(resp)} bytes, status {status})")
    else:
        sys.stdout.buffer.write(resp)
    return 0 if 200 <= status < 400 else 1


class ProxyHandler(http.server.BaseHTTPRequestHandler):
    args = None
    protocol_version = "HTTP/1.1"

    def _handle(self, with_body):
        url = self.path
        if not url.startswith(("http://", "https://")):
            host = self.headers.get("Host", "")
            url = f"http://{host}{url}"
        body = b""
        cl = int(self.headers.get("Content-Length", 0) or 0)
        if with_body and cl:
            body = self.rfile.read(cl)
        try:
            status, hdrs, resp = tunnel_request(
                self.args, url,
                method="POST" if with_body else "GET",
                body=body,
                headers={"User-Agent": self.headers.get("User-Agent", "dnsproxy/1.0")})
        except Exception as e:
            msg = f"tunnel error: {e}".encode()
            self.send_response(502)
            self.send_header("Content-Length", str(len(msg)))
            self.end_headers()
            self.wfile.write(msg)
            return
        self.send_response(status)
        for k, v in hdrs:
            if k.lower() in ("transfer-encoding", "connection", "content-length"):
                continue
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)

    def do_GET(self):
        self._handle(False)

    def do_POST(self):
        self._handle(True)

    def log_message(self, fmt, *a):
        sys.stderr.write("[proxy] %s\n" % (fmt % a))


def cmd_serve(args):
    host, _, port = args.listen.rpartition(":")
    ProxyHandler.args = args
    srv = http.server.ThreadingHTTPServer((host or "127.0.0.1", int(port)), ProxyHandler)
    print(f"[*] dnsproxy v2 client proxy on {args.listen} -> {args.dest_display}")
    srv.serve_forever()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--server", required=True)
    p.add_argument("--port", type=int, default=53)
    p.add_argument("--zone", required=True)
    p.add_argument("--via", default=None, help="send queries to this resolver IP instead of direct")
    p.add_argument("--token", required=True)
    p.add_argument("--transport", choices=["udp", "tcp", "doh"], default="udp",
                   help="udp=53 native, tcp=dns-over-tcp/53, doh=POST --doh URL")
    p.add_argument("--doh", default=None,
                   help="DoH endpoint URL, e.g. https://dns1.example.com:8443/dns-query")
    sub = p.add_subparsers(dest="cmd", required=True)

    f = sub.add_parser("fetch", help="one-shot GET/POST through the tunnel")
    f.add_argument("url")
    f.add_argument("--out", "-o")
    f.add_argument("--data", "-d", default=None, help="POST body string")

    s = sub.add_parser("serve", help="local HTTP proxy over the tunnel")
    s.add_argument("--listen", default="127.0.0.1:8889")

    args = p.parse_args()
    if args.transport == "doh" and not args.doh:
        p.error("--transport doh requires --doh URL")
    args.dest_display = (f"doh:{args.doh}" if args.transport == "doh"
                         else f"{args.via or args.server}:{args.port} ({args.transport})")
    if args.cmd == "fetch":
        sys.exit(cmd_fetch(args))
    cmd_serve(args)


if __name__ == "__main__":
    main()
