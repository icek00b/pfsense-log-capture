#!/usr/bin/env python3
"""
pfSense WAN security digest -- EPHEMERAL capture (designed for cron).

Each run:
  1. Binds the UDP syslog port and receives live for a SHORT window,
     early-stopping once the rendered digest is big enough (target_digest)
     OR a wall-clock cap is hit (seconds) OR a raw-byte ceiling is reached.
  2. Builds a SMALL bounded digest in memory.
  3. Writes the raw window to a temp file, then DELETES it before exiting.
     Nothing persists between runs.

Filters (driven by config.yaml) drop noise before it reaches the agent, then
the digest surfaces WAN signals: suricata alerts, DNS queries (with suspicious
TLD flags), firewall block/pass counts, top blocked external scanners, top WAN
destination ports, and internal->external egress on non-standard ports.

LAN IPs, hostnames, and scrubbed source IPs live in config.yaml -- not here.
"""
import argparse
import json
import os
import re
import socket
import sys
import tempfile
import time
from collections import Counter
from datetime import datetime

import common


# [recvISO] [<src ip>:port] <PRI>Mon DD HH:MM:SS proc[pid]: payload
LINE_RE = re.compile(r"^\[(?P<recv>[^\]]+)\]\s+\[(?P<src>[\d.]+):\d+\]\s+<\d+>(?P<msg>.*)$")
SURICATA_RE = re.compile(r"suricata\[\d+\]:\s+(\{.*\})\s*$")
QUAD_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}),(\d{1,3}(?:\.\d{1,3}){3}),(\d+),(\d+)")


def internal(ip):
    return (ip.startswith("192.168.") or ip.startswith("10.") or
            ip.startswith("172.") or ip.startswith("127."))


def parse_recv(ts):
    try:
        return datetime.fromisoformat(ts)
    except Exception:
        return None


class Acc:
    def __init__(self, cfg):
        self.cfg = cfg
        self.wan = cfg["interface"]["wan"]
        self.excl_sub = [s.lower() for s in cfg["exclude"].get("substrings", [])]
        self.excl_ips = set(str(ip) for ip in cfg["exclude"].get("src_ips", []))
        self.excl_ports = set(str(p) for p in cfg["exclude"].get("ports", []))
        self.std_ports = set(int(p) for p in cfg.get("standard_ports", []))
        self.weird_tld = set(t.lower() for t in cfg.get("weird_tlds", []))
        self.total = 0; self.kept = 0; self.noise = 0; self.mqtt = 0; self.nonwan = 0
        self.s_evt = Counter(); self.alerts = []; self.dns_q = Counter()
        self.weird_dns = []; self.fl_block = 0; self.fl_pass = 0
        self.blocked_src = Counter(); self.wan_dstport = Counter(); self.egress_odd = []
        self.first = None; self.last = None

    def _excluded_noise(self, msg, quad):
        low = msg.lower()
        if any(s in low for s in self.excl_sub):
            return True
        if quad:
            sp, dp = quad[2], quad[3]
            if sp in self.excl_ports or dp in self.excl_ports:
                return True
        return False

    def feed(self, line):
        self.total += 1
        m = LINE_RE.match(line.rstrip("\n"))
        if not m:
            return
        recv = parse_recv(m.group("recv"))
        if recv:
            if self.first is None:
                self.first = recv
            self.last = recv
        # drop packets whose sender is an explicitly-excluded (scrubbed) IP
        if m.group("src") in self.excl_ips:
            self.noise += 1
            return
        msg = m.group("msg")
        if any(n in msg for n in ("sendto: Host is down",)):
            self.noise += 1
            return

        sq = SURICATA_RE.search(msg)
        if sq:
            try:
                ev = json.loads(sq.group(1))
            except Exception:
                return
            if ev.get("in_iface", "") != self.wan:
                self.nonwan += 1
                return
            self.kept += 1
            et = ev.get("event_type", "?")
            self.s_evt[et] += 1
            if et == "alert":
                al = ev.get("alert", {})
                self.alerts.append({
                    "t": ev.get("timestamp", ""), "sev": al.get("severity", "?"),
                    "sig": al.get("signature", "?"), "cat": al.get("category", ""),
                    "src": ev.get("src_ip", "?"), "sport": ev.get("src_port", "?"),
                    "dst": ev.get("dest_ip", "?"), "dport": ev.get("dest_port", "?"),
                    "proto": ev.get("proto", "?")})
                if len(self.alerts) > 400:
                    self.alerts.pop(0)
            elif et == "dns":
                d = ev.get("dns", {})
                if d.get("type") == "query":
                    name = d.get("rrname", "")
                    if name:
                        self.dns_q[name] += 1
                        tld = name.rstrip(".").split(".")[-1].lower()
                        if tld in self.weird_tld or len(name.split(".")[0]) > 30:
                            self.weird_dns.append(name)
            return

        if "filterlog[" in msg:
            quad = QUAD_RE.search(msg)
            if self._excluded_noise(msg, quad.groups() if quad else None):
                self.mqtt += 1
                return
            if f",{self.wan}," not in msg:
                self.nonwan += 1
                return
            self.kept += 1
            blocked = ",block," in msg
            passed = ",pass," in msg or ",allow," in msg
            if blocked:
                self.fl_block += 1
            elif passed:
                self.fl_pass += 1
            if quad:
                s, d, sp, dp = quad.groups()
                try:
                    dpp = int(dp)
                except Exception:
                    dpp = -1
                self.wan_dstport[dpp] += 1
                if blocked and not internal(s):
                    self.blocked_src[s] += 1
                if ((not blocked) and internal(s) and (not internal(d))
                        and dpp not in self.std_ports and dpp > 0):
                    self.egress_odd.append((s, d, sp, dpp,
                        "tcp" if ",6," in msg else ("udp" if ",17," in msg else "")))
            return


def render(a, dcfg):
    max_alerts = dcfg.get("max_alerts", 60)
    max_domains = dcfg.get("max_domains", 40)
    max_scanners = dcfg.get("max_scanners", 15)
    max_ports = dcfg.get("max_ports", 15)
    max_egress = dcfg.get("max_egress", 40)
    out = []
    win = ""
    if a.first and a.last:
        win = (f"{a.first:%Y-%m-%d %H:%M} -> {a.last:%Y-%m-%d %H:%M} "
               f"({int((a.last - a.first).total_seconds())}s)")
    out.append(f"WINDOW: {win or 'n/a'}")
    out.append(f"raw_lines={a.total} kept={a.kept} noise={a.noise} "
               f"excluded={a.mqtt} nonwan={a.nonwan}")
    out.append("")
    out.append(f"SURICATA (WAN {a.wan}) event counts: " +
               (", ".join(f"{k}={v}" for k, v in a.s_evt.most_common()) or "none"))
    if a.alerts:
        out.append(f"SURICATA ALERTS ({len(a.alerts)} total, showing last "
                   f"{min(max_alerts, len(a.alerts))}):")
        for al in a.alerts[-max_alerts:]:
            out.append(f"  [sev {al['sev']}] {al['sig']}  "
                       f"{al['src']}:{al['sport']} -> {al['dst']}:{al['dport']} "
                       f"{al['proto']} ({al['cat']})")
    else:
        out.append("SURICATA ALERTS: none")
    out.append("")
    out.append(f"DNS QUERIES (WAN): {len(a.dns_q)} unique domains, "
               f"{sum(a.dns_q.values())} total")
    if a.weird_dns:
        uw = sorted(set(a.weird_dns))
        out.append(f"  SUSPICIOUS domains (weird TLD / very long label): {len(uw)}")
        for n in uw[:25]:
            out.append(f"    ! {n}")
    if a.dns_q:
        out.append("  top domains:")
        for n, c in a.dns_q.most_common(max_domains):
            out.append(f"    {c:>6}  {n}")
    out.append("")
    out.append(f"FILTERLOG (WAN {a.wan}): block={a.fl_block} pass={a.fl_pass}")
    if a.blocked_src:
        out.append("TOP BLOCKED EXTERNAL SOURCES (scanners/unsolicited inbound):")
        for ip, c in a.blocked_src.most_common(max_scanners):
            out.append(f"    {c:>6}  {ip}")
    if a.wan_dstport:
        out.append("TOP WAN DEST PORTS:")
        for p, c in a.wan_dstport.most_common(max_ports):
            out.append(f"    {c:>6}  port {p}")
    if a.egress_odd:
        agg = Counter((s, d, dp) for s, d, sp, dp, pr in a.egress_odd)
        out.append("INTERNAL -> EXTERNAL on NON-STANDARD PORTS "
                   "(possible weird conns / C2):")
        for (s, d, dp), c in agg.most_common(max_egress):
            out.append(f"    {c:>6}  {s} -> {d}:{dp}")
    else:
        out.append("INTERNAL -> EXTERNAL NON-STANDARD PORTS: none")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description="Ephemeral pfSense WAN security digest.")
    ap.add_argument("--config", help="path to config.yaml")
    ap.add_argument("--host", help="bind address (default from config)")
    ap.add_argument("--port", type=int, help="UDP port (default from config)")
    ap.add_argument("--seconds", type=int, help="wall-clock cap for the window")
    ap.add_argument("--target-digest", type=int,
                    help="stop early once the digest reaches this many bytes")
    ap.add_argument("--max-raw", type=int, help="raw byte safety ceiling")
    ap.add_argument("--keep-raw", action="store_true", help="keep temp raw file (debug)")
    args = ap.parse_args()

    cfg = common.load(args.config)
    dcfg = cfg["digest"]
    host = args.host or cfg["listen"]["host"]
    port = args.port or int(cfg["listen"]["port"])
    seconds = args.seconds or int(dcfg.get("seconds", 30))
    target = args.target_digest or int(dcfg.get("target_digest", 8000))
    max_raw = args.max_raw or int(dcfg.get("max_raw", 30000000))
    keep_raw = args.keep_raw or bool(dcfg.get("keep_raw"))

    rawdir = tempfile.mkdtemp(prefix="pfsense_cap_")
    rawpath = os.path.join(rawdir, "pfsense_window.log")
    rawf = open(rawpath, "w")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((host, port))
    except OSError as e:
        print(f"[digest] ERROR bind {host}:{port} failed: {e} "
              f"(is another receiver holding the port?)")
        sys.exit(2)
    sock.settimeout(0.5)

    a = Acc(cfg)
    raw_bytes = 0
    t0 = time.time()
    stop_reason = ""
    while True:
        if time.time() - t0 >= seconds:
            stop_reason = "time-cap"
            break
        try:
            data, addr = sock.recvfrom(65535)
        except socket.timeout:
            if a.total > 0 and len(render(a, dcfg)) >= target:
                stop_reason = "target-digest"
                break
            continue
        except OSError:
            break
        msg = data.decode("utf-8", "replace").strip()
        line = f"[{datetime.now().isoformat()}] [{addr[0]}:{addr[1]}] {msg}"
        rawf.write(line + "\n")
        raw_bytes += len(line) + 1
        a.feed(line)
        if raw_bytes >= max_raw:
            stop_reason = "max-raw"
            break
        if a.total % 200 == 0 and len(render(a, dcfg)) >= target:
            stop_reason = "target-digest"
            break
    sock.close()
    rawf.close()

    if not keep_raw:
        try:
            os.remove(rawpath)
            os.rmdir(rawdir)
        except OSError:
            pass

    if a.total == 0:
        print("WINDOW: no logs received this cycle (pfSense silent or "
              "receiver bound elsewhere)")
        return

    digest = render(a, dcfg)
    print(f"{digest}  | capture: {int(time.time() - t0)}s, "
          f"stop={stop_reason or 'no-data'}")

    state_file = cfg.get("cron", {}).get("state_file", "")
    if state_file:
        try:
            with open(state_file, "w") as sf:
                sf.write(digest)
        except IOError as e:
            print(f"[WARNING] could not write state file: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
