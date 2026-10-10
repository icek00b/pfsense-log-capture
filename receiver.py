#!/usr/bin/env python3
"""
pfSense syslog receiver (continuous capture).

Listens for UDP syslog packets forwarded by your pfSense box and writes them to
a rotating log file. Stdlib + PyYAML only.

Settings live in config.yaml (same directory) and every one can be overridden
by a CLI flag below. LAN IPs, hostnames, and source IPs are scrubbed -- configure
them in config.yaml under `exclude.src_ips` and `interface`.

Usage:
    python3 receiver.py                      # use config.yaml
    python3 receiver.py --port 5514          # override listen port
    python3 receiver.py --config /path/x.yaml
    python3 receiver.py --only-wan           # WAN interface traffic only
"""
import argparse
import os
import shutil
import socket
import sys
from datetime import datetime

import common


def main():
    ap = argparse.ArgumentParser(description="Receive syslog from pfSense over UDP.")
    ap.add_argument("--config", help="path to config.yaml")
    ap.add_argument("--host", help="bind address (default from config)")
    ap.add_argument("--port", type=int, help="UDP port (default from config)")
    ap.add_argument("--dump", help="log file path to append (default from config)")
    ap.add_argument("--max-size", type=int, help="bytes before rotation (from config)")
    ap.add_argument("--only-wan", action="store_true",
                    help="only keep lines mentioning the WAN interface")
    args = ap.parse_args()

    cfg = common.load(args.config)
    host = args.host or cfg["listen"]["host"]
    port = args.port or int(cfg["listen"]["port"])
    dump = args.dump or cfg["receiver"].get("dump")
    max_size = args.max_size or int(cfg["receiver"].get("max_size", 10485760))
    only_wan = args.only_wan or bool(cfg.get("include", {}).get("only_wan"))
    wan_if = cfg.get("interface", {}).get("wan", "igb3")

    excl = cfg.get("exclude", {})
    excl_ips = set(str(ip) for ip in excl.get("src_ips", []))
    excl_sub = [s.lower() for s in excl.get("substrings", [])]
    excl_ports = set(int(p) for p in excl.get("ports", []))

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((host, port))
    except OSError as e:
        print(f"[ERROR] Failed to bind to {host}:{port}: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Syslog receiver listening on {host}:{port}")
    print(f"[*] Accepting packets from any source")
    if only_wan:
        print(f"[*] Filtering to WAN interface '{wan_if}' only")
    if excl_ips or excl_sub or excl_ports:
        print(f"[*] Excluding: src_ips={sorted(excl_ips)} "
              f"substrings={len(excl_sub)} ports={sorted(excl_ports)}")

    log_file = None
    if dump:
        try:
            log_file = open(dump, "a")
            print(f"[*] Logging to file: {dump} (rotates at {max_size} bytes)")
        except IOError as e:
            print(f"[ERROR] Could not open log file {dump}: {e}", file=sys.stderr)
            sys.exit(1)

    print("[*] Press Ctrl+C to stop\n")

    def excluded(src_ip, msg):
        if src_ip in excl_ips:
            return True
        low = msg.lower()
        if any(s in low for s in excl_sub):
            return True
        if any(f":{p}" in msg or f",{p}," in msg for p in excl_ports):
            return True
        return False

    try:
        while True:
            data, addr = sock.recvfrom(65535)
            msg = data.decode("utf-8", errors="replace").strip()
            src_ip = addr[0]

            if excluded(src_ip, msg):
                continue
            if only_wan and wan_if not in msg:
                continue

            line = f"[{datetime.now().isoformat()}] [{src_ip}:{addr[1]}] {msg}"
            print(line)
            if log_file:
                try:
                    log_file.write(line + "\n")
                    log_file.flush()
                    if os.path.getsize(dump) > max_size:
                        rotated = f"{dump}.{datetime.now():%Y%m%d%H%M%S}"
                        log_file.close()
                        shutil.move(dump, rotated)
                        log_file = open(dump, "a")
                        print(f"[{datetime.now().isoformat()}] Log rotated to: {rotated}")
                except IOError as e:
                    print(f"[WARNING] Failed to write to log file: {e}", file=sys.stderr)
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
    finally:
        sock.close()
        if log_file:
            log_file.close()
            print(f"[{datetime.now().isoformat()}] Log file closed: {dump}")


if __name__ == "__main__":
    main()
