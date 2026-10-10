#!/usr/bin/env python3
"""
Shared config loader for the pfSense log capture scripts.

Loads config.yaml (same directory by default) and merges in environment
placeholders so secrets/IPs/domains stay out of the scripts themselves.
PyYAML is required (pip install pyyaml).
"""
import os
import sys

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.stderr.write("[config] PyYAML is required: pip install pyyaml\n")
    raise


DEFAULTS = {
    "listen": {"host": "0.0.0.0", "port": 42069},
    "receiver": {"dump": "pfsense.log", "max_size": 10485760, "timestamp": True},
    "digest": {
        "seconds": 30,
        "target_digest": 8000,
        "max_raw": 30000000,
        "keep_raw": False,
        "max_alerts": 60,
        "max_domains": 40,
        "max_scanners": 15,
        "max_ports": 15,
        "max_egress": 40,
    },
    "interface": {"wan": "igb3", "lan": ["igb1", "igb2"]},
    "include": {"only_wan": True},
    "exclude": {"src_ips": [], "substrings": [], "ports": []},
    "standard_ports": [],
    "weird_tlds": [],
    "cron": {"state_file": ""},
}


def _merge(base, overlay):
    """Recursive dict merge: overlay wins; lists replace, not append."""
    out = dict(base)
    for k, v in (overlay or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def load(path=None):
    """Load config.yaml from an explicit path, $PFSENSE_LOG_CONFIG, or the
    directory of this module. Returns a merged dict (defaults + file)."""
    candidates = []
    if path:
        candidates.append(path)
    env = os.environ.get("PFSENSE_LOG_CONFIG")
    if env:
        candidates.append(env)
    here = os.path.dirname(os.path.abspath(__file__))
    candidates.append(os.path.join(here, "config.yaml"))

    data = {}
    for c in candidates:
        if c and os.path.exists(c):
            with open(c) as f:
                data = yaml.safe_load(f) or {}
            break
    return _merge(DEFAULTS, data)
