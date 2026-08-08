#!/usr/bin/env python3
"""Envoie N alertes Wazuh identiques pour tester le FP auto-tracking."""
import json
import urllib.request
import sys

URL = "http://147.79.101.212:5000/webhook/wazuh"
COUNT = int(sys.argv[1]) if len(sys.argv) > 1 else 3

alert = {
    "rule": {"id": "5760", "level": 5, "description": "sshd: authentication failed."},
    "data": {"srcip": "10.0.0.50"},
    "agent": {"name": "ubuntu-target", "id": "001"},
}

for i in range(1, COUNT + 1):
    req = urllib.request.Request(
        URL,
        data=json.dumps(alert).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        d = json.loads(resp.read())
        a = d.get("analysis", {})
        r = d.get("remediation", {})
        wazuhr = r.get("wazuh_rule", "")
        fp = a.get("is_false_positive", "?")
        action = r.get("action", "?")
        msg = r.get("message", "")[:80]
        w = f" | 🔥 Règle #{wazuhr} créée !!!" if wazuhr else ""
        print(f"#{i}: FP={fp} | act={action} | {msg}{w}")
