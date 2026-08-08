#!/usr/bin/env python3
"""
Sample alertes Wazuh pour tester l'Agent IA SOC.
Lance le test avec: python3 sample_alerts.py
"""

import json
import urllib.request
import urllib.error
import random

WEBHOOK_URL = "http://localhost:5000/webhook/wazuh"

SAMPLE_ALERTS = [
    # False positive typique — scan réseau
    {
        "rule_id": "100001",
        "level": 7,
        "description": "Nmap scan detecté sur le réseau interne. Source: 10.0.0.45",
        "src_ip": "10.0.0.45",
        "src_user": "",
        "agent_name": "srv-monitoring-01",
    },
    # Attaque brute-force SSH
    {
        "rule_id": "100002",
        "level": 10,
        "description": "Bruteforce SSH detected from 192.168.1.100 - 15 tentatives en 30 secondes sur user root",
        "src_ip": "192.168.1.100",
        "src_user": "root",
        "agent_name": "srv-ssh-01",
    },
    # Attaque SQL injection
    {
        "rule_id": "100003",
        "level": 14,
        "description": "SQL Injection attempt detected: UNION SELECT * FROM users -- dans paramètre GET /api/users?id=1 UNION SELECT * FROM users",
        "src_ip": "203.0.113.50",
        "src_user": "",
        "agent_name": "srv-web-01",
    },
    # Alerte volume élevé (FP prob — test de pénétration)
    {
        "rule_id": "100004",
        "level": 8,
        "description": "Test de pénétration autorisé détecté — scan port 443 sur plage DMZ",
        "src_ip": "10.0.1.99",
        "src_user": "pentest-user",
        "agent_name": "srv-dmz-01",
    },
    # CVE exploitation
    {
        "rule_id": "100005",
        "level": 15,
        "description": "CVE-2024-6387 exploitation attempt detected: Remote code execution via OpenSSH vulnerability",
        "src_ip": "185.220.101.42",
        "src_user": "",
        "agent_name": "srv-mail-01",
    },
    # Ransomware suspect
    {
        "rule_id": "100006",
        "level": 12,
        "description": "Ransomware indicators: multiple file extensions changed to .encrypted in /shared/docs/",
        "src_ip": "192.168.1.200",
        "src_user": "jdupont",
        "agent_name": "srv-files-01",
    },
    # Alerte faible — DNS query suspect
    {
        "rule_id": "100007",
        "level": 4,
        "description": "DNS query for known C2 domain detected: check.darkserver[.]xyz",
        "src_ip": "192.168.1.50",
        "src_user": "",
        "agent_name": "srv-dns-01",
    },
    # Ping flood
    {
        "rule_id": "100008",
        "level": 6,
        "description": "ICMP flood detected from 198.51.100.23 - 5000 pings in 10 seconds",
        "src_ip": "198.51.100.23",
        "src_user": "",
        "agent_name": "srv-monitoring-01",
    },
    # XSS
    {
        "rule_id": "100009",
        "level": 11,
        "description": "XSS attack detected: <script>alert('XSS')</script> in form parameter 'search'",
        "src_ip": "203.0.113.88",
        "src_user": "",
        "agent_name": "srv-web-01",
    },
    # Authentification échouée
    {
        "rule_id": "100010",
        "level": 5,
        "description": "Échec d'authentification AD pour user 'admin' — mauvais mot de passe 3 fois en 5 minutes",
        "src_ip": "192.168.1.150",
        "src_user": "admin",
        "agent_name": "dc-01",
    },
]


def send_alert(alert):
    """Envoie une alerte au webhook."""
    data = json.dumps(alert).encode()
    req = urllib.request.Request(
        WEBHOOK_URL,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read())
    except Exception as e:
        return {"error": str(e)}


def main():
    print(f"🧪 Envoi de {len(SAMPLE_ALERTS)} alertes de test vers {WEBHOOK_URL}\n")
    for i, alert in enumerate(SAMPLE_ALERTS, 1):
        result = send_alert(alert)
        sev = result.get("analysis", {}).get("severity", "?")
        action = result.get("analysis", {}).get("suggested_action", "?")
        auto = result.get("analysis", {}).get("auto_remediate", False)
        conf = result.get("analysis", {}).get("confidence", "?")
        remed = result.get("remediation", {}).get("message", "?")
        emoji = "⚡" if auto else "📋"
        print(f"  {i}. {emoji} [{sev.upper():8}] {alert['description'][:70]:70} → {action:20} ({conf}%) → {remed}")
    print(f"\n✅ Terminé. Voir les résultats sur http://localhost:5000")


if __name__ == "__main__":
    main()
