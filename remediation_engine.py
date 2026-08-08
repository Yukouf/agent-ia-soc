"""
Moteur de remédiation — exécute les actions décidées par l'IA.
"""

import json
import ipaddress
import logging
import os
import subprocess
import time
from datetime import datetime

from wazuh_rule_manager import track_false_positive, deploy_rule, get_tracker_status

logger = logging.getLogger("remediation")

ALERTS_LOG = os.path.join(os.path.dirname(__file__), "alerts_log.json")
ENABLE_AUTO_REMEDIATION = os.environ.get("SOC_ENABLE_AUTO_REMEDIATION", "false").lower() in {
    "1", "true", "yes"
}


def _ensure_log():
    if not os.path.exists(ALERTS_LOG):
        with open(ALERTS_LOG, "w") as f:
            json.dump([], f)


def _append_log(entry: dict):
    _ensure_log()
    try:
        with open(ALERTS_LOG, "r") as f:
            log = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        log = []
    log.append(entry)
    # Keep last 1000 entries
    log = log[-1000:]
    with open(ALERTS_LOG, "w") as f:
        json.dump(log, f, indent=2, ensure_ascii=False)


def _log_action(alert: dict, analysis: dict, action_taken: str, success: bool, details: str = ""):
    entry = {
        "timestamp": datetime.now().isoformat(),
        "alert_rule": alert.get("rule_id", alert.get("description", "unknown")),
        "alert_description": alert.get("description", "")[:200],
        "src_ip": alert.get("src_ip", ""),
        "src_user": alert.get("src_user", ""),
        "analysis": analysis,
        "action_taken": action_taken,
        "success": success,
        "details": details,
    }
    _append_log(entry)


def block_ip(ip: str, temporary: bool = False) -> bool:
    """Bloque une IP via iptables."""
    if not ip:
        return False
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        logger.error("IP invalide refusée")
        return False
    if address.is_loopback or address.is_unspecified or address.is_multicast:
        logger.error(f"IP non bloquable refusée: {address}")
        return False
    canonical_ip = str(address)
    cmd = ["iptables", "-A", "INPUT", "-s", canonical_ip, "-j", "DROP"]
    try:
        subprocess.run(cmd, check=True, capture_output=True, timeout=10)
        if temporary:
            # Schedule unblock in 1 hour
            # canonical_ip provient de ipaddress, jamais de l'entrée brute.
            unblock_cmd = ["sh", "-c", f"sleep 3600 && iptables -D INPUT -s {canonical_ip} -j DROP"]
            subprocess.Popen(unblock_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            logger.info(f"IP {ip} bloquée temporairement (1h)")
        else:
            logger.info(f"IP {ip} bloquée définitivement")
        return True
    except Exception as e:
        logger.error(f"Échec blocage IP {ip}: {e}")
        return False


def silence_alert(alert: dict) -> bool:
    """Loggue le silencement (Wazuh API à connecter si dispo)."""
    logger.info(f"Alerte silencée: {alert.get('description', '')[:80]}")
    return True


def send_slack(webhook_url: str, message: str) -> bool:
    """Envoie une notification Slack."""
    if not webhook_url:
        return False
    import urllib.request
    payload = json.dumps({"text": message}).encode()
    try:
        req = urllib.request.Request(webhook_url, data=payload, headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=10)
        return True
    except Exception:
        return False


def execute(alert: dict, analysis: dict, slack_webhook: str = "") -> dict:
    """
    Exécute l'action de remédiation décidée par l'IA.
    Retourne un rapport.
    """
    action = analysis.get("suggested_action", "create_ticket")
    requested_auto = bool(analysis.get("auto_remediate", False))
    auto = requested_auto and ENABLE_AUTO_REMEDIATION
    ip = alert.get("src_ip", "")
    user = alert.get("src_user", "")
    description = alert.get("description", "")[:120]

    result = {
        "action": action,
        "auto_remediated": auto,
        "success": False,
        "message": "",
    }

    if action == "block_ip" and auto:
        success = block_ip(ip, temporary=False)
        msg = f"🚫 IP {ip} bloquée (définitif)" if success else f"❌ Échec blocage IP {ip}"
        _log_action(alert, analysis, "block_ip", success, msg)
        result["success"] = success
        result["message"] = msg
        if success:
            send_slack(slack_webhook, f"🛡️ *Agent IA SOC*\n{msg}\n→ {description}")

    elif action == "block_ip_temporary" and auto:
        success = block_ip(ip, temporary=True)
        msg = f"⏱️ IP {ip} bloquée temporairement (1h)" if success else f"❌ Échec blocage IP {ip}"
        _log_action(alert, analysis, "block_ip_temporary", success, msg)
        result["success"] = success
        result["message"] = msg
        if success:
            send_slack(slack_webhook, f"🛡️ *Agent IA SOC*\n{msg}\n→ {description}")

    elif action == "silence_alert" and auto:
        success = silence_alert(alert)
        msg = f"🔇 Alerte silencée (FP)"
        _log_action(alert, analysis, "silence_alert", success, msg)
        result["success"] = success
        result["message"] = msg

        # 🔥 AUTO-FP : Track le pattern (la notification Telegram est envoyee par le webhook)
        if analysis.get("is_false_positive"):
            track_false_positive(alert, analysis)
            msg += " 📊 Pattern tracke"
            logger.info(f"📊 FP tracke: {alert.get('rule_id','?')} / {alert.get('src_ip','?')}")

    elif action == "verify_and_escalate":
        msg = f"⚠️ Escalade nécessaire: {description}"
        _log_action(alert, analysis, "verify_and_escalate", True, msg)
        result["success"] = True
        result["message"] = msg
        send_slack(slack_webhook, f"🚨 *Escalade Agent IA*\n{msg}\nNiveau: {analysis.get('severity','?')} / Confiance: {analysis.get('confidence',0)}%")

    else:
        msg = f"📋 Ticket à créer: {description}"
        _log_action(alert, analysis, "create_ticket", True, msg)
        result["action"] = "create_ticket"
        result["auto_remediated"] = False
        result["success"] = True
        result["message"] = msg

    return result
