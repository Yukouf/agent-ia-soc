"""
Gestionnaire de règles Wazuh — False Positive auto → local_rules.xml.
Quand l'IA détecte N fois le même pattern FP, crée automatiquement
un override dans local_rules.xml du manager Wazuh.
"""

import json
import logging
import os
import re
import subprocess
import time
from datetime import datetime
from pathlib import Path

logger = logging.getLogger("wazuh-rules")

# Fichier de tracking des FP
FP_TRACKER = os.path.join(os.path.dirname(__file__), "fp_tracker.json")

# Seuil : nombre de répétitions du même pattern pour créer une règle
FP_THRESHOLD = 3

# Container Wazuh manager
MANAGER_CONTAINER = "single-node-wazuh.manager"
MANAGER_RULES_PATH = "/var/wazuh-manager/etc/rules/local_rules.xml"

# Intervalle de temps pour considérer que c'est le même incident (12h)
TIME_WINDOW_HOURS = 12


def _ensure_tracker():
    """Crée le fichier tracker si pas existant."""
    if not os.path.exists(FP_TRACKER):
        with open(FP_TRACKER, "w") as f:
            json.dump({"patterns": [], "rules_written": []}, f, indent=2)


def _load_tracker() -> dict:
    _ensure_tracker()
    try:
        with open(FP_TRACKER) as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return {"patterns": [], "rules_written": []}


def _save_tracker(data: dict):
    with open(FP_TRACKER, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def _pattern_key(alert: dict, analysis: dict) -> str:
    """
    Génère une clé unique pour un pattern FP.
    Combine : rule_id + src_ip tronqué /24 + description normalisée.
    """
    rule_id = str(alert.get("rule_id", alert.get("rule", {}).get("id", "0")))
    src_ip = alert.get("src_ip", alert.get("data", {}).get("srcip", "0.0.0.0"))
    # Normalise le /24
    ip_parts = src_ip.split(".")
    ip_net = ".".join(ip_parts[:3]) + ".0" if len(ip_parts) >= 3 else src_ip
    # Normalise la description
    desc = alert.get("description", alert.get("rule", {}).get("description", ""))
    desc_norm = re.sub(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "<IP>", desc)
    desc_norm = re.sub(r"\d+", "<N>", desc_norm)[:60]
    return f"{rule_id}|{ip_net}|{desc_norm}"


def _is_within_window(ts: str) -> bool:
    """Vérifie si le timestamp est dans la fenêtre de TIME_WINDOW_HOURS."""
    if not ts:
        return True
    try:
        t = datetime.fromisoformat(ts)
        delta = datetime.now() - t
        return delta.total_seconds() < TIME_WINDOW_HOURS * 3600
    except ValueError:
        return True


def track_false_positive(alert: dict, analysis: dict) -> dict | None:
    """
    Track un FP et retourne la règle à créer si le seuil est atteint.
    Retourne None si pas encore assez d'occurrences.
    """
    key = _pattern_key(alert, analysis)

    tracker = _load_tracker()
    patterns = tracker.get("patterns", [])

    # Nettoie les entrées trop vieilles (sauf notre pattern en cours)
    patterns = [
        p for p in patterns
        if p.get("key") == key or (
            p.get("occurrences")
            and _is_within_window(p["occurrences"][-1].get("timestamp", ""))
        )
    ]

    # Cherche les occurrences existantes de ce pattern
    existing = [p for p in patterns if p.get("key") == key]
    if existing:
        entry = existing[0]
    else:
        entry = {
            "key": key,
            "rule_id": str(alert.get("rule_id", alert.get("rule", {}).get("id", "?"))),
            "src_ip": alert.get("src_ip", alert.get("data", {}).get("srcip", "?")),
            "description": alert.get("description", alert.get("rule", {}).get("description", "?"))[:100],
            "occurrences": [],
            "created": False,
        }
        patterns.append(entry)

    # Ajoute l'occurrence
    entry["occurrences"].append({
        "timestamp": datetime.now().isoformat(),
        "explanation": analysis.get("explanation", "")[:100],
    })

    # Vérifie si le seuil est atteint ET pas déjà créée
    if len(entry["occurrences"]) >= FP_THRESHOLD and not entry.get("created"):
        rule = _generate_rule(entry)
        if rule:
            entry["created"] = True
            entry["rule_written"] = rule.get("rule_id", "?")
            tracker["rules_written"].append({
                "timestamp": datetime.now().isoformat(),
                "rule_id": rule["rule_id"],
                "pattern": key,
                "content": rule["xml"],
            })
            _save_tracker(tracker)
            return rule

    _save_tracker({"patterns": patterns, "rules_written": tracker.get("rules_written", [])})
    return None


def _generate_rule(entry: dict) -> dict | None:
    """
    Génère le XML d'une règle Wazuh pour supprimer ce FP.
    """
    rule_id = entry.get("rule_id", "?")
    src_ip = entry.get("src_ip", "")
    description = entry.get("description", "")

    # Nettoie la description pour le champ XML
    desc_clean = description.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    # Génère un ID unique pour la règle locale (100000+)
    # On hash le pattern pour avoir un ID stable
    import hashlib
    hash_val = int(hashlib.md5(entry["key"].encode()).hexdigest()[:8], 16) % 900000 + 100000
    new_rule_id = hash_val

    # Construit le match XML
    match_parts = []

    if src_ip and src_ip != "?":
        # Match sur le /24
        ip_parts = src_ip.split(".")
        if len(ip_parts) >= 3:
            ip_net = ".".join(ip_parts[:3])
            match_parts.append(f'    <field name="srcip">{ip_net}\\.</field>')

    # Match sur le texte de la description (sans les IPs variables)
    import re as _re
    desc_match = _re.sub(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "", description)
    desc_match = _re.sub(r"\s+", " ", desc_match).strip()
    # Prend les premiers mots significatifs
    desc_match = desc_match[:80].strip()
    if desc_match and desc_match != desc_clean:
        # Nettoie caractères XML
        desc_match_xml = desc_match.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        match_parts.append(f'    <match>{desc_match_xml}</match>')
    elif desc_match:
        match_parts.append(f'    <match>{desc_clean}</match>')

    # Match sur la règle parente
    match_xml = "\n".join(match_parts) if match_parts else ""

    rule_xml = f"""  <!-- Règle auto-générée par Agent IA SOC le {datetime.now().strftime('%Y-%m-%d %H:%M')} -->
  <!-- Pattern: {desc_clean} ({src_ip}) — {len(entry['occurrences'])} occurrences -->
  <rule id="{new_rule_id}" level="0">
    <if_sid>{rule_id}</if_sid>
{match_xml}
    <description>Auto-FP: {desc_clean}</description>
  </rule>"""

    return {
        "rule_id": str(new_rule_id),
        "xml": rule_xml,
        "target_rule": rule_id,
    }


def deploy_rule(rule: dict) -> bool:
    """
    Déploie la règle dans local_rules.xml du manager Wazuh.
    """
    xml_block = rule["xml"]
    rule_id = rule["rule_id"]

    try:
        # 0. S'assurer que le dossier rules/ existe
        subprocess.run(
            ["docker", "exec", MANAGER_CONTAINER,
             "mkdir", "-p", "/var/wazuh-manager/etc/rules"],
            capture_output=True, timeout=10
        )

        # 1. Récupère le fichier actuel du manager
        result = subprocess.run(
            ["docker", "exec", MANAGER_CONTAINER, "cat", MANAGER_RULES_PATH],
            capture_output=True, text=True, timeout=10
        )

        if result.returncode != 0:
            # Fichier n'existe pas encore → créer
            current_content = """<!--
Wazuh Ruleset Local — Règles locales personnalisées.
Auto-généré par Agent IA SOC — Ne pas éditer manuellement si vous ne savez pas ce que vous faites.
-->
<group name="local_rules">\n\n</group>"""
        else:
            current_content = result.stdout

        # 2. Insère la règle avant la fermeture </group>
        if "</group>" in current_content:
            new_content = current_content.replace("</group>", f"{xml_block}\n</group>")
        else:
            # Fallback: ajouter à la fin
            new_content = current_content + f"\n{xml_block}\n"

        # 3. Écrit le fichier dans le conteneur
        # On utilise docker cp avec un fichier temporaire
        tmp_path = "/tmp/wazuh_local_rules.xml"
        with open(tmp_path, "w") as f:
            f.write(new_content)

        result = subprocess.run(
            ["docker", "cp", tmp_path, f"{MANAGER_CONTAINER}:{MANAGER_RULES_PATH}"],
            capture_output=True, text=True, timeout=10
        )

        if result.returncode != 0:
            logger.error(f"Échec copie local_rules.xml: {result.stderr}")
            return False

        # Permissions
        subprocess.run(
            ["docker", "exec", MANAGER_CONTAINER,
             "chown", "root:wazuh", MANAGER_RULES_PATH],
            capture_output=True, timeout=10
        )
        subprocess.run(
            ["docker", "exec", MANAGER_CONTAINER,
             "chmod", "640", MANAGER_RULES_PATH],
            capture_output=True, timeout=10
        )

        # 4. Reload les règles Wazuh
        # On peut utiliser l'API Wazuh ou restart analysisd
        subprocess.run(
            ["docker", "exec", MANAGER_CONTAINER,
             "/var/ossec/bin/wazuh-control", "restart"],
            capture_output=True, timeout=30
        )

        logger.info(f"✅ Règle #{rule_id} déployée dans Wazuh manager")
        logger.info(f"   Pattern: {rule.get('xml', '')[:100]}...")

        # Nettoie
        os.remove(tmp_path)
        return True

    except Exception as e:
        logger.error(f"❌ Erreur déploiement règle: {e}")
        return False


def get_tracker_status() -> dict:
    """Retourne l'état du tracker pour le dashboard."""
    tracker = _load_tracker()
    return {
        "patterns_tracked": len(tracker.get("patterns", [])),
        "rules_deployed": len(tracker.get("rules_written", [])),
        "threshold": FP_THRESHOLD,
        "recent_fps": [
            {
                "rule_id": p.get("rule_id"),
                "src_ip": p.get("src_ip"),
                "description": p.get("description", "")[:80],
                "count": len(p.get("occurrences", [])),
                "created": p.get("created", False),
            }
            for p in tracker.get("patterns", [])[-10:]
        ],
        "rules": [
            {
                "timestamp": r.get("timestamp"),
                "rule_id": r.get("rule_id"),
            }
            for r in tracker.get("rules_written", [])[-10:]
        ],
    }
