"""
Moteur d'analyse IA pour les alertes SOC.
Utilise DeepSeek API si disponible, sinon moteur rule-based.
"""

import json
import os
import re
import subprocess
import urllib.request
import urllib.error

DEEPSEEK_KEY = None

def _load_key():
    global DEEPSEEK_KEY
    if DEEPSEEK_KEY:
        return DEEPSEEK_KEY
    env_path = os.path.expanduser("~/.hermes/.env")
    if os.path.exists(env_path):
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line.startswith("DEEPSEEK_API_KEY="):
                    DEEPSEEK_KEY = line.split("=", 1)[1].strip().strip('"').strip("'")
                    return DEEPSEEK_KEY
    return None


def _call_deepseek(prompt, system_prompt, max_tokens=800):
    """Appelle l'API DeepSeek et retourne le texte."""
    key = _load_key()
    if not key:
        return None

    data = json.dumps({
        "model": "deepseek-chat",
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt}
        ],
        "max_tokens": max_tokens,
        "temperature": 0.1,
        "response_format": {"type": "json_object"}
    }).encode()

    req = urllib.request.Request(
        "https://api.deepseek.com/chat/completions",
        data=data,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {key}"
        },
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read())
            return result["choices"][0]["message"]["content"]
    except Exception as e:
        return None


def _rule_based_analysis(alert):
    """Analyse rule-based quand DeepSeek est indisponible."""
    msg = alert.get("description", "").lower()
    rule_id = str(alert.get("rule_id", ""))
    level = int(alert.get("level", alert.get("rule_level", 0)))
    src_ip = alert.get("src_ip", "")

    result = {
        "is_false_positive": False,
        "severity": "medium",
        "confidence": 70,
        "suggested_action": "create_ticket",
        "explanation": "Analyse rule-based",
        "auto_remediate": False
    }

    # Niveaux critiques
    if level >= 12:
        result["severity"] = "critical"
        result["confidence"] = 85
        result["suggested_action"] = "verify_and_escalate"
    elif level >= 7:
        result["severity"] = "high"
    elif level >= 4:
        result["severity"] = "medium"
    else:
        result["severity"] = "low"

    # False positive patterns
    fp_patterns = [
        (r"scan (de |des )?(ports|réseau)", 0.75),
        (r"nmap|nessus|openvas", 0.85),
        (r"test de (penetration|vulnérabilité)", 0.9),
        (r"ping (flood|sweep|sweep)", 0.7),
        (r"dns (recon|query)", 0.6),
        (r"authentification.*admin.*3 fois", 0.8),
    ]

    # Internal IP prefixes (RFC 1918 + link-local)
    INTERNAL_IPS = ("10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
                    "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.",
                    "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168.")

    # Malicious patterns
    attack_patterns = [
        (r"bruteforce|brute.?force|hydra|medusa", 0.9, "block_ip_temporary"),
        (r"shell.?inject|command.?inject|rce|cve-\d{4}", 0.95, "block_ip"),
        (r"sql.?inject|sqli|union.*select", 0.9, "block_ip"),
        (r"xss|cross.?site|alert\(.*\)", 0.8, "verify_and_escalate"),
        (r"port.*445|eternalblue|smb.*exploit", 0.9, "block_ip"),
        (r"ransomware|maldoc|dropper|loader", 0.95, "isolate_and_escalate"),
    ]

    for pattern, prob in fp_patterns:
        if re.search(pattern, msg):
            result["is_false_positive"] = True
            result["severity"] = "low"
            result["confidence"] = int(prob * 100)
            result["explanation"] = f"FP probable: {msg[:80]}..."
            result["suggested_action"] = "silence_alert"
            result["auto_remediate"] = True
            return result

    # Auth failures depuis IP interne = FP probable
    if src_ip and any(src_ip.startswith(p) for p in INTERNAL_IPS):
        if "authentication failed" in msg or "failed password" in msg.lower():
            result["is_false_positive"] = True
            result["severity"] = "low"
            result["confidence"] = 85
            result["explanation"] = f"FP probable: échec auth depuis IP interne {src_ip}"
            result["suggested_action"] = "silence_alert"
            result["auto_remediate"] = True
            return result

    for pattern, prob, action in attack_patterns:
        if re.search(pattern, msg):
            result["confidence"] = int(prob * 100)
            result["explanation"] = f"Attaque détectée: {pattern} → {action}"
            result["suggested_action"] = action
            if prob >= 0.9 and level >= 10:
                result["auto_remediate"] = True
            return result

    # Si c'est un niveau critique inconnu
    if level >= 10:
        result["confidence"] = 70
        result["explanation"] = f"Alerte niveau {level} non catégorisée, escalade nécessaire"
        result["suggested_action"] = "create_ticket"

    return result


def analyze_alert(alert: dict) -> dict:
    """
    Analyse une alerte Wazuh et retourne :
    - is_false_positive: bool
    - severity: low/medium/high/critical
    - confidence: 0-100
    - suggested_action: str
    - explanation: str
    - auto_remediate: bool
    """
    # Vérification rapide : IP interne = probable FP
    INTERNAL_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                         "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                         "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                         "172.30.", "172.31.", "192.168.", "127.")
    src_ip = alert.get("src_ip", "")
    is_internal = any(src_ip.startswith(p) for p in INTERNAL_PREFIXES)

    # Si IP interne + auth failure → FP direct, pas besoin de DeepSeek
    if is_internal and ("failed password" in str(alert).lower() or "authentication failed" in str(alert).lower()):
        return _rule_based_analysis(alert)

    # On essaie DeepSeek d'abord
    system_prompt = """Tu es un analyste SOC expert. Analyse cette alerte et réponds UNIQUEMENT en JSON:
{
  "is_false_positive": true/false,
  "severity": "low"|"medium"|"high"|"critical",
  "confidence": 0-100,
  "suggested_action": "block_ip"|"block_ip_temporary"|"silence_alert"|"create_ticket"|"verify_and_escalate",
  "explanation": "explication courte en français",
  "auto_remediate": true/false
}
Règles:
- IP source en 10.x, 172.16-31.x, 192.168.x ou 127.x = RÉSEAU INTERNE → is_false_positive=true, silence_alert
- FP + confiance>90 → silence_alert, auto_remediate=true
- Low/Med + confiance>80 → action auto, auto_remediate=true
- Critical + confiance>90 → action auto, auto_remediate=true
- Sinon → create_ticket, auto_remediate=false
- "block_ip" pour attaques claires et graves
- "block_ip_temporary" pour tentatives répétées mais à vérifier
- "verify_and_escalate" si besoin d'analyse humaine
"""

    prompt = json.dumps(alert, indent=2, ensure_ascii=False)
    response = _call_deepseek(prompt, system_prompt)

    if response:
        try:
            # Extract JSON from response
            # Handle markdown code blocks
            cleaned = response.strip()
            if cleaned.startswith("```"):
                cleaned = cleaned.split("\n", 1)[-1]
                cleaned = cleaned.rsplit("```", 1)[0]
            result = json.loads(cleaned)
            # Validate required fields
            required = ["is_false_positive", "severity", "confidence", "suggested_action", "explanation", "auto_remediate"]
            if all(k in result for k in required):
                return result
        except (json.JSONDecodeError, KeyError):
            pass

    # Fallback rule-based
    return _rule_based_analysis(alert)
