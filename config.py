"""Configuration de l'Agent IA SOC Automatique"""

# Port du serveur webhook + dashboard
WEBHOOK_PORT = 5000

# Seuils de décision
CONFIDENCE_AUTO_SILENCE = 90   # False positive → silence auto
CONFIDENCE_AUTO_REMEDIATE = 80  # Low/Med → remediation auto
CONFIDENCE_AUTO_REMEDIATE_HIGH = 90  # High → remediation auto

# Actions de remédiation disponibles
REMEDIATION_ACTIONS = {
    "block_ip": "iptables -A INPUT -s {ip} -j DROP",
    "block_ip_temporary": "iptables -A INPUT -s {ip} -j DROP && (sleep 3600 && iptables -D INPUT -s {ip} -j DROP) &",
    "disable_user_ad": "net user {user} /domain /active:no",
    "silence_alert_wazuh": "curl -k -u {wazuh_user}:{wazuh_pass} -X PUT 'https://{wazuh_host}:55000/rules/silence/{rule_id}'",
    "create_ticket_glpi": "internal",  # traité par le code
    "notify_slack": "internal",        # traité par le code
}

# Wazuh (optionnel — remplir si connecté)
WAZUH_HOST = "localhost"
WAZUH_USER = ""
WAZUH_PASS = ""

# GLPI (optionnel — remplir si connecté)
GLPI_URL = ""
GLPI_API_TOKEN = ""

# Slack webhook (optionnel)
SLACK_WEBHOOK_URL = ""

# Fichier de log pour le dashboard
ALERTS_LOG = "/root/agent-soc-automatique/alerts_log.json"
