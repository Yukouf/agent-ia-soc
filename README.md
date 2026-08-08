# 🤖 Agent IA SOC — Automatisation Wazuh × Telegram × IA

```
 █████╗  ██████╗ ███████╗███╗   ██╗████████╗    ██╗ █████╗     ███████╗ ██████╗  ██████╗
██╔══██╗██╔════╝ ██╔════╝████╗  ██║╚══██╔══╝    ██║██╔══██╗    ██╔════╝██╔═══██╗██╔════╝
███████║██║  ███╗█████╗  ██╔██╗ ██║   ██║       ██║███████║    ███████╗██║   ██║██║
██╔══██║██║   ██║██╔══╝  ██║╚██╗██║   ██║       ██║██╔══██║    ╚════██║██║   ██║██║
██║  ██║╚██████╔╝███████╗██║ ╚████║   ██║       ██║██║  ██║    ███████║╚██████╔╝╚██████╗
╚═╝  ╚═╝ ╚═════╝ ╚════════╝╚═╝  ╚═══╝   ╚═╝       ╚═╝╚═╝  ╚═╝    ╚══════╝ ╚═════╝  ╚═════╝
```

> **Un agent SOC piloté par IA. Reçoit les alertes Wazuh. Analyse via LLM. Demande validation humaine sur Telegram. Exécute la remédiation automatiquement.**

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue?logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.x-black?logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Wazuh](https://img.shields.io/badge/Wazuh-4.x-0077B5?logo=wazuh&logoColor=white)](https://wazuh.com)
[![Telegram](https://img.shields.io/badge/Telegram-Bot-26A5E4?logo=telegram&logoColor=white)](https://core.telegram.org/bots)
[![Tests](https://img.shields.io/badge/Tests-11%2F11%20✓-green)](tests/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 🎯 Le problème

Les SOC N1 passent leur temps à :
- Trier des **faux positifs** (Nmap scans, tentatives légitimes)
- **Copier-coller** des IP dans iptables
- **Attendre** qu'un humain valide chaque action

C'est lent. C'est coûteux. Et 90 % du temps, c'est du bruit.

## 💡 La solution

**Agent IA SOC** ferme la boucle — de la détection à la remédiation — en moins de 30 secondes :

```
Wazuh ──► Webhook ──► IA (analyse) ──► Telegram (validation humaine)
                    │                        │
                    │              ┌─────────┴──────────┐
                    │              │   ✅ APPROVE        │
                    │              │   ❌ REJECT         │
                    │              │   ❓ UNSURE         │
                    │              └─────────┬──────────┘
                    │                        │
                    └──────── Remédiation auto (si approuvé)
```

---

## 🏗️ Architecture

```
┌─────────────┐     ┌──────────────────┐     ┌───────────────┐
│   Wazuh     │────▶│  Flask Webhook   │────▶│  AI Engine    │
│   (SIEM)    │     │  :5000           │     │  (LLM)        │
└─────────────┘     └────────┬─────────┘     └───────┬───────┘
                             │                       │
                             ▼                       ▼
                    ┌──────────────────┐     ┌───────────────┐
                    │  Telegram Bot    │◀────│  Décision     │
                    │  (approbation)   │     │  (auto/man)   │
                    └────────┬─────────┘     └───────────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │  Remédiation     │
                    │  • iptables      │
                    │  • AD disable    │
                    │  • Slack notify  │
                    │  • GLPI ticket   │
                    └──────────────────┘
```

---

## ⚡ Quick Start

```bash
# 1. Cloner
git clone https://github.com/Yukouf/agent-ia-soc.git && cd agent-ia-soc

# 2. Dépendances
pip install flask requests

# 3. Configurer Telegram
export TELEGRAM_BOT_TOKEN="votre_token"
export TELEGRAM_CHAT_IDS='["ID_CHAT_1","ID_CHAT_2"]'

# 4. Lancer
python3 webhook_receiver.py
```

```
╔══════════════════════════════════════════╗
║   🤖 Agent IA SOC — Automatique          ║
║                                          ║
║   Dashboard: http://0.0.0.0:5000         ║
║   Webhook:   POST /webhook/wazuh         ║
║   Test:      GET  /webhook/test          ║
╚══════════════════════════════════════════╝
```

---

## 🧠 Comment ça marche

### 1. Alerte Wazuh → Webhook

Wazuh envoie ses alertes au webhook `/webhook/wazuh` :

```json
{
  "rule": {
    "id": "100002",
    "level": 10,
    "description": "Bruteforce SSH detected from 192.168.1.100"
  },
  "data": {
    "srcip": "192.168.1.100",
    "srcuser": "root"
  }
}
```

### 2. Analyse par IA

L'`ai_engine.py` analyse l'alerte et retourne :

```json
{
  "severity": "high",
  "confidence": 92,
  "explanation": "15 tentatives SSH en 30 secondes depuis une IP externe inconnue. Aucune raison légitime.",
  "suggested_action": "block_ip",
  "is_false_positive": false
}
```

### 3. Validation humaine sur Telegram

> ⚠️ **ALERTE #100002 — BRUTEFORCE SSH**
> IP: `192.168.1.100` | Agent: `srv-web-01`
> **Action suggérée :** `block_ip`
>
> [✅ APPROUVE] [❌ REJETTE] [❓ INCERTAIN]

### 4. Remédiation automatique

Si approuvé, le `remediation_engine.py` exécute :

| Action | Commande |
|---|---|
| `block_ip` | `iptables -A INPUT -s IP -j DROP` |
| `block_ip_temporary` | Blocage 1h puis suppression auto |
| `disable_user_ad` | `net user USER /domain /active:no` |
| `notify_slack` | Alerte Slack |
| `create_ticket_glpi` | Ticket GLPI |

---

## 📊 Dashboard web

Interface minimale, zéro JavaScript requis. Données injectées côté serveur :

- 🔴 **Alertes actives** avec sévérité et confiance
- 📋 **Historique** des remédiations
- 📈 **Statistiques** (faux positifs, actions exécutées)
- 🔍 **Détail** par alerte

---

## 🧪 Tests

```bash
python3 -m unittest discover -s tests -v
```

```
test_auto_remediation_is_disabled_by_default ... ok
test_xss_telegram_approve ...................... ok
test_xss_telegram_reject ....................... ok
test_xss_telegram_unsure ....................... ok
test_xss_dashboard_approve ..................... ok
test_xss_dashboard_reject ...................... ok
test_xss_dashboard_unsure ...................... ok
test_xss_payload_escape ........................ ok
test_fp_tracker_integrity ...................... ok
test_pending_approvals_integrity ............... ok
test_security_headers .......................... ok

Ran 11 tests in 0.024s — OK
```

---

## 🔒 Sécurité

- ✅ Échappement HTML de toutes les données non fiables (XSS)
- ✅ Pas de JavaScript côté client → surface d'attaque réduite
- ✅ Validation des payloads entrants
- ✅ Tests de sécurité automatisés
- ✅ Détection des faux positifs et création automatique de règles Wazuh

---

## 📁 Structure

```
agent-ia-soc/
├── webhook_receiver.py    # Serveur Flask + dashboard + endpoints
├── ai_engine.py            # Analyse IA des alertes
├── remediation_engine.py   # Exécution des actions
├── telegram_bot.py         # Bot Telegram (polling + notifications)
├── wazuh_rule_manager.py   # Gestion des règles de silence Wazuh
├── sample_alerts.py        # Jeu d'alertes de test
├── config.py               # Configuration centralisée
├── test_fp.py              # Test des faux positifs
├── tests/
│   └── test_security.py    # 11 tests de sécurité
├── alerts_log.json         # Log des alertes traitées
├── fp_tracker.json         # Tracker de faux positifs
└── pending_approvals.json  # Approbations en attente
```

---

## 🛣️ Roadmap

- [ ] Intégration native Discord (en plus de Telegram)
- [x] Détection automatique des faux positifs
- [x] Dashboard sans JavaScript
- [ ] Playbooks de remédiation avancés (SOAR)
- [ ] Support multi-tenants
- [ ] Export PDF des rapports d'incidents

---

## ⚖️ Licence

MIT — fais-en ce que tu veux. Fork, améliore, déploie. Juste, crédite l'auteur.

---

*Built with ❤️‍🔥 by [Youssef Guerniou](https://github.com/Yukouf) — parce que les SOC méritent mieux que des copier-coller.*
