"""
Module Telegram Bot — Notifications SOC avec boutons d'approbation.
Polling (pas de webhook HTTPS nécessaire), inline keyboards ✅/❌/📊.
"""

import json
import html
import logging
import os
import threading
import time
import uuid
from datetime import datetime

import requests

logger = logging.getLogger("telegram-bot")

BOT_TOKEN = os.environ.get("SOC_TELEGRAM_BOT_TOKEN", "").strip()

PENDING_FILE = os.path.join(os.path.dirname(__file__), "pending_approvals.json")

# Stockage interne
_last_update_id = 0
_bot_chat_ids = set()  # chats connus (decouverts via /start)
_poller_running = False
_CHAT_IDS_FILE = os.path.join(os.path.dirname(__file__), ".bot_chat_ids.json")


def _save_chat_ids():
    """Sauvegarde les chat_ids dans un fichier."""
    try:
        with open(_CHAT_IDS_FILE, "w") as f:
            json.dump({"chat_ids": list(_bot_chat_ids)}, f)
    except Exception:
        pass


def _load_chat_ids():
    """Charge les chat_ids depuis le fichier."""
    global _bot_chat_ids
    try:
        with open(_CHAT_IDS_FILE) as f:
            data = json.load(f)
            _bot_chat_ids = set(data.get("chat_ids", []))
    except (FileNotFoundError, json.JSONDecodeError):
        _bot_chat_ids = set()


# ─── CRUD pending approvals ───

def _ensure_pending():
    if not os.path.exists(PENDING_FILE):
        with open(PENDING_FILE, "w") as f:
            json.dump({"pending": [], "history": []}, f, indent=2)


def _load_pending() -> dict:
    _ensure_pending()
    try:
        with open(PENDING_FILE) as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return {"pending": [], "history": []}


def _save_pending(data: dict):
    with open(PENDING_FILE, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def add_pending(pattern_key: str, rule: dict, alert: dict, analysis: dict) -> dict:
    """Ajoute une approbation en attente et retourne l'entrée créée."""
    data = _load_pending()
    entry = {
        "id": str(uuid.uuid4())[:8],
        "key": pattern_key,
        "rule_id": rule["rule_id"],
        "rule_xml": rule["xml"],
        "alert_desc": alert.get("description", "")[:100],
        "src_ip": alert.get("src_ip", ""),
        "timestamp": datetime.now().isoformat(),
        "status": "pending",  # pending | approved | rejected
        "telegram_msg_id": None,
        "chat_id": None,
    }
    data["pending"].append(entry)
    _save_pending(data)
    return entry


def get_pending() -> list:
    data = _load_pending()
    return [p for p in data["pending"] if p["status"] == "pending"]


def approve_pending(pending_id: str) -> bool:
    """Approuve une entrée pending. Retourne le rule dict si OK."""
    data = _load_pending()
    for entry in data["pending"]:
        if entry["id"] == pending_id and entry["status"] == "pending":
            entry["status"] = "approved"
            data["history"].append(dict(entry))
            entry["resolved_at"] = datetime.now().isoformat()
            _save_pending(data)
            return True
    return False


def reject_pending(pending_id: str) -> bool:
    """Rejette une entrée pending."""
    data = _load_pending()
    for entry in data["pending"]:
        if entry["id"] == pending_id and entry["status"] == "pending":
            entry["status"] = "rejected"
            entry["resolved_at"] = datetime.now().isoformat()
            data["history"].append(dict(entry))
            _save_pending(data)
            return True
    return False


def _mark_unsure(pending_id: str) -> bool:
    """Marque une entrée comme incertaine (pas de règle, pas de blocage)."""
    data = _load_pending()
    for entry in data["pending"]:
        if entry["id"] == pending_id and entry["status"] == "pending":
            entry["status"] = "unsure"
            entry["resolved_at"] = datetime.now().isoformat()
            data["history"].append(dict(entry))
            _save_pending(data)
            return True
    return False


def get_telegram_msg_id(pending_id: str) -> int | None:
    """Récupère l'ID du message Telegram associé à une entrée."""
    data = _load_pending()
    for entry in data["pending"] + data.get("history", []):
        if entry["id"] == pending_id:
            return entry.get("telegram_msg_id")
    return None


def get_pending_stats() -> dict:
    """Stats pour le dashboard."""
    data = _load_pending()
    pending = [p for p in data["pending"] if p["status"] == "pending"]
    history = data.get("history", [])
    return {
        "pending_count": len(pending),
        "approved_count": sum(1 for h in history if h.get("status") == "approved"),
        "rejected_count": sum(1 for h in history if h.get("status") == "rejected"),
        "unsure_count": sum(1 for h in history if h.get("status") == "unsure"),
        "pending": [
            {
                "id": p["id"],
                "rule_id": p["rule_id"],
                "alert_desc": p["alert_desc"],
                "src_ip": p["src_ip"],
                "timestamp": p["timestamp"][:19] if p.get("timestamp") else "?",
            }
            for p in pending[-20:]
        ],
        "history": [
            {
                "id": h["id"],
                "rule_id": h["rule_id"],
                "alert_desc": h["alert_desc"],
                "status": h["status"],
                "timestamp": h.get("timestamp", "")[:19],
                "resolved_at": h.get("resolved_at", "")[:19],
            }
            for h in history[-20:]
        ],
    }


# ─── Appels Telegram API ───

def _call(method: str, http_timeout: int = 30, **kwargs) -> dict | None:
    if not BOT_TOKEN:
        logger.error("SOC_TELEGRAM_BOT_TOKEN absent: appel Telegram refusé")
        return None
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/{method}"
    try:
        r = requests.post(url, json=kwargs, timeout=http_timeout)
        data = r.json()
        if data.get("ok"):
            return data.get("result")
        logger.warning(f"Telegram API error {method}: {data}")
        return None
    except Exception as e:
        logger.error(f"Telegram API exception {method}: {e}")
        return None


def send_message(chat_id: int, text: str, reply_markup: dict = None) -> dict | None:
    """Envoie un message texte avec clavier inline optionnel."""
    kwargs = {"chat_id": chat_id, "text": text, "parse_mode": "HTML"}
    if reply_markup:
        kwargs["reply_markup"] = reply_markup
    return _call("sendMessage", **kwargs)


def edit_message(chat_id: int, message_id: int, text: str, reply_markup: dict = None):
    """Édite un message existant."""
    kwargs = {"chat_id": chat_id, "message_id": message_id, "text": text, "parse_mode": "HTML"}
    if reply_markup:
        kwargs["reply_markup"] = reply_markup
    return _call("editMessageText", **kwargs)


def answer_callback(callback_id: str, text: str = ""):
    """Répond au callback (enlève le loading)."""
    return _call("answerCallbackQuery", callback_id=callback_id, text=text)


def get_updates(offset: int = 0, timeout: int = 30) -> list:
    """Recupere les mises a jour (long polling)."""
    result = _call("getUpdates", http_timeout=timeout + 5, offset=offset, timeout=timeout)
    return result if result else []


# ─── Envoi approbation ───

def _build_approval_message(entry: dict) -> str:
    rule_id = html.escape(str(entry.get("rule_id", "")), quote=True)
    alert_desc = html.escape(str(entry.get("alert_desc", "")), quote=True)
    src_ip = html.escape(str(entry.get("src_ip", "")), quote=True)
    timestamp = html.escape(str(entry.get("timestamp", ""))[:19], quote=True)
    return (
        f"🤖 <b>Approbation requise — Règle Wazuh</b>\n\n"
        f"<b>Pattern FP détecté 3×</b>\n"
        f"📋 Règle source : <code>#{rule_id}</code>\n"
        f"🔍 Description : <code>{alert_desc}</code>\n"
        f"🌐 IP source : <code>{src_ip}</code>\n"
        f"🕐 Première occ. : {timestamp}\n\n"
        f"Créer une règle <code>level=\"0\"</code> pour supprimer ce pattern ?"
    )


def _build_decision_message(entry: dict, action: str, success: bool = False, source: str = "telegram") -> str:
    """Construit un message Telegram post-décision avec données non fiables échappées."""
    rule_id = html.escape(str(entry.get("rule_id", "")), quote=True)
    alert_desc = html.escape(str(entry.get("alert_desc", "")), quote=True)
    src_ip = html.escape(str(entry.get("src_ip", "")), quote=True)
    source_label = " (depuis dashboard)" if source == "dashboard" else ""

    if action == "approve" and success:
        return (
            f"✅ <b>RÈGLE CRÉÉE (FP)</b>{source_label}\n\n"
            f"<code>#{rule_id}</code> — <code>level=\"0\"</code>\n"
            f"Pattern : {alert_desc} ({src_ip})\n"
            f"<b>Déployée dans Wazuh manager</b> 🎉\n\n"
            f"Ce type d'alerte ne remontera plus."
        )
    if action == "approve":
        return (
            f"⚠️ <b>Approuvée mais échec déploiement</b>{source_label}\n\n"
            f"<code>#{rule_id}</code>\n"
            f"L'IA SOC va retenter. Vérifie le dashboard."
        )
    if action == "reject":
        block_status = "🚫 IP bloquée temporairement (1h)" if success else "⚠️ IP non bloquée (aucune IP valide)"
        return (
            f"❌ <b>REJETÉE — ATTAQUE RÉELLE</b>{source_label}\n\n"
            f"<code>#{rule_id}</code>\n"
            f"Pattern : {alert_desc} ({src_ip})\n"
            f"{block_status}\n"
            f"⚠️ Pas de règle créée — les alertes continueront de remonter."
        )
    if action == "unsure":
        return (
            f"⏸️ <b>INCATÉGORISÉ</b>{source_label}\n\n"
            f"<code>#{rule_id}</code>\n"
            f"Pattern : {alert_desc} ({src_ip})\n\n"
            f"Aucune action prise. Tu pourras trancher plus tard sur le dashboard."
        )
    raise ValueError(f"Action Telegram inconnue: {action}")


def send_approval_request(entry: dict, chat_id: int = None):
    """
    Envoie une demande d'approbation Telegram.
    Si chat_id est None, envoie à tous les chats connus.
    """
    keyboard = {
        "inline_keyboard": [
            [
                {"text": "✅ Approuver (FP)", "callback_data": f"approve:{entry['id']}"},
                {"text": "❌ Rejeter (Bloquer)", "callback_data": f"reject:{entry['id']}"},
            ],
            [
                {"text": "⏸️ Incertain", "callback_data": f"unsure:{entry['id']}"},
                {"text": "📊 Dashboard SOC", "url": "http://147.79.101.212:5000"},
            ],
        ]
    }

    text = _build_approval_message(entry)
    targets = [chat_id] if chat_id else list(_bot_chat_ids)

    for cid in targets:
        msg = send_message(cid, text, reply_markup=keyboard)
        if msg:
            entry["telegram_msg_id"] = msg.get("message_id")
            entry["chat_id"] = cid
            # Persiste le msg_id dans le fichier
            data = _load_pending()
            for e in data["pending"]:
                if e["id"] == entry["id"]:
                    e["telegram_msg_id"] = msg["message_id"]
                    e["chat_id"] = cid
                    break
            _save_pending(data)


def send_simple_notification(chat_id: int, text: str):
    """Envoie une notification simple (pour alertes critiques)."""
    keyboard = {
        "inline_keyboard": [
            [{"text": "📊 Dashboard SOC", "url": "http://147.79.101.212:5000"}],
        ]
    }
    send_message(chat_id, text, reply_markup=keyboard)


# ─── Polling loop ───

def start_poller(app):
    """Demarre le thread de polling Telegram en arriere-plan."""
    global _poller_running
    if _poller_running:
        return

    # Charge les chat_ids persistes
    _load_chat_ids()

    _poller_running = True
    thread = threading.Thread(
        target=_poll_loop,
        args=(app,),
        daemon=True,
        name="telegram-poller",
    )
    thread.start()
    logger.info("Telegram poller thread started")


def _poll_loop(app):
    """Boucle de polling qui traite les callbacks."""
    global _last_update_id, _poller_running

    while _poller_running:
        try:
            updates = get_updates(offset=_last_update_id + 1, timeout=30)
            for update in updates:
                _last_update_id = update.get("update_id", 0)

                # Message texte (ex: /start)
                msg = update.get("message")
                if msg:
                    chat_id = msg.get("chat", {}).get("id")
                    text = msg.get("text", "")
                    if chat_id:
                        _bot_chat_ids.add(chat_id)
                        _save_chat_ids()
                        if text == "/start":
                            send_message(
                                chat_id,
                                "👋 <b>Freya SOC Bot</b> — Assistant SOC<br>"
                                "Je t'informerai quand une règle Wazuh nécessite ton approbation.<br><br>"
                                "✅ <b>Approuver (FP)</b> → Faux positif, crée une règle <code>level=\"0\"</code> dans Wazuh pour cacher ce pattern<br>"
                                "❌ <b>Rejeter (Bloquer)</b> → Attaque réelle, bloque l'IP temporairement + pas de règle<br>"
                                "⏸️ <b>Incertain</b> → Aucune action, à trancher plus tard sur le dashboard<br><br>"
                                f"📊 Dashboard : <a href='http://147.79.101.212:5000'>SOC Dashboard</a>",
                            )
                        elif text == "/status":
                            stats = get_pending_stats()
                            send_message(
                                chat_id,
                                f"📊 <b>Statut SOC</b>\n"
                                f"En attente : {stats['pending_count']}\n"
                                f"Approuvees (FP) : {stats['approved_count']}\n"
                                f"Rejetees (bloquees) : {stats['rejected_count']}\n"
                                f"Incertaines : {stats['unsure_count']}",
                            )
                    continue

                # Callback (clic sur bouton)
                cb = update.get("callback_query")
                if cb:
                    cb_id = cb.get("id")
                    data = cb.get("data", "")
                    msg_obj = cb.get("message", {})
                    chat_id = msg_obj.get("chat", {}).get("id")
                    message_id = msg_obj.get("message_id")

                    # Répond au callback (enlève loading)
                    answer_callback(cb_id)

                    if chat_id:
                        _bot_chat_ids.add(chat_id)
                        _save_chat_ids()

                    # Traite la donnée
                    with app.app_context():
                        _handle_callback(data, chat_id, message_id)

        except Exception as e:
            logger.error(f"Polling error: {e}")
            time.sleep(5)


def _handle_callback(data: str, chat_id: int, message_id: int):
    """Traite un clic sur bouton inline.
    
    ✅ approve  = FP → crée règle level=0 dans Wazuh
    ❌ reject   = Réel → bloque IP + rien dans Wazuh
    ⏸️ unsure   = Incertain → on touche à rien
    """
    from wazuh_rule_manager import deploy_rule

    if ":" not in data:
        return

    action, pending_id = data.split(":", 1)

    entry_data = _load_pending()
    entry = None
    for e in entry_data["pending"]:
        if e["id"] == pending_id:
            entry = e
            break

    if not entry:
        edit_message(chat_id, message_id, "❌ Cette demande n'existe plus (déjà traitée ou expirée).")
        return

    if entry["status"] != "pending":
        edit_message(
            chat_id, message_id,
            f"⏳ Déjà traitée ({entry['status']}) — rien à faire."
        )
        return

    if action == "approve":
        # ✅ FP → crée une règle level=0 dans Wazuh
        rule = {
            "rule_id": entry["rule_id"],
            "xml": entry["rule_xml"],
        }
        ok = deploy_rule(rule)
        approve_pending(pending_id)

        new_text = _build_decision_message(entry, "approve", ok, "telegram")

        edit_message(chat_id, message_id, new_text)
        logger.info(f"✅ Approbation Telegram: règle #{entry['rule_id']} (ok={ok})")

    elif action == "reject":
        # ❌ Réel → bloque l'IP + pas de règle
        from remediation_engine import block_ip

        ip = entry.get("src_ip", "")
        block_ok = block_ip(ip, temporary=True) if ip else False

        reject_pending(pending_id)

        new_text = _build_decision_message(entry, "reject", block_ok, "telegram")
        edit_message(chat_id, message_id, new_text)
        logger.info(f"❌ Rejet Telegram (attaque réelle): IP {ip} bloquée={block_ok}")

    elif action == "unsure":
        # ⏸️ Incertain → on touche à rien, juste archivé
        _mark_unsure(pending_id)

        new_text = _build_decision_message(entry, "unsure", False, "telegram")
        edit_message(chat_id, message_id, new_text)
        logger.info(f"⏸️ Incertain Telegram: #{entry['rule_id']}")

    # Nettoie le clavier du message édité (enlève les boutons)
    # déjà fait — edit_messageText remplace tout le contenu
