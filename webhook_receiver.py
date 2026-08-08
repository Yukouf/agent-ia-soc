"""
Serveur webhook Wazuh + Dashboard SOC Agent IA.
Reçoit les alertes Wazuh, les analyse via IA, exécute la remédiation.
Dashboard web avec données injectées côté serveur (pas de JS nécessaire).
"""

import json
import html
import logging
import os
from datetime import datetime
from flask import Flask, request, jsonify

from ai_engine import analyze_alert
from remediation_engine import execute, _ensure_log, ALERTS_LOG
from wazuh_rule_manager import get_tracker_status
from telegram_bot import get_pending_stats, start_poller

# Config
logging.basicConfig(level=logging.INFO, format="[SOC Agent] %(asctime)s %(message)s")
logger = logging.getLogger("soc-agent")

app = Flask(__name__)

SLACK_WEBHOOK = os.environ.get("SLACK_WEBHOOK_URL", "")
WEBHOOK_HOST = os.environ.get("SOC_WEBHOOK_HOST", "127.0.0.1")

_ensure_log()


def _load_alerts():
    """Charge les alertes depuis le fichier JSON."""
    try:
        with open(ALERTS_LOG) as f:
            alerts = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        alerts = []
    return alerts


def _compute_stats(alerts):
    """Calcule les stats depuis la liste d'alertes."""
    return {
        "total": len(alerts),
        "auto_count": sum(1 for a in alerts if a.get("analysis", {}).get("auto_remediate")),
        "critical_count": sum(1 for a in alerts if a.get("analysis", {}).get("severity") == "critical"),
        "escalated_count": sum(1 for a in alerts if a.get("action_taken") == "verify_and_escalate"),
        "fp_count": sum(1 for a in alerts if a.get("analysis", {}).get("is_false_positive")),
    }


def _render_alert_row(a):
    """Génère le HTML d'une ligne d'alerte."""
    sev = str((a.get("analysis") or {}).get("severity") or "unknown")
    sev_class = sev if sev in {"low", "medium", "high", "critical", "unknown"} else "unknown"
    conf = str((a.get("analysis") or {}).get("confidence") or "?")
    act = str(a.get("action_taken") or "?")
    ok = a.get("success", False)
    auto = (a.get("analysis") or {}).get("auto_remediate", False)
    ts = (a.get("timestamp") or "")[11:19] if a.get("timestamp") else "?"
    desc = (a.get("alert_description") or a.get("alert_rule") or "")[:120]
    expl = ((a.get("analysis") or {}).get("explanation") or "")
    details = a.get("details") or ""
    src_ip = a.get("src_ip") or ""

    badge = ""
    if ok and act == "silence_alert":
        badge = '<span class="badge badge-silence">🔇 Silencé</span>'
    elif ok and auto:
        badge = '<span class="badge badge-auto">⚡ Auto</span>'
    elif not ok:
        badge = '<span class="badge badge-fail">❌ Échec</span>'
    elif act == "verify_and_escalate":
        badge = '<span class="badge badge-escalate">🚨 Escalade</span>'
    elif ok:
        badge = '<span class="badge badge-success">✅ OK</span>'

    desc_escaped = html.escape(str(desc), quote=True)
    expl_escaped = html.escape(str(expl), quote=True).replace('\n', '<br>')
    details_escaped = html.escape(str(details), quote=True).replace('\n', '<br>')
    sev_escaped = html.escape(sev, quote=True)
    act_escaped = html.escape(act, quote=True)
    conf_escaped = html.escape(conf, quote=True)
    ts_escaped = html.escape(str(ts), quote=True)

    return f"""<tr onclick="this.nextElementSibling.classList.toggle('visible')" style="cursor:pointer">
  <td>{ts_escaped}</td>
  <td class="desc" title="{desc_escaped}">{desc_escaped}</td>
  <td class="severity-{sev_class}">{sev_escaped}</td>
  <td>{act_escaped}</td>
  <td>{conf_escaped}%</td>
  <td>{badge}</td>
  <td>🔽</td>
</tr>
<tr class="detail-row">
  <td colspan="7" class="detail-cell">{expl_escaped}{'<br><br>---<br>' + details_escaped if details else ''}</td>
</tr>"""


_DASHBOARD_JS = """<script>
var AUTO_REFRESH_INTERVAL = setInterval(function() {
  var x = new XMLHttpRequest();
  x.open('GET', '/api/alerts', true);
  x.onload = function() {
    if (x.status === 200) {
      var d = JSON.parse(x.responseText);
      document.querySelectorAll('.stat-card.blue .num')[0].textContent = d.total;
      document.querySelectorAll('.stat-card.green .num')[0].textContent = d.auto_count;
      document.querySelectorAll('.stat-card.red .num')[0].textContent = d.critical_count;
      document.querySelectorAll('.stat-card.purple .num')[0].textContent = d.escalated_count;
      document.querySelectorAll('.stat-card.orange .num')[0].textContent = d.fp_count;
      document.getElementById('status').textContent = '✅ Auto-rafraîchi';
      document.getElementById('update-time').textContent = 'Dernière mise à jour: ' + new Date().toLocaleTimeString('fr-FR', {hour:'2-digit',minute:'2-digit',second:'2-digit'});
    }
  };
  x.send();
});

function approveRule(id) {
  fetch('/api/approve/' + id, {method:'POST'})
    .then(function(r){ return r.json(); })
    .then(function(d){
      var card = document.getElementById('pending-' + id);
      if (card) { card.style.opacity = '0.4'; card.innerHTML = '✅ Approuvee (FP) - #' + d.rule_id; }
      setTimeout(function(){ location.reload(); }, 1500);
    });
}
function rejectRule(id) {
  fetch('/api/reject/' + id, {method:'POST'})
    .then(function(r){ return r.json(); })
    .then(function(d) {
      var card = document.getElementById('pending-' + id);
      if (card) { card.style.opacity = '0.4'; card.innerHTML = '❌ Rejetee - IP bloquee'; }
      setTimeout(function(){ location.reload(); }, 1500);
    });
}
function unsureRule(id) {
  fetch('/api/unsure/' + id, {method:'POST'})
    .then(function(r){ return r.json(); })
    .then(function() {
      var card = document.getElementById('pending-' + id);
      if (card) { card.style.opacity = '0.4'; card.innerHTML = '⏸️ Incertain - aucune action'; }
      setTimeout(function(){ location.reload(); }, 1500);
    });
}
</script>"""


def _build_page():
    """Génère la page HTML complète avec les données injectées."""
    alerts = _load_alerts()
    stats = _compute_stats(alerts)

    rows_html = "\n".join(_render_alert_row(a) for a in reversed(alerts[-200:]))
    fp_status = get_tracker_status()

    rules_html = ""
    for r in fp_status.get("rules", []):
        rule_id = html.escape(str(r.get("rule_id", "")), quote=True)
        rule_ts = html.escape(str(r.get("timestamp", "?"))[:19], quote=True)
        rules_html += f'<div class="rule-card">'
        rules_html += f'  <span class="rule-id">#{rule_id}</span> '
        rules_html += f'  <span class="badge-active">✅ Active</span>'
        rules_html += f'  <span class="rule-date">{rule_ts}</span>'
        rules_html += f'</div>'

    fp_patterns_html = ""
    for p in fp_status.get("recent_fps", []):
        fp_rule = html.escape(str(p.get("rule_id", "")), quote=True)
        fp_desc = html.escape(str(p.get("description", "")), quote=True)
        fp_ip = html.escape(str(p.get("src_ip", "")), quote=True)
        fp_count = html.escape(str(p.get("count", 0)), quote=True)
        created = bool(p.get("created", False))
        fp_patterns_html += f'<div class="rule-card">'
        fp_patterns_html += f'  <span class="rule-id">#{fp_rule}</span> '
        fp_patterns_html += f'  <span class="rule-desc">{fp_desc}</span> '
        fp_patterns_html += f'  <span style="color:{("#3fb950" if created else "#d29922")}">{fp_count}/3'
        fp_patterns_html += f'{" ✅ Règle créée" if created else " en cours"}</span>'
        fp_patterns_html += f'  <span class="rule-date">{fp_ip}</span>'
        fp_patterns_html += f'</div>'

    pending_stats = get_pending_stats()
    pending_html = ""
    for p in pending_stats.get("pending", []):
        pending_id = html.escape(str(p.get("id", "")), quote=True)
        pending_rule = html.escape(str(p.get("rule_id", "")), quote=True)
        pending_desc = html.escape(str(p.get("alert_desc", "")), quote=True)
        pending_ip = html.escape(str(p.get("src_ip", "")), quote=True)
        pending_ts = html.escape(str(p.get("timestamp", "")), quote=True)
        pending_html += f'<div class="rule-card pending-card" id="pending-{pending_id}">'
        pending_html += f'  <div style="display: flex; justify-content: space-between; align-items: center;">'
        pending_html += f'    <div>'
        pending_html += f'      <span class="rule-id">#{pending_rule}</span> '
        pending_html += f'      <span class="rule-desc">{pending_desc}</span>'
        pending_html += f'      <span class="rule-date">({pending_ip})</span>'
        pending_html += f'    </div>'
        pending_html += f'    <div style="display: flex; gap: 6px; flex-wrap: wrap;">'
        pending_html += f'      <button class="btn-approve" onclick="approveRule(\'{pending_id}\')">✅ FP</button>'
        pending_html += f'      <button class="btn-reject" onclick="rejectRule(\'{pending_id}\')">❌ Bloquer</button>'
        pending_html += f'      <button class="btn-unsure" onclick="unsureRule(\'{pending_id}\')">⏸️ ?</button>'
        pending_html += f'    </div>'
        pending_html += f'  </div>'
        pending_html += f'  <span class="rule-date">{pending_ts}</span>'
        pending_html += f'</div>'

    return f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>🤖 Agent IA SOC — Dashboard</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; background: #0d1117; color: #c9d1d9; padding: 16px; }}
  h1 {{ font-size: 1.6rem; margin-bottom: 2px; color: #58a6ff; display: flex; align-items: center; gap: 8px; }}
  .subtitle {{ color: #8b949e; margin-bottom: 16px; font-size: 0.85rem; }}
  .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 10px; margin-bottom: 16px; }}
  .stat-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 12px 8px; text-align: center; }}
  .stat-card .num {{ font-size: 1.8rem; font-weight: 700; }}
  .stat-card .label {{ font-size: 0.75rem; color: #8b949e; margin-top: 2px; }}
  .stat-card.green .num {{ color: #3fb950; }}
  .stat-card.blue .num {{ color: #58a6ff; }}
  .stat-card.orange .num {{ color: #d29922; }}
  .stat-card.red .num {{ color: #f85149; }}
  .stat-card.purple .num {{ color: #bc8cff; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.82rem; }}
  th {{ text-align: left; padding: 8px 6px; border-bottom: 2px solid #30363d; color: #8b949e; text-transform: uppercase; font-size: 0.7rem; letter-spacing: 0.5px; }}
  td {{ padding: 7px 6px; border-bottom: 1px solid #21262d; vertical-align: top; }}
  tr:hover {{ background: #161b22; }}
  .severity-low {{ color: #3fb950; }}
  .severity-medium {{ color: #d29922; }}
  .severity-high {{ color: #f85149; }}
  .severity-critical {{ color: #f85149; font-weight: 700; }}
  .badge {{ display: inline-block; padding: 2px 7px; border-radius: 10px; font-size: 0.7rem; font-weight: 600; white-space: nowrap; }}
  .badge-auto {{ background: #d2992222; color: #d29922; border: 1px solid #d2992233; }}
  .badge-fail {{ background: #f8514922; color: #f85149; border: 1px solid #f8514933; }}
  .badge-success {{ background: #3fb95022; color: #3fb950; border: 1px solid #3fb95033; }}
  .badge-escalate {{ background: #bc8cff22; color: #bc8cff; border: 1px solid #bc8cff33; }}
  .badge-silence {{ background: #8b949e22; color: #8b949e; border: 1px solid #8b949e33; }}
  .desc {{ max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
  .detail-row {{ display: none; }}
  .detail-row.visible {{ display: table-row; }}
  .detail-cell {{ background: #0d1117; padding: 10px; font-family: 'SF Mono', 'Consolas', monospace; font-size: 0.75rem; white-space: pre-wrap; word-break: break-all; }}
  .footer {{ margin-top: 12px; display: flex; justify-content: space-between; align-items: center; }}
  .status {{ color: #8b949e; font-size: 0.8rem; }}
  .refresh-btn {{ background: #21262d; border: 1px solid #30363d; color: #c9d1d9; padding: 6px 14px; border-radius: 6px; cursor: pointer; font-size: 0.82rem; text-decoration: none; }}
  .refresh-btn:hover {{ background: #30363d; }}
  .last-update {{ color: #484f58; font-size: 0.7rem; margin-top: 4px; }}
  h2 {{ font-size: 1.1rem; margin: 16px 0 8px; color: #c9d1d9; }}
  .rule-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 8px 12px; margin-bottom: 6px; font-size: 0.8rem; }}
  .rule-card .rule-id {{ color: #58a6ff; font-weight: 600; }}
  .rule-card .rule-desc {{ color: #8b949e; }}
  .rule-card .rule-date {{ color: #484f58; font-size: 0.7rem; }}
  .rule-card .badge-active {{ background: #3fb95022; color: #3fb950; border: 1px solid #3fb95033; padding: 1px 5px; border-radius: 8px; font-size: 0.65rem; }}
  .btn-approve {{ background: #3fb95022; color: #3fb950; border: 1px solid #3fb95044; padding: 4px 10px; border-radius: 6px; cursor: pointer; font-size: 0.75rem; }}
  .btn-approve:hover {{ background: #3fb95044; }}
  .btn-reject {{ background: #f8514922; color: #f85149; border: 1px solid #f8514944; padding: 4px 10px; border-radius: 6px; cursor: pointer; font-size: 0.75rem; }}
  .btn-reject:hover {{ background: #f8514944; }}
  .pending-card {{ border-left: 3px solid #d29922 !important; }}
  .btn-unsure {{ background: #8b949e22; color: #8b949e; border: 1px solid #8b949e44; padding: 4px 10px; border-radius: 6px; cursor: pointer; font-size: 0.75rem; }}
  .btn-unsure:hover {{ background: #8b949e44; }}
  @media (max-width: 600px) {{ 
    .stats {{ grid-template-columns: repeat(2, 1fr); }}
    th, td {{ font-size: 0.72rem; padding: 5px 4px; }}
    .desc {{ max-width: 110px; }}
    h1 {{ font-size: 1.3rem; }}
  }}
</style>
</head>
<body>
<h1>🤖 Agent IA SOC</h1>
<p class="subtitle">Surveillance • Analyse • Remédiation automatique</p>

<div class="stats">
  <div class="stat-card blue"><div class="num">{stats['total']}</div><div class="label">Alertes reçues</div></div>
  <div class="stat-card green"><div class="num">{stats['auto_count']}</div><div class="label">Remédiées auto</div></div>
  <div class="stat-card red"><div class="num">{stats['critical_count']}</div><div class="label">Critiques</div></div>
  <div class="stat-card purple"><div class="num">{stats['escalated_count']}</div><div class="label">Escaladées</div></div>
  <div class="stat-card orange"><div class="num">{stats['fp_count']}</div><div class="label">False positives</div></div>
</div>

<table>
  <thead>
    <tr><th>Heure</th><th>Description</th><th>Sévérité</th><th>Action</th><th>Conf</th><th>Statut</th><th></th></tr>
  </thead>
  <tbody>
    {rows_html if rows_html else '<tr><td colspan="7" style="text-align:center;color:#484f58;padding:30px">Aucune alerte pour le moment</td></tr>'}
  </tbody>
</table>

<h2>🔧 Règles Wazuh auto-générées (FP)</h2>
{rules_html if rules_html else '<div class="rule-card" style="color:#484f58">Aucune règle créée pour le moment (seuil: 3 FP identiques)</div>'}

<h2>📊 Patterns FP en tracking</h2>
{fp_patterns_html if fp_patterns_html else '<div class="rule-card" style="color:#484f58">Aucun pattern en cours de tracking</div>'}

<h2>⏳ Approbations en attente</h2>
<p style="color:#8b949e;font-size:0.8rem;margin:-4px 0 8px">Clique sur un bouton ou réponds via le bot Telegram</p>
{pending_html if pending_html else '<div class="rule-card" style="color:#484f58">Aucune approbation en attente</div>'}

<div class="footer">
  <span class="status" id="status">✅ Données injectées serveur</span>
  <a href="/" class="refresh-btn">🔄 Rafraîchir</a>
</div>
<p class="last-update" id="update-time">Dernière mise à jour: {datetime.now().strftime('%H:%M:%S')}</p>

{_DASHBOARD_JS}

</body>
</html>"""


# ─── Routes ───

@app.route("/")
def dashboard():
    return _build_page()


@app.route("/api/alerts")
def api_alerts():
    alerts = _load_alerts()
    stats = _compute_stats(alerts)
    fp_status = get_tracker_status()
    return jsonify({
        "alerts": alerts[-200:],
        **stats,
        "fp_rules": fp_status,
    })


@app.route("/api/fp-rules")
def api_fp_rules():
    return jsonify(get_tracker_status())


@app.route("/api/pending-approvals")
def api_pending_approvals():
    """Retourne les approbations en attente et l'historique."""
    return jsonify(get_pending_stats())


@app.route("/api/approve/<pending_id>", methods=["POST"])
def api_approve(pending_id):
    """Approuve la création de règle depuis le dashboard."""
    from telegram_bot import approve_pending
    from wazuh_rule_manager import deploy_rule
    from telegram_bot import _load_pending, get_telegram_msg_id, edit_message, _build_decision_message

    ok = approve_pending(pending_id)
    if not ok:
        return jsonify({"status": "error", "message": "ID introuvable ou déjà traité"}), 404

    # Récupère le XML de la règle et déploie
    data = _load_pending()
    entry = None
    for e in data["pending"] + data.get("history", []):
        if e["id"] == pending_id:
            entry = e
            break

    if entry and entry.get("rule_xml"):
        rule = {"rule_id": entry["rule_id"], "xml": entry["rule_xml"]}
        deploy_ok = deploy_rule(rule)

        # Met à jour le message Telegram si existant
        msg_id = entry.get("telegram_msg_id")
        chat_id = entry.get("chat_id")
        if msg_id and chat_id:
            edit_message(chat_id, msg_id, _build_decision_message(
                entry, "approve", deploy_ok, "dashboard"
            ))

        logger.info(f"✅ Approbation dashboard: règle #{entry['rule_id']} (deploy={deploy_ok})")
        return jsonify({"status": "ok", "rule_id": entry["rule_id"], "deployed": deploy_ok})

    return jsonify({"status": "error", "message": "Règle non trouvée"}), 404


@app.route("/api/bot-status")
def api_bot_status():
    """Debug: etat du bot Telegram."""
    from telegram_bot import _bot_chat_ids, _CHAT_IDS_FILE
    import os
    return jsonify({
        "chat_ids": list(_bot_chat_ids),
        "chat_ids_file": _CHAT_IDS_FILE,
        "file_exists": os.path.exists(_CHAT_IDS_FILE),
        "poller_running": True,
    })


@app.route("/api/reject/<pending_id>", methods=["POST"])
def api_reject(pending_id):
    """Rejette la création de règle depuis le dashboard + bloque IP."""
    from telegram_bot import reject_pending, _load_pending
    from telegram_bot import get_telegram_msg_id, edit_message, _build_decision_message
    from remediation_engine import block_ip

    # Bloque l'IP d'abord
    data = _load_pending()
    entry = None
    for e in data["pending"]:
        if e["id"] == pending_id:
            entry = e
            break

    ip = entry.get("src_ip", "") if entry else ""
    block_ok = block_ip(ip, temporary=True) if ip else False

    ok = reject_pending(pending_id)
    if not ok:
        return jsonify({"status": "error", "message": "ID introuvable ou déjà traité"}), 404

    # Met à jour le message Telegram
    msg_id = entry.get("telegram_msg_id") if entry else None
    chat_id = entry.get("chat_id") if entry else None
    if msg_id and chat_id:
        edit_message(chat_id, msg_id, _build_decision_message(
            entry, "reject", block_ok, "dashboard"
        ))

    logger.info(f"❌ Rejet dashboard (attaque): {pending_id} IP bloquee={block_ok}")
    return jsonify({"status": "ok", "action": "rejected", "pending_id": pending_id, "ip_blocked": block_ok})


@app.route("/api/unsure/<pending_id>", methods=["POST"])
def api_unsure(pending_id):
    """Marque comme incertain depuis le dashboard."""
    from telegram_bot import _mark_unsure, _load_pending
    from telegram_bot import get_telegram_msg_id, edit_message, _build_decision_message

    ok = _mark_unsure(pending_id)
    if not ok:
        return jsonify({"status": "error", "message": "ID introuvable ou déjà traité"}), 404

    data = _load_pending()
    entry = None
    for e in data.get("history", []):
        if e["id"] == pending_id:
            entry = e
            break

    msg_id = entry.get("telegram_msg_id") if entry else None
    chat_id = entry.get("chat_id") if entry else None
    if msg_id and chat_id:
        edit_message(chat_id, msg_id, _build_decision_message(
            entry, "unsure", False, "dashboard"
        ))

    logger.info(f"⏸️ Incertain dashboard: {pending_id}")
    return jsonify({"status": "ok", "action": "unsure", "pending_id": pending_id})


def _send_alert_notification(alert: dict, analysis: dict, report: dict):
    """Envoie une notification Telegram pour chaque alerte non encore traitee."""
    from telegram_bot import add_pending, send_approval_request, _load_pending
    from wazuh_rule_manager import _pattern_key, _generate_rule, _load_tracker

    key = _pattern_key(alert, analysis)

    # Deja en attente d'approbation ?
    pending_data = _load_pending()
    if any(p.get("key") == key and p["status"] == "pending" for p in pending_data["pending"]):
        logger.info(f"⏳ Deja en attente: {key[:60]}")
        return

    # Deja une regle creee pour ce pattern ?
    tracker = _load_tracker()
    if any(p.get("key") == key and p.get("created") for p in tracker.get("patterns", [])):
        logger.info(f"✅ Deja regle Wazuh: {key[:60]}")
        return

    # Genere la regle et envoie la notification
    from wazuh_rule_manager import track_false_positive
    track_false_positive(alert, analysis)

    entry_data = None
    for p in tracker.get("patterns", []):
        if p.get("key") == key:
            entry_data = p
            break

    if not entry_data:
        # Recharge le tracker apres track_false_positive
        tracker = _load_tracker()
        for p in tracker.get("patterns", []):
            if p.get("key") == key:
                entry_data = p
                break

    if entry_data:
        rule = _generate_rule(entry_data)
        if rule:
            entry = add_pending(key, rule, alert, analysis)
            send_approval_request(entry)
            logger.info(f"📨 Notification Telegram envoyee: #{rule.get('rule_id','?')} ({entry['id']})")


@app.route("/webhook/wazuh", methods=["POST"])
def webhook_wazuh():
    """Endpoint qui reçoit les alertes Wazuh."""
    raw = request.get_json(silent=True) or {}

    try:
        level = int(raw.get("rule", {}).get("level", raw.get("level", 0)))
    except (TypeError, ValueError):
        return jsonify({"error": "level must be an integer"}), 400
    
    # Normalise le format Wazuh → format attendu par l'IA
    data = {
        "rule_id": raw.get("rule", {}).get("id", raw.get("rule_id", "?")),
        "level": level,
        "description": raw.get("rule", {}).get("description", raw.get("description", "")),
        "src_ip": raw.get("data", {}).get("srcip", raw.get("src_ip", "")),
        "src_user": raw.get("data", {}).get("srcuser", raw.get("src_user", "")),
        "full_log": raw.get("full_log", ""),
        "agent_name": raw.get("agent", {}).get("name", ""),
        "agent_id": raw.get("agent", {}).get("id", ""),
        "_raw": raw,  # garde l'original pour les logs
    }
    
    logger.info(f"📨 Alerte reçue: {data['rule_id']} — {data['description'][:80]} (IP: {data['src_ip']})")

    analysis = analyze_alert(data)
    logger.info(f"🧠 Analyse: {analysis.get('severity','?')} / confiance={analysis.get('confidence','?')}% / action={analysis.get('suggested_action','?')}")

    report = execute(data, analysis, slack_webhook=SLACK_WEBHOOK)
    logger.info(f"⚡ Résultat: {report.get('message','?')}")

    # 🔥 TOUTES les alertes → notification Telegram (sauf déjà traitées)
    _send_alert_notification(data, analysis, report)

    return jsonify({
        "status": "ok",
        "analysis": analysis,
        "remediation": report,
    })


@app.route("/webhook/test", methods=["POST", "GET"])
def webhook_test():
    """Endpoint de test."""
    if request.method == "GET":
        return """
        <form method="POST">
          <textarea name="alert" rows="10" cols="60">{"rule_id": "100001", "level": 10, "description": "Bruteforce SSH detected from 192.168.1.100", "src_ip": "192.168.1.100"}</textarea><br><br>
          <button type="submit">Tester</button>
        </form>
        """
    data = request.get_json(silent=True) or {}
    if not data:
        try:
            data = json.loads(request.form.get("alert", "{}"))
        except json.JSONDecodeError:
            return jsonify({"error": "Invalid JSON"}), 400

    analysis = analyze_alert(data)
    report = execute(data, analysis, slack_webhook=SLACK_WEBHOOK)
    _send_alert_notification(data, analysis, report)
    return jsonify({"alert": data, "analysis": analysis, "remediation": report})


if __name__ == "__main__":
    # Démarre le poller Telegram (thread bg)
    start_poller(app)

    print("""
╔══════════════════════════════════════════╗
║   🤖 Agent IA SOC — Automatique          ║
║                                          ║
║   Dashboard: http://VIP:5000             ║
║   Webhook:   POST /webhook/wazuh         ║
║   Test:      GET  /webhook/test          ║
╚══════════════════════════════════════════╝
    """)
    app.run(host=WEBHOOK_HOST, port=5000, debug=False)
