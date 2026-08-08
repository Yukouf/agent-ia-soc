import os
import re
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import remediation_engine
import telegram_bot
import webhook_receiver


class SecurityRegressionTests(unittest.TestCase):
    def test_bot_token_is_not_hardcoded(self):
        source = (ROOT / "telegram_bot.py").read_text(encoding="utf-8")
        hardcoded = re.search(r"BOT_TOKEN\s*=\s*['\"][^'\"]{10,}['\"]", source)
        self.assertIsNone(hardcoded)

    def test_telegram_call_fails_closed_without_token(self):
        with mock.patch.object(telegram_bot, "BOT_TOKEN", ""), mock.patch.object(
            telegram_bot.requests, "post"
        ) as post:
            self.assertIsNone(telegram_bot._call("getMe"))
            post.assert_not_called()

    def test_invalid_alert_level_returns_400(self):
        client = webhook_receiver.app.test_client()
        response = client.post(
            "/webhook/wazuh",
            json={"rule": {"id": "1", "level": "invalid", "description": "test"}},
        )
        self.assertEqual(response.status_code, 400)

    def test_pending_content_is_html_escaped(self):
        malicious = "<script>pwn()</script>"
        stats = {
            "pending_count": 1,
            "approved_count": 0,
            "rejected_count": 0,
            "unsure_count": 0,
            "pending": [
                {
                    "id": "x",
                    "rule_id": malicious,
                    "alert_desc": malicious,
                    "src_ip": malicious,
                    "timestamp": "2026-01-01",
                }
            ],
            "history": [],
        }
        with mock.patch.object(webhook_receiver, "get_pending_stats", return_value=stats):
            page = webhook_receiver._build_page()
        self.assertNotIn(malicious, page)
        self.assertIn("&lt;script&gt;pwn()&lt;/script&gt;", page)

    def test_fp_patterns_and_alert_rows_are_html_escaped(self):
        malicious = "<script>pwn()</script>"
        tracker = {
            "rules": [{"rule_id": malicious, "timestamp": malicious}],
            "recent_fps": [
                {
                    "rule_id": malicious,
                    "description": malicious,
                    "src_ip": malicious,
                    "count": 1,
                    "created": False,
                }
            ],
        }
        alert = {
            "timestamp": "2026-01-01T00:00:00",
            "alert_description": malicious,
            "analysis": {"severity": malicious, "confidence": malicious, "explanation": malicious},
            "action_taken": malicious,
            "details": malicious,
            "success": True,
        }
        empty_pending = {"pending_count": 0, "pending": [], "history": []}
        with mock.patch.object(webhook_receiver, "get_tracker_status", return_value=tracker), mock.patch.object(
            webhook_receiver, "get_pending_stats", return_value=empty_pending
        ), mock.patch.object(webhook_receiver, "_load_alerts", return_value=[alert]):
            page = webhook_receiver._build_page()
        self.assertNotIn(malicious, page)
        self.assertIn("&lt;script&gt;pwn()&lt;/script&gt;", page)

    def test_telegram_approval_message_is_html_escaped(self):
        malicious = "<script>pwn()</script>"
        text = telegram_bot._build_approval_message(
            {
                "rule_id": malicious,
                "alert_desc": malicious,
                "src_ip": malicious,
                "timestamp": "2026-01-01T00:00:00",
            }
        )
        self.assertNotIn(malicious, text)
        self.assertIn("&lt;script&gt;pwn()&lt;/script&gt;", text)

    def test_all_telegram_decision_messages_escape_html(self):
        malicious = '</code><a href="https://attacker.example">texte trompeur</a>'
        entry = {
            "rule_id": malicious,
            "alert_desc": malicious,
            "src_ip": malicious,
            "timestamp": "2026-01-01T00:00:00",
        }
        for action, success in (
            ("approve", True),
            ("approve", False),
            ("reject", True),
            ("reject", False),
            ("unsure", False),
        ):
            for source in ("telegram", "dashboard"):
                with self.subTest(action=action, success=success, source=source):
                    text = telegram_bot._build_decision_message(entry, action, success, source)
                    self.assertNotIn(malicious, text)
                    self.assertIn("&lt;/code&gt;&lt;a href=&quot;", text)

    def test_default_listener_is_localhost(self):
        self.assertEqual(webhook_receiver.WEBHOOK_HOST, "127.0.0.1")

    def test_invalid_ip_never_reaches_subprocess(self):
        with mock.patch.object(remediation_engine.subprocess, "run") as run:
            self.assertFalse(remediation_engine.block_ip("127.0.0.1;touch /tmp/pwn"))
            run.assert_not_called()

    def test_deepseek_receives_alert_as_user_and_policy_as_system(self):
        captured = {}

        def fake_call(prompt, system_prompt, max_tokens=800):
            captured["prompt"] = prompt
            captured["system_prompt"] = system_prompt
            return None

        alert = {"description": "test externe", "level": 5, "src_ip": "203.0.113.9"}
        with mock.patch("ai_engine._call_deepseek", side_effect=fake_call):
            import ai_engine

            ai_engine.analyze_alert(alert)
        self.assertIn('"description": "test externe"', captured["prompt"])
        self.assertTrue(captured["system_prompt"].startswith("Tu es un analyste SOC expert"))

    def test_auto_remediation_is_disabled_by_default(self):
        alert = {"src_ip": "203.0.113.10", "description": "test"}
        analysis = {
            "suggested_action": "block_ip",
            "auto_remediate": True,
            "severity": "critical",
        }
        with mock.patch.object(remediation_engine, "ENABLE_AUTO_REMEDIATION", False), mock.patch.object(
            remediation_engine, "block_ip"
        ) as block, mock.patch.object(remediation_engine, "_log_action") as log_action:
            result = remediation_engine.execute(alert, analysis)
        block.assert_not_called()
        log_action.assert_called_once()
        self.assertFalse(result["auto_remediated"])
        self.assertTrue(result["success"])
        self.assertEqual(result["action"], "create_ticket")


if __name__ == "__main__":
    unittest.main(verbosity=2)
