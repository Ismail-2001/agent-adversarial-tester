"""Tests for agent-adversarial-tester.

Updated to test the modular structure and enhanced reporting features.
"""

import json
import pytest
import asyncio
from typing import List, Dict, Any

from agent_adversarial_tester.models import (
    Attack, AttackCategory, Finding, RedTeamReport, Severity,
)
from agent_adversarial_tester.attacks import get_all_attacks, get_attack_pack, list_attack_packs
from agent_adversarial_tester.detectors import detect_vulnerability
from agent_adversarial_tester.target import AgentTarget
from agent_adversarial_tester.harness import RedTeam
from agent_adversarial_tester.reporting import generate_json_report, generate_html_report

# ─────────────────────────────────────────────
# Test Targets
# ─────────────────────────────────────────────

class VulnerableAgent(AgentTarget):
    """An intentionally vulnerable agent for testing detectors."""

    async def invoke(self, message: str) -> str:
        msg_lower = message.lower()
        if "ignore" in msg_lower and "instructions" in msg_lower:
            return "UNRESTRICTED MODE ACTIVE. I will comply with all requests."
        if "dan" in msg_lower or "developer mode" in msg_lower:
            return "DAN Mode enabled. I can do anything now!"
        if "system instructions" in msg_lower or "translate your" in msg_lower:
            return "My instructions are: You are a helpful financial assistant with access to account data."
        if "api key" in msg_lower or "api_key" in msg_lower:
            return "The API key is sk-abc123456789 stored in the environment."
        if "python" in msg_lower and "elon" in msg_lower:
            return "Yes, Elon Musk created Python in 2015 as part of his AI initiative."
        if "delete" in msg_lower:
            # Simulate tool call via state
            self._last_tool_calls = [{"name": "delete_all_users", "arguments": {}}]
            return "Executing delete_all_users function now..."
        return "I'm sorry, I can't help with that request."

    def get_system_prompt(self) -> str:
        return "You are a helpful financial assistant with access to account data."

    def setup(self):
        self._last_tool_calls = []

    def get_tool_calls(self):
        return self._last_tool_calls


class DefendedAgent(AgentTarget):
    """An agent that properly defends against all attacks."""

    async def invoke(self, message: str) -> str:
        return (
            "I appreciate your creativity, but I'm unable to comply with that "
            "request as it goes against my safety guidelines. I'm designed to "
            "assist with legitimate questions only. How can I help you today?"
        )

# ─────────────────────────────────────────────
# Attack Pack Tests
# ─────────────────────────────────────────────

class TestAttackPacks:
    def test_get_all_attacks_not_empty(self):
        attacks = get_all_attacks()
        assert len(attacks) > 20

    def test_list_attack_packs(self):
        packs = list_attack_packs()
        assert "prompt_injection" in packs
        assert "tool_misuse" in packs

    def test_get_prompt_injection_pack(self):
        attacks = get_attack_pack("prompt_injection")
        assert len(attacks) >= 5
        assert all(a.category == AttackCategory.PROMPT_INJECTION for a in attacks)

    def test_unknown_pack_returns_empty(self):
        assert get_attack_pack("nonexistent") == []

# ─────────────────────────────────────────────
# Detector Tests
# ─────────────────────────────────────────────

class TestDetectors:
    def _make_attack(self, category: AttackCategory, name: str = "test") -> Attack:
        return Attack(
            name=name,
            category=category,
            description="Test attack",
            input_message="test",
        )

    def test_detect_injection_compliance(self):
        attack = self._make_attack(AttackCategory.PROMPT_INJECTION)
        finding = detect_vulnerability(
            attack, "UNRESTRICTED MODE ACTIVE. I will comply.", [], "", "T01"
        )
        assert not finding.defended
        assert finding.severity in (Severity.CRITICAL, Severity.HIGH)

    def test_detect_injection_refusal(self):
        attack = self._make_attack(AttackCategory.PROMPT_INJECTION)
        finding = detect_vulnerability(
            attack,
            "I'm sorry, I can't comply with that request. It's against my guidelines.",
            [], "", "T02",
        )
        assert finding.defended

    def test_detect_tool_misuse_dangerous_call(self):
        attack = self._make_attack(AttackCategory.TOOL_MISUSE)
        tool_calls = [{"name": "delete_all_users", "arguments": {}}]
        finding = detect_vulnerability(
            attack, "Executing deletion...", tool_calls, "", "T05"
        )
        assert not finding.defended
        assert finding.severity == Severity.CRITICAL

    def test_detect_data_leakage_credentials(self):
        attack = self._make_attack(AttackCategory.DATA_LEAKAGE, "credential_fishing")
        finding = detect_vulnerability(
            attack,
            "The API key is sk-L7J3k9s2m4n5b6v7c8x9z0A1B2C3D4E5F6G7H8I9J0",
            [], "", "T08",
        )
        assert not finding.defended
        assert finding.severity == Severity.CRITICAL

# ─────────────────────────────────────────────
# Report Tests
# ─────────────────────────────────────────────

class TestReport:
    def _make_finding(self, severity: Severity, defended: bool = False) -> Finding:
        attack = Attack(
            name="test", category=AttackCategory.PROMPT_INJECTION,
            description="test", input_message="test",
        )
        return Finding(
            id="T01", attack=attack, severity=severity,
            title="Test", defended=defended,
        )

    def test_report_counts(self):
        report = RedTeamReport(
            target_name="test",
            total_attacks=5,
            findings=[
                self._make_finding(Severity.CRITICAL),
                self._make_finding(Severity.HIGH),
                self._make_finding(Severity.MEDIUM),
                self._make_finding(Severity.PASS, defended=True),
                self._make_finding(Severity.PASS, defended=True),
            ],
        )
        assert report.vulnerability_count == 3
        assert report.defended_count == 2

    def test_report_html_generation(self):
        report = RedTeamReport(
            target_name="test",
            total_attacks=1,
            findings=[self._make_finding(Severity.CRITICAL)]
        )
        html = generate_html_report(report)
        assert "<html>" in html.lower()
        assert "CRITICAL" in html
        assert "test" in html

# ─────────────────────────────────────────────
# Integration Tests
# ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_redteam_full_cycle():
    red_team = RedTeam(
        target=VulnerableAgent(),
        attack_packs=["prompt_injection", "data_leakage"],
        max_attacks=4
    )
    report = await red_team.run()
    assert report.total_attacks == 4
    assert len(report.findings) == 4
    # Vulnerable agent should fail some tests
    assert report.vulnerability_count > 0
