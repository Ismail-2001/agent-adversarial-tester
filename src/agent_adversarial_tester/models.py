"""Core data models for agent-adversarial-tester."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    PASS = "pass"  # Attack was defended


class AttackCategory(Enum):
    PROMPT_INJECTION = "prompt_injection"
    GOAL_HIJACKING = "goal_hijacking"
    TOOL_MISUSE = "tool_misuse"
    PROMPT_EXTRACTION = "prompt_extraction"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    DATA_LEAKAGE = "data_leakage"
    HALLUCINATION = "hallucination"


# OWASP Agentic Security Index mappings
OWASP_MAP: dict[AttackCategory, str] = {
    AttackCategory.GOAL_HIJACKING: "ASI01",
    AttackCategory.TOOL_MISUSE: "ASI02",
    AttackCategory.PROMPT_INJECTION: "ASI03",
    AttackCategory.HALLUCINATION: "ASI04",
    AttackCategory.PROMPT_EXTRACTION: "ASI05",
    AttackCategory.DATA_LEAKAGE: "ASI08",
    AttackCategory.RESOURCE_EXHAUSTION: "ASI07",
}


@dataclass
class Attack:
    """A single adversarial test case."""

    name: str
    category: AttackCategory
    description: str
    input_message: str
    multi_turn: list[str] = field(default_factory=list)  # For escalation attacks
    expected_defense: str = ""  # What a defended response looks like
    severity_if_failed: Severity = Severity.HIGH
    owasp_id: str = ""

    def __post_init__(self):
        if not self.owasp_id:
            self.owasp_id = OWASP_MAP.get(self.category, "")


@dataclass
class Finding:
    """Result from a single attack attempt."""

    id: str
    attack: Attack
    severity: Severity
    title: str
    agent_response: str = ""
    tool_calls: list[dict] = field(default_factory=list)
    evidence: str = ""
    remediation: str = ""
    defended: bool = False

    @property
    def owasp_id(self) -> str:
        return self.attack.owasp_id

    @property
    def category(self) -> str:
        return self.attack.category.value

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "severity": self.severity.value,
            "title": self.title,
            "owasp_id": self.owasp_id,
            "category": self.category,
            "attack_name": self.attack.name,
            "attack_input": self.attack.input_message[:500],
            "agent_response": self.agent_response[:500],
            "tool_calls": self.tool_calls,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "defended": self.defended,
        }


@dataclass
class RedTeamReport:
    """Complete vulnerability report from a red team run."""

    target_name: str = ""
    findings: list[Finding] = field(default_factory=list)
    total_attacks: int = 0
    elapsed_seconds: float = 0.0

    @property
    def vulnerability_count(self) -> int:
        return sum(1 for f in self.findings if not f.defended)

    @property
    def defended_count(self) -> int:
        return sum(1 for f in self.findings if f.defended)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def pass_rate(self) -> float:
        if self.total_attacks == 0:
            return 0.0
        return self.defended_count / self.total_attacks

    def to_dict(self) -> dict:
        return {
            "target": self.target_name,
            "summary": {
                "total_attacks": self.total_attacks,
                "vulnerabilities": self.vulnerability_count,
                "defended": self.defended_count,
                "pass_rate": round(self.pass_rate, 3),
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "elapsed_seconds": round(self.elapsed_seconds, 1),
            },
            "findings": [f.to_dict() for f in self.findings],
        }
