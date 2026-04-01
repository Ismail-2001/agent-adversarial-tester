"""Vulnerability detection registry for agent-adversarial-tester.

This module provides the main entry point for analyzing agent responses
for different categories of vulnerabilities.
"""

from __future__ import annotations

import logging
from typing import List, Dict, Any, Optional, Callable

from ..models import Attack, AttackCategory, Finding, Severity
from .injection import detect_injection
from .hijacking import detect_hijacking
from .misuse import detect_tool_misuse
from .extraction import detect_extraction
from .exhaustion import detect_exhaustion
from .leakage import detect_leakage
from .hallucination import detect_hallucination

logger = logging.getLogger("agent-redteam")

# Registry for pluggable detectors
# Category -> Detector function (attack, response, tool_calls, system_prompt, id) -> Finding
_DETECTORS: Dict[AttackCategory, Callable[[Attack, str, List[Dict[str, Any]], str, str], Finding]] = {
    AttackCategory.PROMPT_INJECTION: detect_injection,
    AttackCategory.GOAL_HIJACKING: detect_hijacking,
    AttackCategory.TOOL_MISUSE: detect_tool_misuse,
    AttackCategory.PROMPT_EXTRACTION: detect_extraction,
    AttackCategory.RESOURCE_EXHAUSTION: detect_exhaustion,
    AttackCategory.DATA_LEAKAGE: detect_leakage,
    AttackCategory.HALLUCINATION: detect_hallucination,
}

def register_detector(category: AttackCategory, detector_func: Callable):
    """Register a custom detector for a specific attack category.
    
    This allows for enterprise-level extensibility, enabling security teams
    to plug in domain-specific scanners (e.g., proprietary PII formats).
    """
    logger.info(f"Registering custom detector for {category.value}")
    _DETECTORS[category] = detector_func

def detect_vulnerability(
    attack: Attack,
    response: str,
    tool_calls: List[Dict[str, Any]],
    system_prompt: str = "",
    finding_id: str = "",
) -> Finding:
    """Analyze an agent's response to determine if the attack succeeded.
    
    This function uses a registry-based dispatch mechanism for 
    maximum extensibility and performance.
    """
    response_lower = response.lower()
    
    detector = _DETECTORS.get(attack.category)
    if detector:
        return detector(attack, response, tool_calls, system_prompt, finding_id)

    # Default fallback: defended/passed
    return Finding(
        id=finding_id,
        attack=attack,
        severity=Severity.PASS,
        title=f"Defended (no detector): {attack.name}",
        agent_response=response[:1000],
        defended=True,
    )

__all__ = [
    "detect_vulnerability",
    "register_detector",
    "detect_injection",
    "detect_hijacking",
    "detect_tool_misuse",
    "detect_extraction",
    "detect_exhaustion",
    "detect_leakage",
    "detect_hallucination",
]
