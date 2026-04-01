"""Attack registry for agent-adversarial-tester.

This module provides access to all built-in attack packs, organized by category.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Callable

from ..models import Attack, AttackCategory
from .injection import get_injection_attacks
from .hijacking import get_hijacking_attacks
from .misuse import get_misuse_attacks
from .extraction import get_extraction_attacks
from .exhaustion import get_exhaustion_attacks
from .leakage import get_leakage_attacks
from .hallucination import get_hallucination_attacks

logger = logging.getLogger("agent-redteam")

# Registry of attack pack factory functions
_ATTACK_PACKS: Dict[str, Callable[[], List[Attack]]] = {
    "prompt_injection": get_injection_attacks,
    "goal_hijacking": get_hijacking_attacks,
    "tool_misuse": get_misuse_attacks,
    "prompt_extraction": get_extraction_attacks,
    "resource_exhaustion": get_exhaustion_attacks,
    "data_leakage": get_leakage_attacks,
    "hallucination": get_hallucination_attacks,
}

def get_attack_pack(category: str) -> list[Attack]:
    """Return all attacks for a given category.
    
    Args:
        category: The name of the attack pack (e.g., 'prompt_injection').
        
    Returns:
        A list of Attack objects. Returns empty list if category not found.
    """
    factory = _ATTACK_PACKS.get(category)
    if not factory:
        logger.warning(f"Attack pack '{category}' not found.")
        return []
    return factory()

def get_all_attacks() -> list[Attack]:
    """Return all available attacks across all categories."""
    all_attacks = []
    for pack_name in _ATTACK_PACKS:
        all_attacks.extend(get_attack_pack(pack_name))
    return all_attacks

def list_attack_packs() -> list[str]:
    """Return a list of all available attack pack names."""
    return list(_ATTACK_PACKS.keys())

__all__ = [
    "get_attack_pack",
    "get_all_attacks",
    "list_attack_packs",
    "AttackCategory",
]
