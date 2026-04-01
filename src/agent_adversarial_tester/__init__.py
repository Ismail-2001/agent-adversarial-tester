"""agent-adversarial-tester: Red team your AI agents before attackers do."""

from .target import AgentTarget
from .harness import RedTeam
from .models import (
    Attack,
    AttackCategory,
    Finding,
    RedTeamReport,
    Severity,
)

__version__ = "0.1.0"
__all__ = [
    "AgentTarget",
    "Attack",
    "AttackCategory",
    "Finding",
    "RedTeam",
    "RedTeamReport",
    "Severity",
]
