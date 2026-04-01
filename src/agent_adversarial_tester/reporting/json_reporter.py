"""JSON report generator for agent-adversarial-tester."""

from __future__ import annotations

import json
import logging
from typing import Dict, Any

from ..models import RedTeamReport

logger = logging.getLogger("agent-redteam")

def generate_json_report(report: RedTeamReport) -> str:
    """Generate a clean JSON representation of the report.
    
    Returns:
        A pretty-printed JSON string.
    """
    logger.debug(f"Generating JSON report for {report.target_name}")
    data = report.to_dict()
    return json.dumps(data, indent=2)
