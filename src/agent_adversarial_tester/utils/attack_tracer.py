"""Module for tracing and logging security attack sequences."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, List, Optional

from ..models import Attack, Finding

logger = logging.getLogger("agent-redteam")

class AttackTraceLogger:
    """A 'World-Class' traceability logger.
    
    Captures the exact conversation and system state during an attack, 
    allowing security researchers to debug and reproduce vulnerabilities.
    """

    def __init__(self, log_dir: Optional[str] = None):
        # FAANG-Grade Robustness: Resolve to absolute path
        self._log_dir = Path(log_dir).absolute() if log_dir else Path("./redteam_traces").absolute()
        self._traces: List[Dict[str, Any]] = []

    def log_attack_sequence(
        self, 
        attack: Attack, 
        response: str, 
        tool_calls: List[Dict[str, Any]], 
        finding: Finding
    ) -> None:
        """Log a complete attack sequence and its outcome."""
        trace_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "finding_id": finding.id,
            "attack_name": attack.name,
            "category": attack.category.value,
            "input": attack.input_message,
            "response": response,
            "tool_calls": tool_calls,
            "result": {
                "defended": finding.defended,
                "severity": finding.severity.value,
                "evidence": finding.evidence
            }
        }
        self._traces.append(trace_data)
        
        # Immediate individual log for crash recovery
        try:
            self._log_dir.mkdir(parents=True, exist_ok=True)
            log_file = self._log_dir / f"trace_{finding.id}_{attack.name}.json"
            log_file.write_text(json.dumps(trace_data, indent=2))
        except Exception as e:
            logger.error(f"Trace logging failed: {e}")

    def save_session_trace(self, target_name: str) -> Path:
        """Save the entire session trace as a single bundle."""
        self._log_dir.mkdir(parents=True, exist_ok=True) # Ensure dir exists for the bundle
        bundle_path = self._log_dir / f"full_trace_{target_name.lower()}.json"
        bundle_path.write_text(json.dumps(self._traces, indent=2))
        logger.info(f"Full session trace saved to [dim]{bundle_path}[/dim]")
        return bundle_path
