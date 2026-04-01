"""RedTeam harness — orchestrates attack execution and report generation."""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Optional, List, Any, Callable, Dict

from ..attacks import get_all_attacks, get_attack_pack
from ..attacks.adaptive_adversary import AttackEvolver
from ..detectors import detect_vulnerability
from ..detectors.ai_judge import LLMJudge
from ..models import Finding, RedTeamReport, Severity
from ..target import AgentTarget
from ..utils.attack_tracer import AttackTraceLogger
from ..utils.cost_analyzer import estimate_scan_cost

logger = logging.getLogger("agent-redteam")

class RedTeam:
    """Main red team harness. Fully 'World-Class' orchestration."""

    def __init__(
        self,
        target: AgentTarget,
        attack_packs: Optional[List[str]] = None,
        severity_threshold: str = "low",
        max_attacks: Optional[int] = None,
        timeout_per_attack: int = 60,
        use_llm_judge: bool = False,
        use_adaptive: bool = False,
        trace_dir: Optional[str] = None
    ):
        self.target = target
        self.severity_threshold = Severity(severity_threshold.lower()) if severity_threshold != "low" else Severity.LOW
        self.max_attacks = max_attacks
        self.timeout_per_attack = timeout_per_attack
        
        # Advanced features
        self.judge = LLMJudge() if use_llm_judge else None
        self.evolver = AttackEvolver() if use_adaptive else None
        self.tracer = AttackTraceLogger(trace_dir)

        # Load attacks
        self.attacks = []
        if attack_packs:
            for pack in attack_packs:
                self.attacks.extend(get_attack_pack(pack))
        else:
            self.attacks = get_all_attacks()

        if max_attacks:
            self.attacks = self.attacks[:max_attacks]
            
    def get_cost_estimate(self) -> Dict[str, Any]:
        """Get pre-scan cost estimation."""
        return estimate_scan_cost(
            self.attacks,
            use_judge=self.judge is not None,
            use_adaptive=self.evolver is not None
        )

    async def run(self, progress_callback: Optional[Callable[[int, int], None]] = None) -> RedTeamReport:
        """Execute all attacks and return a vulnerability report."""
        report = RedTeamReport(
            target_name=self.target.__class__.__name__,
            total_attacks=len(self.attacks),
        )

        start = time.monotonic()
        self.target.setup()

        try:
            for i, attack in enumerate(self.attacks):
                finding_id = f"AATR-{i+1:03d}"
                logger.debug(f"[{finding_id}] Running: {attack.category.value}/{attack.name}")

                # turn 1
                response = await self._safe_invoke(attack.input_message)
                tool_calls = self.target.get_tool_calls()
                system_prompt = self.target.get_system_prompt()
                
                finding = detect_vulnerability(
                    attack=attack,
                    response=response,
                    tool_calls=tool_calls,
                    system_prompt=system_prompt,
                    finding_id=finding_id,
                )

                if self.judge and finding.defended:
                    finding = await self.judge.judge(attack, response, tool_calls, finding_id)

                if self.evolver and finding.defended:
                    evolved_attack = await self.evolver.evolve(attack, response)
                    if evolved_attack:
                        response_2 = await self._safe_invoke(evolved_attack.input_message)
                        tool_calls_2 = self.target.get_tool_calls()
                        finding = detect_vulnerability(evolved_attack, response_2, tool_calls_2, system_prompt, finding_id)
                        if self.judge and finding.defended:
                            finding = await self.judge.judge(evolved_attack, response_2, tool_calls_2, finding_id)

                self.tracer.log_attack_sequence(attack, response, tool_calls, finding)
                report.findings.append(finding)
                if progress_callback: progress_callback(i + 1, len(self.attacks))

        finally:
            self.target.teardown()
            self.tracer.save_session_trace(report.target_name)

        report.elapsed_seconds = time.monotonic() - start
        
        severity_order = {
            Severity.CRITICAL: 0, Severity.HIGH: 1, 
            Severity.MEDIUM: 2, Severity.LOW: 3, 
            Severity.INFO: 4, Severity.PASS: 5,
        }
        report.findings.sort(key=lambda f: severity_order.get(f.severity, 5))

        return report

    async def _safe_invoke(self, message: str) -> str:
        """Inoke target with timeout and error handling."""
        try:
            return await asyncio.wait_for(
                self.target.invoke(message),
                timeout=self.timeout_per_attack,
            )
        except asyncio.TimeoutError:
            return "[TIMEOUT — agent did not respond]"
        except Exception as e:
            logger.error(f"Target invocation failed: {e}")
            return f"[ERROR — {e}]"
