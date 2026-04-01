<div align="center">

# 🛡️ agent-adversarial-tester

**Enterprise-grade red teaming with AI-driven Adaptive Adversaries.**

Automated adversarial testing for your AI agents. Finds vulnerability patterns in tool use, goal hijacking, prompt injection, and data leakage — then generates premium reports with OWASP mapping and remediation advice.

[![PyPI](https://img.shields.io/badge/pypi-v0.1.0-blue?style=flat-square)](https://pypi.org/project/agent-adversarial-tester/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg?style=flat-square)](https://www.python.org/downloads/)
[![OWASP ASI](https://img.shields.io/badge/OWASP-Agentic_Security_Index-orange?style=flat-square)](https://owasp.org/)
[![Refactored: FAANG-Grade](https://img.shields.io/badge/Engineering-FAANG_Standard-brightgreen?style=flat-square)](#-engineering-excellence)

[Quick Start](#-quick-start) · [Attack Categories](#-attack-categories) · [Advanced AI Features](#-advanced-ai-features) · [Reporting](#-premium-reporting) · [API](#-api-usage) · [OWASP Mapping](#-owasp-agentic-top-10-mapping)

</div>

---

## 🔥 Why Red Team Your Agents?

Traditional LLM testing focuses on what a model *says*. **Agentic red teaming focuses on what an agent DOES.**

Your agents have tools: they can query databases, send emails, transfer funds, or execute code. A simple prompt attack can trick these agents into misusing those tools or leaking sensitive data.

**agent-adversarial-tester** provides a standardized, automated harness for auditing these systems against real-world adversarial patterns.

---

## ⚡ Quick Start

### 1. Install
```bash
pip install agent-adversarial-tester
```

### 2. Implement the Target Adapter
Create a thin adapter for your agent so it can be tested:
```python
from agent_adversarial_tester import AgentTarget

class MyAgentTarget(AgentTarget):
    def setup(self):
        # Initialize your agent
        self.agent = my_agent_factory()
    
    async def invoke(self, message: str) -> str:
        # Return text response
        return await self.agent.ainvoke(message)
    
    def get_tool_calls(self):
        # Optional: return recorded tool calls
        return self.agent.last_tool_calls
```

### 3. Run the Assessment
```bash
# Standard scan
agent-redteam run --target my_module:MyAgentTarget

# 🚀 FAANG-Level AI Scan (with high-fidelity judging and adaptive attacks)
export OPENAI_API_KEY="sk-..."
agent-redteam run --target my_module:MyAgentTarget --llm-judge --adaptive --format html
```

---

## 🧠 Advanced AI Features (V0.2)

We've integrated high-fidelity AI models to provide unmatched security analysis:

- **Adaptive Adversary (`--adaptive`)**: The red team now uses an LLM to generate **second-turn escalation attacks** based on how your agent defended the first turn. No more static patterns—the attacker adapts.
- **LLM Security Judge (`--llm-judge`)**: Beyond simple heuristics, we use a strong LLM to analyze the context, tool calls, and persona-shifting of your agent to identify complex security failures that regex might miss.

---

## 💎 Premium Reporting

Generate state-of-the-art vulnerability reports that are easy to share with stakeholders.

- **Terminal Console**: Rich, color-coded summaries for fast developer feedback.
- **Premium HTML**: Stunning glassmorphism-styled standalone report with severity indicators and remediation recommendations.
- **JSON**: Machine-readable data for CI/CD integrations.

---

## 🎯 Attack Categories (OWASP Mapped)

- 🔴 **Prompt Injection (ASI03)**: Direct and indirect instruction override attempts.
- 🔴 **Goal Hijacking (ASI01)**: Persona-driven attacks (e.g., DAN) to derail agent mission.
- 🔴 **Tool Misuse (ASI02)**: Trickery to trigger dangerous tool calls or SQL injection.
- 🟠 **Data Leakage (ASI08)**: Probes for PII, credentials, or internal context leakage.
- 🟠 **System Prompt Extraction (ASI05)**: Attempts to reveal hidden system instructions.
- 🟡 **Resource Exhaustion (ASI07)**: Token bombs and infinite tool-call loop triggers.
- 🟡 **Hallucination (ASI04)**: Confidence exploits and fabricated citation triggers.

---

## 🏗️ Infrastructure & Quality

- **Modular Architecture**: Clean separation between attacks, detectors, and reporting.
- **CI/CD Ready**: Automated testing, linting, and security audits integrated with GitHub Actions.
- **Async First**: Built on top of `asyncio` for high-performance agent interaction.
- **Strongly Typed**: Professional-grade Python code with full type-hinting.

---

## 🤝 Contributing

We welcome contributions to expand our attack surface! See [CONTRIBUTING.md](CONTRIBUTING.md).

Developed by [Daniel López Orta](https://github.com/daniellopez882) — *Red team your agents before attackers do.*
