# Contributing to agent-adversarial-tester

## Setup
```bash
git clone https://github.com/daniellopez882/agent-adversarial-tester.git
cd agent-adversarial-tester
pip install -e ".[dev]"
pytest tests/ -v
```

## High-Impact Contributions

- **New attacks** — multi-turn escalation, indirect injection via RAG docs
- **Better detectors** — fewer false positives/negatives
- **Framework adapters** — pre-built targets for LangGraph, CrewAI, AutoGen
- **HTML report** — shareable vulnerability report
- **Attack evolution** — LLM-powered attack generation that adapts
- **Custom attack packs** — YAML-defined attack libraries

## Code Style
- Python 3.10+ with type hints
- Lint: `ruff check src/ tests/`
- Every new attack needs corresponding detector tests
- Both "vulnerable" and "defended" agent test cases required
