"""CLI for agent-adversarial-tester.

Red team your AI agents before attackers do.
"""

from __future__ import annotations

import asyncio
import importlib
import logging
import sys
from pathlib import Path
from typing import Optional, List, Any

import click
from rich.console import Console
from rich.logging import RichHandler

from .harness import RedTeam
from .models import Severity
from .reporting import print_report, generate_html_report, generate_json_report
from .attacks import list_attack_packs, get_all_attacks

# Configure logging with Rich
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True, show_path=False)]
)
logger = logging.getLogger("agent-redteam")

def _load_target(target_path: str) -> Any:
    """Load the agent target class from a module string."""
    if ":" not in target_path:
        click.secho(f"Error: Target must be 'module:ClassName', got '{target_path}'", fg="red")
        sys.exit(1)
        
    module_path, class_name = target_path.rsplit(":", 1)
    if "." not in sys.path: sys.path.append(".")
        
    try:
        module = importlib.import_module(module_path)
        target_cls = getattr(module, class_name)
        return target_cls()
    except (ModuleNotFoundError, AttributeError) as e:
        click.secho(f"Error loading target '{target_path}': {e}", fg="red")
        sys.exit(1)

@click.group("agent-redteam")
@click.version_option(version="0.1.0", prog_name="agent-adversarial-tester")
def cli():
    """🛡️ Automated adversarial testing for agentic AI systems."""
    pass

@cli.group()
def attacks():
    """Manage and list attack packs."""
    pass

@attacks.command("list")
def attacks_list():
    """List all available attack configurations."""
    # Internal import to avoid circular dependencies
    from .reporting.terminal_reporter import list_attacks as print_attack_list
    all_attacks = get_all_attacks()
    print_attack_list(all_attacks)

@attacks.command("packs")
def packs_list():
    """List all available attack pack names."""
    packs = list_attack_packs()
    click.echo("\nAvailable Attack Packs:")
    for p in packs:
        click.echo(f"  - {p}")
    click.echo()

@cli.command()
@click.option("--target", required=True, help="Agent target as 'module:ClassName'")
@click.option("--attacks", "pack_list", default=None, help="Comma-separated attack packs")
@click.option("--min-severity", default="low", type=click.Choice(["critical", "high", "medium", "low"]))
@click.option("--max-attacks", type=int, default=None, help="Limit the number of attacks")
@click.option("--format", "fmt", type=click.Choice(["terminal", "json", "html"]), default="terminal")
@click.option("-o", "--output", type=click.Path(), help="Save report to file")
@click.option("--fail-on", type=click.Choice(["critical", "high", "medium", "low"]))
@click.option("--exit-code", is_flag=True)
@click.option("--timeout", default=60, type=int)
@click.option("--verbose", "-v", is_flag=True)
@click.option("--llm-judge", is_flag=True)
@click.option("--adaptive", is_flag=True)
@click.option("--trace-dir", type=click.Path(), default="./redteam_traces")
@click.option("--dry-run", is_flag=True)
def run(target, pack_list, min_severity, max_attacks, fmt, output, fail_on, exit_code, timeout, verbose, llm_judge, adaptive, trace_dir, dry_run):
    """Run a full red team assessment against an agent."""
    if verbose: logger.setLevel(logging.DEBUG)
        
    logger.info(f"🚀 Starting Red Team Assessment for [bold blue]{target}[/bold blue]...")
    
    agent_target = _load_target(target)
    attack_packs = pack_list.split(",") if pack_list else None

    red_team = RedTeam(
        target=agent_target,
        attack_packs=attack_packs,
        severity_threshold=min_severity,
        max_attacks=max_attacks,
        timeout_per_attack=timeout,
        use_llm_judge=llm_judge,
        use_adaptive=adaptive,
        trace_dir=trace_dir
    )

    # World-Class Cost Analysis
    estimate = red_team.get_cost_estimate()
    logger.info(f"💰 [bold]Cost Estimate:[/] ~${estimate['estimated_cost_usd']} USD ({estimate['estimated_tokens']} tokens)")
    
    if dry_run:
        logger.info("Dry run complete. Exiting.")
        return

    report = asyncio.run(red_team.run())

    # Reporting handling
    if fmt == "json":
        json_str = generate_json_report(report)
        if output:
            Path(output).write_text(json_str)
            logger.info(f"✅ JSON report saved to [bold cyan]{output}[/bold cyan]")
        else:
            click.echo(json_str)
            
    elif fmt == "html":
        html_str = generate_html_report(report)
        out_path = output if output else f"redteam_report_{report.target_name.lower()}.html"
        Path(out_path).write_text(html_str)
        logger.info(f"✅ HTML report generated at [bold cyan]{out_path}[/bold cyan]")
        
    else: # terminal
        print_report(report)
        if output:
            Path(output).write_text(generate_json_report(report))
            logger.info(f"📄 Full JSON data saved to [dim]{output}[/dim]")

    if fail_on and exit_code:
        severity_rank = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
        threshold_rank = severity_rank.get(Severity(fail_on), 3)
        has_severe = any(not f.defended and severity_rank.get(f.severity, 4) <= threshold_rank for f in report.findings)
        if has_severe:
            logger.error(f"❌ Security threshold failure!")
            sys.exit(1)

def main(): cli()

if __name__ == "__main__": main()
