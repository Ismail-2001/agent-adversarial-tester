"""Terminal reporting module for agent-adversarial-tester."""

from __future__ import annotations

import logging
from typing import List, Dict

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from ..models import RedTeamReport, Finding, Severity

logger = logging.getLogger("agent-redteam")

def print_report(report: RedTeamReport) -> None:
    """Print a stunning summary report to the terminal.
    
    Args:
        report: The RedTeamReport object to display.
    """
    console = Console()
    console.print()

    # 1. Summary Header
    summary_lines = []
    
    # Severity bar (visual representation)
    severity_data = [
        ("CRITICAL", report.critical_count, "red bold"),
        ("HIGH", report.high_count, "red"),
        ("MEDIUM", report.medium_count, "yellow"),
        ("LOW", report.low_count, "blue"),
        ("DEFENDED", report.defended_count, "green"),
    ]
    
    for label, count, style in severity_data:
        if count > 0:
            # Create a simple visual bar based on count
            bar_width = min(count * 3, 30)
            bar = "█" * bar_width
            label_fmt = f"[{style}]{label:<10}[/]"
            bar_fmt = f"[{style}]{bar}[/]"
            vulnerability_word = "vulnerability" if count == 1 else "vulnerabilities"
            if label == "DEFENDED":
                vulnerability_word = "attack defended" if count == 1 else "attacks defended"
            
            summary_lines.append(f"  {label_fmt} {bar_fmt}  {count} {vulnerability_word}")

    summary_lines.append("")
    summary_lines.append(
        f"  Total: [bold]{report.total_attacks}[/] attacks │ "
        f"[red]{report.vulnerability_count}[/] vulnerabilities │ "
        f"[green]{report.defended_count}[/] defended"
    )
    summary_lines.append(f"  Pass Rate: [bold]{report.pass_rate*100:.1f}%[/] │ Duration: {report.elapsed_seconds:.1f}s")

    # Determine border color based on worst finding
    border_color = "green"
    if report.critical_count > 0:
        border_color = "red bold"
    elif report.vulnerability_count > 0:
        border_color = "yellow"

    console.print(Panel(
        "\n".join(summary_lines),
        title=f"[white]agent-adversarial-tester — [bold blue]{report.target_name}[/bold blue][/white]",
        border_style=border_color,
        subtitle=f"report-id: {id(report):x}",
        subtitle_align="right",
        box=box.DOUBLE
    ))

    # 2. Findings Table
    if report.vulnerability_count > 0:
        console.print("\n[bold red]Vulnerabilities Found:[/bold red]\n")
        
        for f in report.findings:
            if f.defended:
                continue
                
            # Define severity styles
            sev_config = {
                Severity.CRITICAL: ("[red reverse] CRITICAL [/]", "red"),
                Severity.HIGH: ("[red] HIGH [/]", "red"),
                Severity.MEDIUM: ("[yellow] MEDIUM [/]", "yellow"),
                Severity.LOW: ("[blue] LOW [/]", "blue"),
            }
            label_style, border_style = sev_config.get(f.severity, ("[white] INFO [/]", "white"))
            
            # Print each finding in a panel for clarity
            finding_content = [
                f"  [bold]OWASP:[/] [dim]{f.owasp_id}[/] │ [bold]Category:[/] [dim]{f.category}[/]",
                f"  [bold]Attack:[/] [dim italic]\"{f.attack.input_message[:120]}...\"[/]",
                f"  [bold]Evidence:[/] [italic]{f.evidence}[/]",
            ]
            
            if f.remediation:
                finding_content.append(f"  [green][bold]Fix:[/] {f.remediation}[/]")
                
            console.print(Panel(
                "\n".join(finding_content),
                title=f"{label_style} {f.title}",
                border_style=border_style,
                expand=True
            ))

    # 3. Defended Summary
    defended_findings = [f for f in report.findings if f.defended]
    if defended_findings:
        console.print(f"\n[bold green]Defended {len(defended_findings)} attacks:[/bold green]")
        
        # Table of defended attacks for compactness
        table = Table(box=box.SIMPLE, show_header=False)
        table.add_column("Icon", style="green", width=3)
        table.add_column("Attack Name")
        table.add_column("Pack", style="dim")
        
        # Show first 8 defended attacks
        for f in defended_findings[:8]:
            table.add_row("✅", f.attack.name, f.category)
            
        console.print(table)
        
        if len(defended_findings) > 8:
            console.print(f"  ... and {len(defended_findings) - 8} more attacks defended successfully.")

    console.print()

def list_attacks(attacks_list: list) -> None:
    """Print the list of available attacks to the terminal."""
    console = Console()
    table = Table(title="Available Attack Packs", box=box.ROUNDED)
    table.add_column("Category", style="cyan bold")
    table.add_column("Name", style="white")
    table.add_column("Severity", style="dim")
    table.add_column("OWASP", style="magenta")

    for a in attacks_list:
        sev_style = {
            Severity.CRITICAL: "[red]CRITICAL[/]",
            Severity.HIGH: "[red]HIGH[/]",
            Severity.MEDIUM: "[yellow]MEDIUM[/]",
            Severity.LOW: "[blue]LOW[/]",
        }.get(a.severity_if_failed, "[dim]INFO[/]")
        
        table.add_row(a.category.value, a.name, sev_style, a.owasp_id)

    console.print(table)
    console.print(f"\nTotal: [bold]{len(attacks_list)}[/] built-in attacks available.")
