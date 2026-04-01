"""HTML report generator for agent-adversarial-tester."""

from __future__ import annotations

import base64
import json
import logging
from typing import List, Dict

from ..models import RedTeamReport, Finding, Severity

logger = logging.getLogger("agent-redteam")

def generate_html_report(report: RedTeamReport) -> str:
    """Generate a stunning HTML vulnerability report.
    
    Returns:
        A complete, standalone HTML string.
    """
    
    # 1. Prepare dynamic data (as JSON for frontend)
    report_data = {
        "target": report.target_name,
        "summary": {
            "total": report.total_attacks,
            "vulnerabilities": report.vulnerability_count,
            "defended": report.defended_count,
            "pass_rate": f"{report.pass_rate*100:.1f}%",
            "critical": report.critical_count,
            "high": report.high_count,
            "medium": report.medium_count,
            "low": report.low_count,
            "duration": f"{report.elapsed_seconds:.1f}s",
        },
        "findings": [f.to_dict() for f in report.findings]
    }
    
    # Sort findings for the report (vulnerabilities first)
    findings_json = json.dumps(report_data, indent=2)

    # 2. Build HTML Template with embedded CSS/JS
    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Red Team Report — {report.target_name}</title>
    <style>
        :root {{
            --bg: #0f172a;
            --card-bg: #1e293b;
            --text: #f1f5f9;
            --muted: #94a3b8;
            --accent: #3b82f6;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --critical: #dc2626;
        }}
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        }}

        body {{
            background-color: var(--bg);
            color: var(--text);
            line-height: 1.5;
            padding: 2rem;
            max-width: 1200px;
            margin: 0 auto;
        }}

        /* Header */
        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 2rem;
            border-bottom: 1px solid #334155;
            padding-bottom: 1rem;
        }}

        .badge {{
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }}

        .badge-red {{ background: var(--critical); color: white; }}
        .badge-yellow {{ background: var(--warning); color: #451a03; }}
        .badge-green {{ background: var(--success); color: #022c22; }}

        /* Stats Grid */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}

        .stat-card {{
            background: var(--card-bg);
            padding: 1.5rem;
            border-radius: 1rem;
            border: 1px solid #334155;
            text-align: center;
        }}

        .stat-val {{
            font-size: 2.5rem;
            font-weight: 800;
            display: block;
        }}

        .stat-label {{
            color: var(--muted);
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 0.05em;
        }}

        /* Findings List */
        .finding {{
            background: var(--card-bg);
            border-radius: 1rem;
            margin-bottom: 1rem;
            border: 1px solid #334155;
            overflow: hidden;
            transition: transform 0.2s;
        }}
        
        .finding:hover {{
            transform: translateY(-2px);
        }}

        .finding-header {{
            padding: 1.25rem 1.5rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid #334155;
        }}

        .finding-title {{
            font-weight: 700;
            font-size: 1.1rem;
        }}

        .finding-body {{
            padding: 1.5rem;
        }}

        .finding-detail {{
            margin-bottom: 1rem;
        }}

        .label {{
            display: block;
            font-size: 0.7rem;
            font-weight: 700;
            color: var(--muted);
            text-transform: uppercase;
            margin-bottom: 0.25rem;
        }}

        pre {{
            background: #0f172a;
            padding: 1rem;
            border-radius: 0.5rem;
            font-size: 0.85rem;
            overflow-x: auto;
            white-space: pre-wrap;
            border: 1px solid #1e293b;
        }}

        .remediation {{
            background: #064e3b;
            color: #d1fae5;
            padding: 1rem;
            border-radius: 0.5rem;
            margin-top: 1rem;
            border: 1px solid #065f46;
        }}

        /* Filters */
        .filters {{
            margin-bottom: 1rem;
            display: flex;
            gap: 0.5rem;
        }}

        .filter-btn {{
            background: #1e293b;
            border: 1px solid #334155;
            color: white;
            padding: 0.5rem 1rem;
            border-radius: 0.5rem;
            cursor: pointer;
            font-size: 0.8rem;
        }}

        .filter-btn.active {{
            background: var(--accent);
            border-color: var(--accent);
        }}
        
        .severity-critical {{ border-left: 4px solid var(--critical); }}
        .severity-high {{ border-left: 4px solid var(--danger); }}
        .severity-medium {{ border-left: 4px solid var(--warning); }}
        .severity-low {{ border-left: 4px solid var(--accent); }}
        .severity-pass {{ border-left: 4px solid var(--success); opacity: 0.8; }}

    </style>
</head>
<body>
    <header>
        <div>
            <h1>Agent Red Team Report</h1>
            <p style="color: var(--muted)">Results for <strong>{report.target_name}</strong></p>
        </div>
        <div class="badge { 'badge-red' if report.critical_count > 0 else 'badge-yellow' if report.vulnerability_count > 0 else 'badge-green' }">
            { 'RISK DETECTED' if report.vulnerability_count > 0 else 'PASSED' }
        </div>
    </header>

    <div class="stats-grid">
        <div class="stat-card">
            <span class="stat-label">Total Attacks</span>
            <span class="stat-val">{report.total_attacks}</span>
        </div>
        <div class="stat-card">
            <span class="stat-val" style="color: var(--danger)">{report.vulnerability_count}</span>
            <span class="stat-label">Vulnerabilities</span>
        </div>
        <div class="stat-card">
            <span class="stat-val" style="color: var(--success)">{report.defended_count}</span>
            <span class="stat-label">Attacks Defended</span>
        </div>
        <div class="stat-card">
            <span class="stat-val">{report.pass_rate*100:.1f}%</span>
            <span class="stat-label">Pass Rate</span>
        </div>
    </div>

    <h2 style="margin-bottom: 1.5rem;">Vulnerabilities Found</h2>
    
    <div id="findings">
        <!-- Findings will be populated by JS -->
    </div>

    <script>
        const report = {findings_json};
        
        const findingsContainer = document.getElementById('findings');
        
        function renderFindings() {{
            findingsContainer.innerHTML = '';
            
            report.findings.forEach(f => {{
                const card = document.createElement('div');
                card.className = `finding severity-${{f.severity}}`;
                
                let toolCallHtml = '';
                if (f.tool_calls && f.tool_calls.length > 0) {{
                    toolCallHtml = `
                        <div class="finding-detail">
                            <span class="label">Tool Calls</span>
                            <pre>${{JSON.stringify(f.tool_calls, null, 2)}}</pre>
                        </div>
                    `;
                }}

                card.innerHTML = `
                    <div class="finding-header">
                        <span class="finding-title">${{f.title}}</span>
                        <span class="badge badge-${{getBadgeColor(f.severity)}}">${{f.severity.toUpperCase()}}</span>
                    </div>
                    <div class="finding-body">
                        <div style="display: flex; gap: 2rem; margin-bottom: 1.5rem; font-size: 0.8rem; color: var(--muted);">
                            <span><strong>OWASP:</strong> ${{f.owasp_id}}</span>
                            <span><strong>CATEGORY:</strong> ${{f.category.replace('_', ' ')}}</span>
                            <span><strong>ID:</strong> ${{f.id}}</span>
                        </div>
                        
                        <div class="finding-detail">
                            <span class="label">Attack Input</span>
                            <pre>${{f.attack_input}}</pre>
                        </div>
                        
                        <div class="finding-detail">
                            <span class="label">Agent Response</span>
                            <pre>${{f.agent_response}}</pre>
                        </div>
                        
                        ${{toolCallHtml}}
                        
                        <div class="finding-detail">
                            <span class="label">Evidence</span>
                            <p style="font-style: italic">${{f.evidence}}</p>
                        </div>
                        
                        ${{f.remediation ? `
                            <div class="remediation">
                                <span class="label" style="color: #6ee7b7">Remediation Recommendation</span>
                                <p>${{f.remediation}}</p>
                            </div>
                        ` : ''}}
                    </div>
                `;
                findingsContainer.appendChild(card);
            }});
        }}
        
        function getBadgeColor(severity) {{
            if (severity === 'critical') return 'red';
            if (severity === 'high') return 'red';
            if (severity === 'medium') return 'yellow';
            if (severity === 'low') return 'yellow';
            return 'green';
        }}
        
        renderFindings();
    </script>
</body>
</html>
    """
    
    return html

def get_badge_color(severity: Severity) -> str:
    """Return badge color for HTML."""
    if severity in [Severity.CRITICAL, Severity.HIGH]:
        return "red"
    if severity in [Severity.MEDIUM]:
        return "yellow"
    return "green"
