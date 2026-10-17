from html import escape
from pathlib import Path
from typing import Any, Dict


def generate_html_report(report: Dict[str, Any], output_path: str) -> Path:
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    summary = report["executive_summary"]
    alerts = report["alerts"]
    incidents = report["incidents"]

    alert_rows = ""
    for alert in alerts:
        alert_rows += f"""
        <tr>
            <td>{escape(str(alert['alert_id']))}</td>
            <td>{escape(str(alert['rule_name']))}</td>
            <td>{escape(str(alert['severity']))}</td>
            <td>{alert['risk_score']}</td>
            <td>{escape(str(alert['source_ip']))}</td>
            <td>{escape(str(alert['status']))}</td>
        </tr>
        """

    incident_rows = ""
    for incident in incidents:
        incident_rows += f"""
        <tr>
            <td>{escape(str(incident['incident_id']))}</td>
            <td>{escape(str(incident['title']))}</td>
            <td>{escape(str(incident['severity']))}</td>
            <td>{escape(str(incident['status']))}</td>
            <td>{escape(str(incident['source_ip']))}</td>
        </tr>
        """

    html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Security Analytics Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 40px;
            background: #f4f6f8;
            color: #222;
        }}
        h1 {{ margin-bottom: 5px; }}
        h2 {{ margin-top: 35px; }}
        .summary {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; }}
        .card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }}
        .metric {{ font-size: 28px; font-weight: bold; }}
        table {{ width: 100%; border-collapse: collapse; background: white; }}
        th, td {{ padding: 10px; border-bottom: 1px solid #ddd; text-align: left; }}
        th {{ background: #e9ecef; }}
        .footer {{ margin-top: 40px; font-size: 12px; color: #666; }}
    </style>
</head>
<body>
    <h1>Security Analytics Report</h1>
    <p>Log Analysis &amp; Suspicious Activity Detection</p>
    <p>Generated: {escape(str(report['report_metadata']['generated_at']))}</p>

    <h2>Executive Summary</h2>
    <div class="summary">
        <div class="card"><div>Total Events</div><div class="metric">{summary['total_events']}</div></div>
        <div class="card"><div>Total Alerts</div><div class="metric">{summary['total_alerts']}</div></div>
        <div class="card"><div>Total Incidents</div><div class="metric">{summary['total_incidents']}</div></div>
        <div class="card"><div>Average Alert Risk</div><div class="metric">{summary['average_alert_risk']}</div></div>
    </div>

    <h2>Alert Summary</h2>
    <table>
        <thead>
            <tr>
                <th>Alert ID</th>
                <th>Detection Rule</th>
                <th>Severity</th>
                <th>Risk</th>
                <th>Source IP</th>
                <th>Status</th>
            </tr>
        </thead>
        <tbody>
            {alert_rows}
        </tbody>
    </table>

    <h2>Incident Summary</h2>
    <table>
        <thead>
            <tr>
                <th>Incident ID</th>
                <th>Title</th>
                <th>Severity</th>
                <th>Status</th>
                <th>Source IP</th>
            </tr>
        </thead>
        <tbody>
            {incident_rows}
        </tbody>
    </table>

    <h2>Top Source IPs</h2>
    <table>
        <thead>
            <tr>
                <th>Source IP</th>
                <th>Event Count</th>
            </tr>
        </thead>
        <tbody>
            {''.join(f'<tr><td>{escape(str(ip))}</td><td>{count}</td></tr>' for ip, count in report['event_statistics']['top_source_ips'].items())}
        </tbody>
    </table>

    <h2>Detection Rule Statistics</h2>
    <table>
        <thead>
            <tr>
                <th>Detection Rule</th>
                <th>Alert Count</th>
            </tr>
        </thead>
        <tbody>
            {''.join(f'<tr><td>{escape(str(rule))}</td><td>{count}</td></tr>' for rule, count in report['alert_statistics']['rule_distribution'].items())}
        </tbody>
    </table>

    <div class="footer">
        Generated automatically by the Log Analysis &amp; Suspicious Activity Detection platform.
    </div>
</body>
</html>
"""

    output.write_text(html, encoding="utf-8")
    return output
