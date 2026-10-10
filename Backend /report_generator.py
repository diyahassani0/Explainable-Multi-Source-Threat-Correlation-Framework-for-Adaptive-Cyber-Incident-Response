"""
Report and Analytics Generator.
Produces downloadable incident reports, CSV exports, JSON telemetry exports,
and printable Executive Summary reports for college presentations and compliance audits.
"""

from datetime import datetime
import io
import csv
import json


def generate_executive_html_report(incident: dict, connected_logs: list, cluster: dict, soar_actions: list, xai_data: dict) -> str:
    """
    Generates a beautifully styled, high-resolution HTML Executive Incident Report
    ready for viewing and printing/saving to PDF.
    """
    now_str = datetime.utcnow().strftime("%B %d, %Y - %H:%M UTC")
    inc_id = incident.get("id", "N/A")
    sev = incident.get("severity", "Medium")
    amt = float(incident.get("amount_lost_inr", 0))

    sev_color = "#DC2626" if sev == "Critical" else "#EA580C" if sev == "High" else "#D97706" if sev == "Medium" else "#2563EB"

    # SHAP table rows
    shap_rows = ""
    for item in (xai_data.get("feature_impacts", [])[:6]):
        effect_color = "#DC2626" if item["effect"] == "Increases Risk" else "#16A34A"
        shap_rows += f"""
        <tr>
            <td style="padding: 8px; border-bottom: 1px solid #E2E8F0; font-weight: 500;">{item['feature']}</td>
            <td style="padding: 8px; border-bottom: 1px solid #E2E8F0;">{item['raw_value']}</td>
            <td style="padding: 8px; border-bottom: 1px solid #E2E8F0; font-family: monospace;">{item['shap_value']:+.4f}</td>
            <td style="padding: 8px; border-bottom: 1px solid #E2E8F0; color: {effect_color}; font-weight: 600;">{item['effect']}</td>
        </tr>
        """

    # Telemetry rows
    log_rows = ""
    for log in connected_logs[:6]:
        log_rows += f"""
        <tr>
            <td style="padding: 6px; border-bottom: 1px solid #E2E8F0; font-family: monospace; font-size: 11px;">{log.get('timestamp')}</td>
            <td style="padding: 6px; border-bottom: 1px solid #E2E8F0; font-weight: 600;">{log.get('log_source')}</td>
            <td style="padding: 6px; border-bottom: 1px solid #E2E8F0;">{log.get('event_type')}</td>
            <td style="padding: 6px; border-bottom: 1px solid #E2E8F0; font-family: monospace;">{log.get('source_ip')} &rarr; {log.get('dest_ip')}</td>
            <td style="padding: 6px; border-bottom: 1px solid #E2E8F0;"><code>{log.get('action_taken')}</code></td>
        </tr>
        """

    # Actions rows
    actions_rows = ""
    if soar_actions:
        for a in soar_actions:
            actions_rows += f"""
            <tr>
                <td style="padding: 6px; border-bottom: 1px solid #E2E8F0;">{a.get('action_type')}</td>
                <td style="padding: 6px; border-bottom: 1px solid #E2E8F0; font-family: monospace;">{a.get('target_entity')}</td>
                <td style="padding: 6px; border-bottom: 1px solid #E2E8F0;">{a.get('status')}</td>
                <td style="padding: 6px; border-bottom: 1px solid #E2E8F0; font-size: 11px;">{a.get('executed_at')}</td>
            </tr>
            """
    else:
        actions_rows = "<tr><td colspan='4' style='padding: 10px; text-align: center; color: #64748B;'>No adaptive response actions executed yet.</td></tr>"

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Executive Incident Report - Incident #{inc_id}</title>
    <style>
        @media print {{
            body {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
            .no-print {{ display: none !important; }}
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            color: #0F172A;
            background: #F8FAFC;
            margin: 0;
            padding: 24px;
        }}
        .report-card {{
            max-width: 900px;
            margin: 0 auto;
            background: #FFFFFF;
            border: 1px solid #E2E8F0;
            border-radius: 8px;
            padding: 36px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05);
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            border-bottom: 2px solid #0B192C;
            padding-bottom: 20px;
            margin-bottom: 24px;
        }}
        .title {{ font-size: 24px; font-weight: 800; color: #0B192C; margin: 0; }}
        .subtitle {{ font-size: 13px; color: #64748B; margin-top: 4px; }}
        .badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 13px;
            font-weight: 700;
            color: #FFFFFF;
            text-transform: uppercase;
        }}
        .grid-2 {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 16px;
            margin-bottom: 24px;
        }}
        .info-box {{
            background: #F1F5F9;
            border-radius: 6px;
            padding: 14px 18px;
        }}
        .info-box strong {{ display: block; font-size: 11px; text-transform: uppercase; color: #475569; margin-bottom: 4px; }}
        .info-box span {{ font-size: 16px; font-weight: 600; color: #0B192C; }}
        h3 {{
            color: #0B192C;
            font-size: 15px;
            border-left: 4px solid #00A8E8;
            padding-left: 8px;
            margin-top: 28px;
            margin-bottom: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
            margin-bottom: 20px;
        }}
        th {{
            background: #F8FAFC;
            text-align: left;
            padding: 8px;
            border-bottom: 2px solid #CBD5E1;
            font-size: 11px;
            text-transform: uppercase;
            color: #475569;
        }}
        .callout {{
            background: #EFF6FF;
            border-left: 4px solid #2563EB;
            padding: 12px 16px;
            border-radius: 0 4px 4px 0;
            font-size: 13px;
            line-height: 1.5;
            color: #1E3A8A;
            margin: 16px 0;
        }}
        .btn-print {{
            background: #0B192C;
            color: #FFFFFF;
            border: none;
            padding: 8px 16px;
            border-radius: 6px;
            font-size: 13px;
            font-weight: 600;
            cursor: pointer;
        }}
    </style>
</head>
<body>
    <div style="max-width: 900px; margin: 0 auto 16px; display: flex; justify-content: flex-end;" class="no-print">
        <button class="btn-print" onclick="window.print()">Print / Save as PDF</button>
    </div>

    <div class="report-card">
        <div class="header">
            <div>
                <h1 class="title">CYBER INCIDENT INVESTIGATION REPORT</h1>
                <div class="subtitle">Explainable Multi-Source Threat Correlation Framework | Incident #{inc_id}</div>
            </div>
            <div style="text-align: right;">
                <span class="badge" style="background: {sev_color};">{sev} SEVERITY</span>
                <div class="subtitle" style="margin-top: 6px;">Generated: {now_str}</div>
            </div>
        </div>

        <div class="grid-2">
            <div class="info-box">
                <strong>Incident Type & Vector</strong>
                <span>{incident.get('incident_type')}</span>
            </div>
            <div class="info-box">
                <strong>Financial Loss Impact</strong>
                <span>INR {amt:,.0f}</span>
            </div>
            <div class="info-box">
                <strong>Target Category & Entity</strong>
                <span>{incident.get('category')} ({incident.get('city')})</span>
            </div>
            <div class="info-box">
                <strong>Investigation Status</strong>
                <span>{incident.get('investigation_status', 'New')}</span>
            </div>
        </div>

        <h3>1. Machine Learning Prediction & Explainability (XAI - SHAP)</h3>
        <div class="callout">
            <strong>Model Assessment:</strong> {xai_data.get('explanation_narrative', 'Prediction based on XGBoost multi-source risk classifier.')}
        </div>
        <table>
            <thead>
                <tr>
                    <th>Feature</th>
                    <th>Observed Value</th>
                    <th>SHAP Contribution</th>
                    <th>Risk Influence</th>
                </tr>
            </thead>
            <tbody>
                {shap_rows}
            </tbody>
        </table>

        <h3>2. Cross-Source Threat Correlation & Attack Chain</h3>
        <div class="callout" style="background: #FFFBEB; border-color: #D97706; color: #92400E;">
            <strong>Correlation Rationale:</strong> {cluster.get('explanation', 'Correlated via shared IP telemetry across Firewall and IDS.')}
        </div>
        <table>
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>Log Source</th>
                    <th>Event Type</th>
                    <th>Network Path</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
                {log_rows}
            </tbody>
        </table>

        <h3>3. Adaptive Incident Response (SOAR Actions)</h3>
        <table>
            <thead>
                <tr>
                    <th>Action Type</th>
                    <th>Target Entity</th>
                    <th>Execution Status</th>
                    <th>Timestamp</th>
                </tr>
            </thead>
            <tbody>
                {actions_rows}
            </tbody>
        </table>

        <div style="margin-top: 36px; padding-top: 16px; border-top: 1px solid #E2E8F0; display: flex; justify-content: space-between; font-size: 11px; color: #64748B;">
            <div>SOC Tier-2 Certified Audit Trail</div>
            <div>Antigravity Cybersecurity Lab</div>
        </div>
    </div>
</body>
</html>
"""
    return html_content


def export_incidents_to_csv(incidents_list: list) -> str:
    """Exports incidents to CSV string."""
    if not incidents_list:
        return ""
    output = io.StringIO()
    fieldnames = list(incidents_list[0].keys())
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for row in incidents_list:
        writer.writerow(row)
    return output.getvalue()


def export_incidents_to_json(incidents_list: list) -> str:
    """Exports incidents to formatted JSON string."""
    return json.dumps(incidents_list, indent=2)
