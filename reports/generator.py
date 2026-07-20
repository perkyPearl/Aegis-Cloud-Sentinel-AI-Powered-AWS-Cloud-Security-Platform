import os
import json
import datetime
from typing import List, Dict, Any

# ReportLab imports for PDF generation
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether

from scanner.security_metadata import SECURITY_METADATA

class ReportGenerator:
    """Generates JSON, HTML, and PDF reports for a given scan run tailored by audience."""
    
    def __init__(self, scan_summary: Dict[str, Any], findings: List[Dict[str, Any]], output_dir: str = None):
        self.summary = scan_summary
        self.findings = findings
        
        # Set output directory to default "output" in the workspace if not specified
        if output_dir is None:
            self.output_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                "output"
            )
        else:
            self.output_dir = output_dir
            
        os.makedirs(self.output_dir, exist_ok=True)

    def generate_all(self) -> Dict[str, str]:
        """Generate JSON, HTML, and PDF reports and return their file paths."""
        paths = {
            "json": self.generate_json(),
            "html": self.generate_html(),
            "pdf": self.generate_pdf()
        }
        return paths

    def generate_json(self) -> str:
        """Export scan details to a JSON file."""
        filename = f"scan_report_{self.summary['id']}.json"
        filepath = os.path.join(self.output_dir, filename)
        
        data = {
            "summary": self.summary,
            "findings": self.findings
        }
        
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
            
        return filepath

    def generate_html(self, audience: str = None) -> str:
        """Export scan details to an HTML report with visual styling tailored by audience."""
        suffix = f"_{audience}" if audience else ""
        filename = f"scan_report_{self.summary['id']}{suffix}.html"
        filepath = os.path.join(self.output_dir, filename)
        
        score = self.summary["score"]
        score_color = "#ef4444"  # Red
        if score >= 90:
            score_color = "#22c55e"  # Green
        elif score >= 70:
            score_color = "#eab308"  # Yellow
        elif score >= 50:
            score_color = "#f97316"  # Orange
            
        # Determine Title and Executive Summary based on Audience
        if audience == "ciso":
            report_title = "Aegis Cloud Sentinel - CISO Executive Report"
            subtitle = "High-level risk dashboard, trend details, and compliance posture summaries"
            exec_summary = f"""
            <div style="background-color: #f8fafc; border-left: 4px solid #7b2cbf; padding: 16px; border-radius: 6px; margin-bottom: 24px;">
                <h3 style="margin-top: 0; color: #1e293b;">Executive Summary</h3>
                <p style="margin: 0; font-size: 14px; line-height: 1.6; color: #475569;">
                    An automated security assessment was performed on the AWS cloud environment. The overall security posture score is evaluated at <strong>{score}/100</strong>. 
                    A total of <strong>{self.summary['failed_checks']} failed checks</strong> were identified, containing <strong>{self.summary['critical_count']} Critical risk</strong> and <strong>{self.summary['high_count']} High risk</strong> exposures. 
                    Immediate prioritization should be placed on resolving chained vulnerabilities (such as exposed servers with administrative profiles) to prevent unauthorized perimeter entry or account compromise.
                </p>
            </div>
            """
        elif audience == "developer":
            report_title = "Aegis Cloud Sentinel - Developer Remediation Report"
            subtitle = "Code-centric mitigation instructions, Terraform snippets, and AWS CLI scripts"
            exec_summary = """
            <div style="background-color: #f0fdf4; border-left: 4px solid #16a34a; padding: 16px; border-radius: 6px; margin-bottom: 24px;">
                <h3 style="margin-top: 0; color: #14532d;">Developer Action Summary</h3>
                <p style="margin: 0; font-size: 14px; line-height: 1.6; color: #166534;">
                    This document lists all active security vulnerabilities alongside direct infrastructure remediation scripts. Copy/apply the Terraform code or AWS CLI commands provided in the findings below to integrate these security fixes directly into your CI/CD pipelines.
                </p>
            </div>
            """
        elif audience == "compliance":
            report_title = "Aegis Cloud Sentinel - Compliance Audit Report"
            subtitle = "Framework mapping audits for CIS Benchmarks, SOC 2, and HIPAA Security Rules"
            exec_summary = f"""
            <div style="background-color: #fef9c3; border-left: 4px solid #ca8a04; padding: 16px; border-radius: 6px; margin-bottom: 24px;">
                <h3 style="margin-top: 0; color: #713f12;">Compliance Posture Assessment</h3>
                <p style="margin: 0; font-size: 14px; line-height: 1.6; color: #854d0e;">
                    This report verifies compliance against the <strong>CIS AWS Foundations Benchmark v1.4.0</strong>. Out of {self.summary['total_checks']} rules checked, <strong>{self.summary['failed_checks']} controls failed compliance parameters</strong>. Reference lists and mapped framework sections are compiled below.
                </p>
            </div>
            """
        else:
            report_title = "Aegis Cloud Sentinel - Cloud Security Engineer Report"
            subtitle = "Technical security posture details, resource references, and configuration audits"
            exec_summary = ""

        # Build findings rows based on audience
        findings_html = ""
        for f in self.findings:
            if f["status"] == "PASS" and audience != "compliance":
                continue  # Standard reports focus on failures
                
            sev_badge = ""
            if f["severity"] == "CRITICAL":
                sev_badge = '<span style="background-color: #fef2f2; color: #991b1b; padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; border: 1px solid #fca5a5;">CRITICAL</span>'
            elif f["severity"] == "HIGH":
                sev_badge = '<span style="background-color: #fff7ed; color: #c2410c; padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; border: 1px solid #fed7aa;">HIGH</span>'
            elif f["severity"] == "MEDIUM":
                sev_badge = '<span style="background-color: #fef9c3; color: #854d0e; padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; border: 1px solid #fef08a;">MEDIUM</span>'
            else:
                sev_badge = '<span style="background-color: #f0fdf4; color: #166534; padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; border: 1px solid #bbf7d0;">LOW</span>'

            # Get metadata details
            meta = SECURITY_METADATA.get(f["check_id"], {})
            
            # Tailor findings details panel by audience
            if audience == "ciso":
                details_panel = f"""
                <strong>Why this matters:</strong> {meta.get('why_dangerous', f['message'])}<br>
                <div style="margin-top: 6px; padding: 8px; background-color: #fef2f2; border-left: 3px solid #ef4444; border-radius: 2px; font-size: 13px;">
                    <strong>Business Impact Assessment:</strong> {meta.get('estimated_impact', 'Risk of resource exploitation.')}
                </div>
                """
            elif audience == "developer":
                details_panel = f"""
                <strong>Issue Message:</strong> {f['message']}<br>
                <div style="margin-top: 8px; display: grid; grid-template-columns: 1fr; gap: 12px;">
                    <div style="padding: 10px; background-color: #0f172a; border-radius: 6px; color: #e2e8f0; font-family: monospace; font-size: 11px;">
                        <strong>// Terraform Remediation Code:</strong><br>
                        <pre style="margin: 4px 0 0 0; white-space: pre-wrap; font-size: 11px;">{meta.get('fix_terraform', '# Fix code not available')}</pre>
                    </div>
                    <div style="padding: 10px; background-color: #0f172a; border-radius: 6px; color: #e2e8f0; font-family: monospace; font-size: 11px;">
                        <strong># AWS CLI Command:</strong><br>
                        <pre style="margin: 4px 0 0 0; white-space: pre-wrap; font-size: 11px;">{meta.get('fix_cli', '# CLI command not available')}</pre>
                    </div>
                </div>
                """
            elif audience == "compliance":
                status_color = "#16a34a" if f["status"] == "PASS" else "#dc2626"
                status_label = "COMPLIANT" if f["status"] == "PASS" else "NON-COMPLIANT"
                details_panel = f"""
                <strong>Compliance Status:</strong> <span style="color: {status_color}; font-weight: bold;">{status_label}</span><br>
                <strong>CIS Rule:</strong> {meta.get('cis_benchmark', 'N/A')}<br>
                <strong>MITRE ATT&CK Mapping:</strong> {meta.get('mitre_attack', 'N/A')}<br>
                <strong>Audit Details:</strong> {f['message']}<br>
                <strong>Real World Incident:</strong> {meta.get('real_world_incident', 'No public reference logged.')}
                """
            else: # engineer (default)
                details_panel = f"""
                <strong>Issue Message:</strong> {f['message']}<br>
                <strong>Console Fix:</strong> {meta.get('fix_console', f['reremediation'] if 'reremediation' in f else f['remediation'])}<br>
                <strong>Official Docs:</strong> <a href="{meta.get('aws_docs', '#')}" target="_blank">{meta.get('aws_docs', 'AWS User Guide')}</a>
                """

            findings_html += f"""
            <tr style="border-bottom: 1px solid #e2e8f0;">
                <td style="padding: 12px; font-weight: 500; color: #1e293b;">{f['service']}</td>
                <td style="padding: 12px; color: #1e293b;">{f['check_name']}</td>
                <td style="padding: 12px;">{sev_badge}</td>
                <td style="padding: 12px; font-family: monospace; font-size: 12px; color: #475569; max-width: 150px; word-break: break-all;">{f['resource_id']}</td>
                <td style="padding: 12px; color: #334155; font-size: 13.5px; line-height: 1.5;">
                    {details_panel}
                </td>
            </tr>
            """
            
        if not findings_html:
            findings_html = """
            <tr>
                <td colspan="5" style="padding: 20px; text-align: center; color: #64748b;">
                    No security issues found! Your AWS account meets all checked guidelines.
                </td>
            </tr>
            """

        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>{report_title}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            line-height: 1.5;
            color: #334155;
            background-color: #f8fafc;
            margin: 0;
            padding: 24px;
        }}
        .container {{
            max-width: 1100px;
            margin: 0 auto;
            background: #ffffff;
            border-radius: 12px;
            box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1);
            padding: 32px;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid #e2e8f0;
            padding-bottom: 20px;
            margin-bottom: 24px;
        }}
        .title {{
            margin: 0;
            font-size: 26px;
            color: #0f172a;
        }}
        .meta-info {{
            color: #64748b;
            font-size: 13px;
            margin-top: 4px;
        }}
        .score-box {{
            text-align: center;
            background-color: #f8fafc;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 16px;
            width: 140px;
        }}
        .score-val {{
            font-size: 36px;
            font-weight: 800;
            margin-top: 4px;
        }}
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 32px;
        }}
        .metric-card {{
            background-color: #f8fafc;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 16px;
            text-align: center;
        }}
        .metric-title {{
            font-size: 12px;
            color: #64748b;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            font-weight: 600;
        }}
        .metric-value {{
            font-size: 24px;
            font-weight: 700;
            margin-top: 4px;
            color: #0f172a;
        }}
        .findings-table {{
            width: 100%;
            border-collapse: collapse;
            text-align: left;
        }}
        .findings-table th {{
            background-color: #f1f5f9;
            color: #475569;
            font-weight: 600;
            padding: 12px;
            font-size: 13.5px;
            border-bottom: 2px solid #e2e8f0;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1 class="title">{report_title}</h1>
                <div class="meta-info">
                    {subtitle}
                </div>
                <div class="meta-info" style="margin-top: 10px;">
                    Scan ID: <strong>{self.summary['id']}</strong> &bull; 
                    Date: <strong>{self.summary['timestamp']}</strong> &bull; 
                    Type: <strong>Live AWS Scan</strong>
                </div>
                <div class="meta-info">
                    Regions scanned: {", ".join(self.summary['regions'])}
                </div>
            </div>
            <div class="score-box">
                <div class="metric-title">Security Score</div>
                <div class="score-val" style="color: {score_color};">{score}/100</div>
            </div>
        </div>

        {exec_summary}

        <div class="metrics-grid">
            <div class="metric-card" style="border-top: 4px solid #ef4444;">
                <div class="metric-title" style="color: #991b1b;">Critical</div>
                <div class="metric-value">{self.summary['critical_count']}</div>
            </div>
            <div class="metric-card" style="border-top: 4px solid #f97316;">
                <div class="metric-title" style="color: #c2410c;">High</div>
                <div class="metric-value">{self.summary['high_count']}</div>
            </div>
            <div class="metric-card" style="border-top: 4px solid #eab308;">
                <div class="metric-title" style="color: #854d0e;">Medium</div>
                <div class="metric-value">{self.summary['medium_count']}</div>
            </div>
            <div class="metric-card" style="border-top: 4px solid #16a34a;">
                <div class="metric-title" style="color: #166534;">Low</div>
                <div class="metric-value">{self.summary['low_count']}</div>
            </div>
            <div class="metric-card">
                <div class="metric-title">Total Issues</div>
                <div class="metric-value">{self.summary['failed_checks']} / {self.summary['total_checks']}</div>
            </div>
        </div>

        <h2 style="font-size: 18px; color: #0f172a; margin-bottom: 16px;">Vulnerability Audit Report</h2>
        <table class="findings-table">
            <thead>
                <tr>
                    <th style="width: 12%;">Service</th>
                    <th style="width: 20%;">Check Rule</th>
                    <th style="width: 10%;">Severity</th>
                    <th style="width: 18%;">Resource ID</th>
                    <th style="width: 40%;">Auditing details</th>
                </tr>
            </thead>
            <tbody>
                {findings_html}
            </tbody>
        </table>
        
        <div style="margin-top: 40px; border-top: 1px solid #e2e8f0; padding-top: 16px; text-align: center; color: #94a3b8; font-size: 12px;">
            Aegis Cloud Sentinel &bull; AI-Powered Cloud Security Gemini Assistant for AWS
        </div>
    </div>
</body>
</html>
"""
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_content)
            
        return filepath

    def generate_pdf(self, audience: str = None) -> str:
        """Export scan details to a clean, professionally formatted PDF report tailored by audience."""
        suffix = f"_{audience}" if audience else ""
        filename = f"scan_report_{self.summary['id']}{suffix}.pdf"
        filepath = os.path.join(self.output_dir, filename)
        
        doc = SimpleDocTemplate(
            filepath,
            pagesize=letter,
            rightMargin=0.5 * inch,
            leftMargin=0.5 * inch,
            topMargin=0.5 * inch,
            bottomMargin=0.5 * inch
        )
        
        styles = getSampleStyleSheet()
        
        title_style = ParagraphStyle(
            name="PDFTitle",
            parent=styles["Heading1"],
            fontSize=20,
            leading=24,
            textColor=colors.HexColor("#0f172a"),
            spaceAfter=6
        )
        
        subtitle_style = ParagraphStyle(
            name="PDFSubTitle",
            parent=styles["Normal"],
            fontSize=10,
            leading=13,
            textColor=colors.HexColor("#475569"),
            spaceAfter=18
        )
        
        section_style = ParagraphStyle(
            name="PDFSection",
            parent=styles["Heading2"],
            fontSize=14,
            leading=18,
            textColor=colors.HexColor("#1e293b"),
            spaceBefore=14,
            spaceAfter=8,
            keepWithNext=True
        )
        
        body_style = ParagraphStyle(
            name="PDFBody",
            parent=styles["Normal"],
            fontSize=8.5,
            leading=11,
            textColor=colors.HexColor("#334155")
        )
        
        remediation_style = ParagraphStyle(
            name="PDFRemediation",
            parent=styles["Normal"],
            fontSize=8.0,
            leading=10.5,
            textColor=colors.HexColor("#475569")
        )
        
        story = []
        
        # Determine Title
        report_title = "Aegis Cloud Sentinel - Cloud Security Audit"
        if audience == "ciso":
            report_title = "Aegis Cloud Sentinel - CISO Executive Report"
        elif audience == "developer":
            report_title = "Aegis Cloud Sentinel - Developer Remediation Report"
        elif audience == "compliance":
            report_title = "Aegis Cloud Sentinel - Compliance Audit Report"
            
        story.append(Paragraph(report_title, title_style))
        
        meta_text = (
            f"<b>Scan Run ID:</b> {self.summary['id']}<br/>"
            f"<b>Date:</b> {self.summary['timestamp']}<br/>"
            f"<b>Scan Type:</b> LIVE AWS SCAN RUN | <b>Regions Scanned:</b> {', '.join(self.summary['regions'])}"
        )
        story.append(Paragraph(meta_text, subtitle_style))
        
        # --- SUMMARY SCORE DASHBOARD ---
        score = self.summary["score"]
        score_color = colors.HexColor("#ef4444")
        if score >= 90:
            score_color = colors.HexColor("#22c55e")
        elif score >= 70:
            score_color = colors.HexColor("#eab308")
        elif score >= 50:
            score_color = colors.HexColor("#f97316")
            
        dashboard_data = [
            [
                Paragraph("<b>SECURITY SCORE</b>", body_style),
                Paragraph("<b>CRITICAL</b>", body_style),
                Paragraph("<b>HIGH</b>", body_style),
                Paragraph("<b>MEDIUM</b>", body_style),
                Paragraph("<b>LOW</b>", body_style),
                Paragraph("<b>TOTAL CHECKS</b>", body_style)
            ],
            [
                Paragraph(f"<font size=18 color='{score_color}'><b>{score}/100</b></font>", body_style),
                Paragraph(f"<font size=12 color='#991b1b'><b>{self.summary['critical_count']}</b></font>", body_style),
                Paragraph(f"<font size=12 color='#c2410c'><b>{self.summary['high_count']}</b></font>", body_style),
                Paragraph(f"<font size=12 color='#854d0e'><b>{self.summary['medium_count']}</b></font>", body_style),
                Paragraph(f"<font size=12 color='#166534'><b>{self.summary['low_count']}</b></font>", body_style),
                Paragraph(f"<font size=12 color='#0f172a'><b>{self.summary['failed_checks']}/{self.summary['total_checks']}</b></font>", body_style)
            ]
        ]
        
        t_dash = Table(dashboard_data, colWidths=[1.5*inch, 1*inch, 1*inch, 1*inch, 1*inch, 2*inch])
        t_dash.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#f1f5f9")),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
            ('BOTTOMPADDING', (0,0), (-1,-1), 8),
            ('TOPPADDING', (0,0), (-1,-1), 8),
        ]))
        
        story.append(t_dash)
        story.append(Spacer(1, 16))
        
        # --- EXECUTIVE SUMMARY FOR CISO ---
        if audience == "ciso":
            ciso_summary = (
                "<b>CISO Executive Risk Assessment Summary:</b><br/>"
                "Our automated engine evaluated your AWS security baseline configurations. "
                "Exposures were detected in core areas like Identity Management (MFA settings) and Network Firewalls. "
                "Immediate priorities must focus on removing wide wildcard IAM permissions and public network gateways. "
                "Remediating these top exposures reduces overall account takeover risks by up to 90%."
            )
            story.append(Paragraph(ciso_summary, remediation_style))
            story.append(Spacer(1, 14))
        
        # --- FINDINGS SECTION ---
        story.append(Paragraph("Vulnerability Logs", section_style))
        story.append(Spacer(1, 6))
        
        # Build detailed findings table
        findings_table_data = [
            [
                Paragraph("<b>Service</b>", body_style),
                Paragraph("<b>Check Rule</b>", body_style),
                Paragraph("<b>Severity</b>", body_style),
                Paragraph("<b>Resource</b>", body_style),
                Paragraph("<b>Auditing Details</b>", body_style)
            ]
        ]
        
        for f in self.findings:
            if f["status"] == "PASS" and audience != "compliance":
                continue
                
            sev = f["severity"]
            if sev == "CRITICAL":
                sev_p = Paragraph("<font color='#991b1b'><b>CRITICAL</b></font>", body_style)
            elif sev == "HIGH":
                sev_p = Paragraph("<font color='#c2410c'><b>HIGH</b></font>", body_style)
            elif sev == "MEDIUM":
                sev_p = Paragraph("<font color='#854d0e'><b>MEDIUM</b></font>", body_style)
            else:
                sev_p = Paragraph("<font color='#166534'><b>LOW</b></font>", body_style)
                
            service_p = Paragraph(f["service"], body_style)
            check_p = Paragraph(f["check_name"], body_style)
            resource_p = Paragraph(f["resource_id"], body_style)
            
            # Fetch metadata
            meta = SECURITY_METADATA.get(f["check_id"], {})
            
            # Formulate detail paragraph by audience
            if audience == "ciso":
                detail_text = (
                    f"<b>Why dangerous:</b> {meta.get('why_dangerous', f['message'])}<br/>"
                    f"<b>Estimated Impact:</b> <font color='#991b1b'>{meta.get('estimated_impact', 'Risk of account compromise.')}</font>"
                )
            elif audience == "developer":
                tf_code = meta.get('fix_terraform', '# Code not defined').replace('\n', '<br/>').replace(' ', '&nbsp;')
                detail_text = (
                    f"<b>Issue:</b> {f['message']}<br/>"
                    f"<b>Terraform snippet:</b><br/>"
                    f"<font face='Courier' size=7 color='#1e293b'>{tf_code}</font>"
                )
            elif audience == "compliance":
                status_str = f"<b>STATUS:</b> <font color='#16a34a'>PASS</font>" if f["status"] == "PASS" else f"<b>STATUS:</b> <font color='#dc2626'>FAIL</font>"
                detail_text = (
                    f"{status_str}<br/>"
                    f"<b>CIS Reference:</b> {meta.get('cis_benchmark', 'N/A')}<br/>"
                    f"<b>MITRE ATT&CK:</b> {meta.get('mitre_attack', 'N/A')}<br/>"
                    f"<b>Finding:</b> {f['message']}"
                )
            else: # Cloud Engineer / default
                detail_text = (
                    f"<b>Finding:</b> {f['message']}<br/>"
                    f"<b>Remediation:</b> {meta.get('fix_console', f['remediation'])}"
                )
                
            detail_p = Paragraph(detail_text, remediation_style)
            findings_table_data.append([service_p, check_p, sev_p, resource_p, detail_p])
            
        if len(findings_table_data) == 1:
            findings_table_data.append([Paragraph("No active findings found.", body_style), "", "", "", ""])
            
        t_findings = Table(
            findings_table_data, 
            colWidths=[0.8*inch, 1.4*inch, 0.8*inch, 1.3*inch, 3.2*inch],
            repeatRows=1
        )
        t_findings.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#f1f5f9")),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ]))
        
        story.append(t_findings)
        
        # Build PDF document
        doc.build(story)
        
        return filepath
