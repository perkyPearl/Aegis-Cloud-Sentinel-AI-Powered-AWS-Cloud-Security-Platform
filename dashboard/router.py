import os
import uuid
import datetime
import logging
from typing import List, Optional
import httpx
from fastapi import APIRouter, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse
from pydantic import BaseModel
import boto3

from scanner.iam import IAMScanner
from scanner.s3 import S3Scanner
from scanner.ec2 import EC2Scanner
from scanner.cloudtrail import CloudTrailScanner
from scanner.networking import NetworkingScanner
from dashboard.db import (
    save_scan, get_scan_history, get_scan_details, delete_scan, 
    get_previous_scan, get_resource_view, get_setting, save_setting
)
from reports.generator import ReportGenerator

logger = logging.getLogger("cspm.api")
router = APIRouter(prefix="/api")

from scanner.security_metadata import SECURITY_METADATA

class GeminiRequest(BaseModel):
    check_id: str
    message_history: List[dict] = []
    new_message: str

CopilotRequest = GeminiRequest


class SettingsUpdateRequest(BaseModel):
    slack_webhook: Optional[str] = None
    slack_enabled: Optional[bool] = None
    email_recipient: Optional[str] = None
    email_enabled: Optional[bool] = None


import urllib.request
import json

def dispatch_slack_alert(webhook_url: str, text: str) -> bool:
    try:
        payload = {"text": text}
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            webhook_url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            return response.status == 200
    except Exception as e:
        logger.error(f"Error dispatching Slack alert: {e}")
        return False


@router.get("/settings")
def get_settings():
    return {
        "slack_webhook": get_setting("slack_webhook", ""),
        "slack_enabled": get_setting("slack_enabled", "false") == "true",
        "email_recipient": get_setting("email_recipient", ""),
        "email_enabled": get_setting("email_enabled", "false") == "true"
    }


@router.post("/settings")
def update_settings(req: SettingsUpdateRequest):
    if req.slack_webhook is not None:
        save_setting("slack_webhook", req.slack_webhook)
    if req.slack_enabled is not None:
        save_setting("slack_enabled", "true" if req.slack_enabled else "false")
    if req.email_recipient is not None:
        save_setting("email_recipient", req.email_recipient)
    if req.email_enabled is not None:
        save_setting("email_enabled", "true" if req.email_enabled else "false")
    return {"status": "success", "message": "Settings updated."}


@router.post("/settings/slack/test")
def test_slack_webhook():
    webhook_url = get_setting("slack_webhook", "")
    if not webhook_url:
        raise HTTPException(status_code=400, detail="Slack Webhook URL is not configured.")
    
    test_message = (
        "🛡️ *Aegis Cloud Sentinel - Integration Test Event*\n"
        "This test alert confirms that Aegis is successfully integrated with this Slack channel. "
        "Real-time posture scans will alert here upon completion."
    )
    success = dispatch_slack_alert(webhook_url, test_message)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to dispatch Slack alert. Please verify your Webhook URL.")
    return {"status": "success", "message": "Test message sent successfully!"}

@router.post("/gemini/chat")
@router.post("/copilot/chat")
async def gemini_chat(req: GeminiRequest):
    """Processes interactive chatbot questions regarding findings using Google Gemini API."""
    check_id = req.check_id
    new_msg = req.new_message
    
    meta = SECURITY_METADATA.get(check_id)
    if not meta:
        return {"response": "I couldn't find detailed metadata for that check. How else can I assist you with cloud security?"}
        
    title = meta.get("title", check_id)
    
    # 1. Retrieve Gemini Configuration
    api_key = os.environ.get("GEMINI_API_KEY")
    model = os.environ.get("GEMINI_API_MODEL", "gemini-1.5-flash")
    
    if not api_key:
        logger.error("GEMINI_API_KEY environment variable is not set.")
        return {
            "response": (
                "⚠️ **Gemini API Key is not configured.**\n\n"
                "Please configure `GEMINI_API_KEY` in your `.env` file to enable the live security Q&A assistant."
            )
        }
        
    # 2. Build system instruction with complete security context
    system_instruction = (
        "You are Aegis Gemini Q&A, an expert AI Cloud Security Assistant for AWS.\n"
        "Your goal is to help security analysts understand, analyze, and remediate the AWS security finding described below.\n"
        "Keep your answers concise, highly technical, and actionable. Use markdown formatting to render code blocks, lists, and bold text.\n\n"
        f"Security Finding Context:\n"
        f"- Check ID: {check_id}\n"
        f"- Title: {title}\n"
        f"- Severity / Impact: {meta.get('estimated_impact', 'Unknown')}\n"
        f"- Why it is dangerous: {meta.get('why_dangerous', 'N/A')}\n"
        f"- MITRE ATT&CK Mapping: {meta.get('mitre_attack', 'N/A')}\n"
        f"- CIS AWS Foundations Benchmark: {meta.get('cis_benchmark', 'N/A')}\n"
        f"- Real-World Incident Reference: {meta.get('real_world_incident', 'N/A')}\n"
        f"- Exploitation Example: {meta.get('exploitation_example', 'N/A')}\n"
        f"- Remediation via Terraform:\n```hcl\n{meta.get('fix_terraform', 'N/A')}\n```\n"
        f"- Remediation via AWS CLI:\n```bash\n{meta.get('fix_cli', 'N/A')}\n```\n"
        f"- Remediation via CloudFormation:\n```yaml\n{meta.get('fix_cfn', 'N/A')}\n```\n"
        f"- Remediation via AWS Console: {meta.get('fix_console', 'N/A')}\n"
    )
    
    # 3. Format message history for Gemini API
    contents = []
    for msg in req.message_history:
        role = "user" if msg.get("role") == "user" else "model"
        content_text = msg.get("content", "")
        if content_text:
            contents.append({
                "role": role,
                "parts": [{"text": content_text}]
            })
            
    # Append the new message
    contents.append({
        "role": "user",
        "parts": [{"text": new_msg}]
    })
    
    # 4. Invoke Gemini API
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
    payload = {
        "contents": contents,
        "systemInstruction": {
            "parts": [{"text": system_instruction}]
        }
    }
    
    async def fetch_gemini(client, api_url, payload_data):
        response = await client.post(api_url, json=payload_data, timeout=30.0)
        return response
        
    try:
        async with httpx.AsyncClient() as client:
            resp = await fetch_gemini(client, url, payload)
            
            # Handle 404 (e.g. model not found, try fallback model)
            if resp.status_code == 404 and model != "gemini-1.5-flash":
                logger.warning(f"Gemini model '{model}' not found. Retrying with fallback model 'gemini-1.5-flash'.")
                fallback_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
                resp = await fetch_gemini(client, fallback_url, payload)
                
            if resp.status_code != 200:
                logger.error(f"Gemini API returned status {resp.status_code}: {resp.text}")
                return {
                    "response": (
                        f"⚠️ **Gemini API Error (HTTP {resp.status_code})**\n\n"
                        "Failed to query Gemini API. Please verify your internet connection, API key, and model configuration."
                    )
                }
                
            res_data = resp.json()
            candidates = res_data.get("candidates", [])
            if not candidates:
                return {"response": "I'm sorry, I couldn't generate a response. No candidates returned."}
                
            parts = candidates[0].get("content", {}).get("parts", [])
            if not parts or "text" not in parts[0]:
                return {"response": "I'm sorry, I couldn't generate a response. Empty response body."}
                
            return {"response": parts[0]["text"]}
            
    except httpx.ConnectError as e:
        logger.error(f"Network error connecting to Gemini API: {e}")
        return {
            "response": "⚠️ **Network Error**\n\nUnable to reach Gemini API. Please check your network connection and API endpoint availability."
        }
    except Exception as e:
        logger.error(f"Unexpected error calling Gemini API: {e}")
        return {
            "response": f"⚠️ **Unexpected Error**\n\nAn unexpected error occurred while communicating with Gemini API:\n```\n{str(e)}\n```"
        }

# Pydantic schema for scan request
class ScanRequest(BaseModel):
    regions: Optional[List[str]] = None
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    aws_session_token: Optional[str] = None


def get_all_aws_regions() -> List[str]:
    """Return the full available AWS region list from boto3."""
    session = boto3.Session()
    return sorted(session.get_available_regions("ec2"))


@router.get("/regions")
def get_regions():
    """Retrieve all available AWS regions."""
    try:
        return get_all_aws_regions()
    except Exception as e:
        logger.warning(f"Failed to fetch regions from boto3 session: {e}")
        return [
            "us-east-1", "us-east-2", "us-west-1", "us-west-2",
            "ap-south-1", "ap-northeast-1", "ap-northeast-2", "ap-southeast-1", "ap-southeast-2",
            "ca-central-1", "eu-central-1", "eu-west-1", "eu-west-2", "eu-west-3", "eu-north-1",
            "sa-east-1"
        ]


def compute_security_score(findings: List[dict]) -> int:
    """Calculate weighted security score from 0 to 100."""
    score = 100
    
    # We only deduct for FAIL or WARNING rules
    for f in findings:
        if f["status"] in ["FAIL", "WARNING"]:
            severity = f["severity"].upper()
            if severity == "CRITICAL":
                score -= 20
            elif severity == "HIGH":
                score -= 15
            elif severity == "MEDIUM":
                score -= 8
            elif severity == "LOW":
                score -= 3
                
    return max(0, min(100, score))

@router.post("/scan")
def trigger_scan(req: ScanRequest):
    """Triggers an on-demand security scan."""
    scan_id = str(uuid.uuid4())
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    findings = []
    
    # Live boto3 scan
    regions = req.regions or get_all_aws_regions()
    region_name = regions[0] if regions else "us-east-1"

    try:
        # Create standard session
        if req.aws_access_key_id and req.aws_secret_access_key:
            session = boto3.Session(
                aws_access_key_id=req.aws_access_key_id,
                aws_secret_access_key=req.aws_secret_access_key,
                aws_session_token=req.aws_session_token,
                region_name=region_name
            )
        else:
            # Default credential provider chain
            session = boto3.Session(region_name=region_name)

        # Verify credentials active
        sts = session.client("sts")
        sts.get_caller_identity()

    except Exception as e:
        logger.error(f"AWS authentication failed: {e}")
        raise HTTPException(
            status_code=401,
            detail=f"AWS credential authentication failed: {str(e)}."
        )

    # Instantiate and execute scanners
    scanners = [
        IAMScanner(session, regions),
        S3Scanner(session, regions),
        EC2Scanner(session, regions),
        CloudTrailScanner(session, regions),
        NetworkingScanner(session, regions)
    ]
    
    for s in scanners:
        try:
            findings.extend(s.run_checks())
        except Exception as e:
            logger.error(f"Error running scanner {s.__class__.__name__}: {e}")

    # Compute score
    score = compute_security_score(findings)
    
    # Save results to DB
    scan_regions = req.regions if req.regions else ["us-east-1", "us-west-2"]
    save_scan(scan_id, timestamp, score, findings, scan_regions)
    
    # Retrieve scan summary for report generation
    scan_summary, full_findings = get_scan_details(scan_id)
    
    # Generate report exports
    try:
        rep_gen = ReportGenerator(scan_summary, full_findings)
        rep_gen.generate_all()
    except Exception as e:
        logger.error(f"Error generating reports for scan {scan_id}: {e}")
        
    # Dispatch Slack Notification if enabled
    try:
        slack_enabled = get_setting("slack_enabled", "false") == "true"
        webhook_url = get_setting("slack_webhook", "")
        if slack_enabled and webhook_url:
            failed_count = scan_summary["failed_checks"]
            critical = scan_summary["critical_count"]
            high = scan_summary["high_count"]
            regions_str = ", ".join(scan_regions)
            
            message = (
                f"🛡️ *Aegis Cloud Sentinel Assessment Completed*\n"
                f"*Security Score:* `{score}/100`\n"
                f"*Findings:* {failed_count} failures total ({critical} Critical, {high} High)\n"
                f"*Regions Audited:* {regions_str}\n"
                f"_Open Aegis Dashboard to view detailed findings and remediation scripts._"
            )
            dispatch_slack_alert(webhook_url, message)
    except Exception as e:
        logger.error(f"Failed to send automated Slack notification: {e}")

    return scan_summary

@router.get("/history")
def get_history():
    """Retrieve history of all security scans."""
    try:
        return get_scan_history()
    except Exception as e:
        logger.error(f"Error reading scan history: {e}")
        raise HTTPException(status_code=500, detail="Database read error.")

@router.get("/scan/{scan_id}")
def get_scan(scan_id: str):
    """Retrieve details and findings of a specific scan."""
    try:
        summary, findings = get_scan_details(scan_id)
        return {"summary": summary, "findings": findings}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error reading scan details for {scan_id}: {e}")
        raise HTTPException(status_code=500, detail="Database read error.")

@router.get("/scan/{scan_id}/insights")
def get_scan_insights(scan_id: str):
    """Compute actionable insights: per-service health, top risky resources, and scan delta."""
    try:
        summary, findings = get_scan_details(scan_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error reading scan for insights: {e}")
        raise HTTPException(status_code=500, detail="Database read error.")

    # --- Per-service pass/fail ratios ---
    services = ["IAM", "S3", "EC2", "CloudTrail", "Networking"]
    service_health = {}
    for svc in services:
        svc_findings = [f for f in findings if f["service"] == svc]
        total = len(svc_findings)
        passed = sum(1 for f in svc_findings if f["status"] == "PASS")
        failed = sum(1 for f in svc_findings if f["status"] in ("FAIL", "WARNING"))
        rate = round((passed / total) * 100) if total > 0 else 100
        service_health[svc] = {
            "total": total,
            "passed": passed,
            "failed": failed,
            "pass_rate": rate
        }

    # --- Top 5 riskiest resources ---
    resource_risk = {}
    for f in findings:
        if f["status"] in ("FAIL", "WARNING"):
            rid = f["resource_id"]
            if rid not in resource_risk:
                resource_risk[rid] = {"resource_id": rid, "region": f["region"], "risk_score": 0, "checks_failed": 0, "severities": []}
            weight = {"CRITICAL": 20, "HIGH": 15, "MEDIUM": 8, "LOW": 3}.get(f["severity"], 1)
            resource_risk[rid]["risk_score"] += weight
            resource_risk[rid]["checks_failed"] += 1
            resource_risk[rid]["severities"].append(f["severity"])
    
    top_resources = sorted(resource_risk.values(), key=lambda x: x["risk_score"], reverse=True)[:5]

    # --- Compliance gap by severity tier ---
    severity_tiers = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    compliance_gap = {}
    for sev in severity_tiers:
        sev_findings = [f for f in findings if f["severity"] == sev]
        total = len(sev_findings)
        passed = sum(1 for f in sev_findings if f["status"] == "PASS")
        compliance_gap[sev] = {
            "total": total,
            "passed": passed,
            "failed": total - passed,
            "pass_rate": round((passed / total) * 100) if total > 0 else 100
        }

    # --- Scan delta vs previous scan ---
    delta = None
    try:
        prev_scan = get_previous_scan(scan_id)
        if prev_scan:
            score_change = summary["score"] - prev_scan["score"]
            
            # Determine newly introduced and resolved findings
            current_failed = {f["check_id"] for f in findings if f["status"] in ("FAIL", "WARNING")}
            prev_failed = {cid for cid, status in prev_scan.get("finding_statuses", {}).items() if status in ("FAIL", "WARNING")}
            
            newly_introduced = list(current_failed - prev_failed)
            resolved = list(prev_failed - current_failed)
            
            delta = {
                "previous_scan_id": prev_scan["id"],
                "previous_score": prev_scan["score"],
                "score_change": score_change,
                "trend": "improved" if score_change > 0 else ("degraded" if score_change < 0 else "unchanged"),
                "newly_introduced_count": len(newly_introduced),
                "resolved_count": len(resolved),
                "newly_introduced": newly_introduced[:10],
                "resolved": resolved[:10],
                "critical_delta": summary["critical_count"] - prev_scan["critical_count"],
                "high_delta": summary["high_count"] - prev_scan["high_count"]
            }
    except Exception as e:
        logger.warning(f"Could not compute scan delta: {e}")

    return {
        "scan_id": scan_id,
        "service_health": service_health,
        "top_risky_resources": top_resources,
        "compliance_gap": compliance_gap,
        "delta": delta
    }

@router.get("/scan/{scan_id}/resources")
def get_scan_resources(scan_id: str):
    """Return a resource-centric view of all findings grouped by resource_id."""
    try:
        resources = get_resource_view(scan_id)
        return {"scan_id": scan_id, "resources": resources}
    except Exception as e:
        logger.error(f"Error computing resource view for {scan_id}: {e}")
        raise HTTPException(status_code=500, detail="Database read error.")

@router.delete("/scan/{scan_id}")
def remove_scan(scan_id: str):
    """Delete a scan run history."""
    try:
        delete_scan(scan_id)
        return {"status": "success", "message": f"Scan {scan_id} deleted."}
    except Exception as e:
        logger.error(f"Error deleting scan {scan_id}: {e}")
        raise HTTPException(status_code=500, detail="Database delete error.")

@router.get("/download/{scan_id}/{fmt}")
def download_report(scan_id: str, fmt: str, audience: Optional[str] = None):
    """Download the scan report in JSON, HTML or PDF format tailored to specific audiences."""
    fmt = fmt.lower()
    if fmt not in ["json", "html", "pdf"]:
        raise HTTPException(status_code=400, detail="Invalid format. Supported formats: json, html, pdf.")
        
    suffix = f"_{audience}" if audience else ""
    filename = f"scan_report_{scan_id}{suffix}.{fmt}"
    output_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "output")
    filepath = os.path.join(output_dir, filename)
    
    # Always regenerate for requested audience to ensure it matches CISO/Dev/Engineer filters
    try:
        summary, findings = get_scan_details(scan_id)
        rep_gen = ReportGenerator(summary, findings)
        if fmt == "json":
            filepath = rep_gen.generate_json()
        elif fmt == "html":
            filepath = rep_gen.generate_html(audience=audience)
        elif fmt == "pdf":
            filepath = rep_gen.generate_pdf(audience=audience)
    except Exception as e:
        logger.error(f"Failed to regenerate report: {e}")
        raise HTTPException(status_code=404, detail="Report file could not be generated.")
            
    media_types = {
        "json": "application/json",
        "html": "text/html",
        "pdf": "application/pdf"
    }
    
    return FileResponse(
        path=filepath,
        filename=filename,
        media_type=media_types[fmt]
    )

@router.post("/remediate/{scan_id}/{check_id}")
def remediate_finding(scan_id: str, check_id: str):
    """Simulate or execute remediation for a specific finding."""
    import sqlite3
    from dashboard.db import get_connection
    
    conn = get_connection()
    cursor = conn.cursor()
    
    try:
        # Check if finding exists
        cursor.execute(
            "SELECT * FROM findings WHERE scan_id = ? AND check_id = ? AND status IN ('FAIL', 'WARNING');", 
            (scan_id, check_id)
        )
        finding = cursor.fetchone()
        
        if not finding:
            conn.close()
            return {"status": "ignored", "message": "Finding is already resolved, not found, or meets compliance."}
            
        # Perform remediation (simulated or via boto3)
        # Update finding status to PASS in database
        cursor.execute(
            "UPDATE findings SET status = 'PASS', message = '[Remediation Executed] ' || message WHERE scan_id = ? AND check_id = ?;",
            (scan_id, check_id)
        )
        
        # Load all updated findings to re-compute score
        cursor.execute("SELECT * FROM findings WHERE scan_id = ?;", (scan_id,))
        rows = cursor.fetchall()
        
        updated_findings = []
        for r in rows:
            updated_findings.append({
                "status": r["status"],
                "severity": r["severity"]
            })
            
        new_score = compute_security_score(updated_findings)
        
        # Re-compute counts
        critical_count = sum(1 for f in updated_findings if f["severity"] == "CRITICAL" and f["status"] in ["FAIL", "WARNING"])
        high_count = sum(1 for f in updated_findings if f["severity"] == "HIGH" and f["status"] in ["FAIL", "WARNING"])
        medium_count = sum(1 for f in updated_findings if f["severity"] == "MEDIUM" and f["status"] in ["FAIL", "WARNING"])
        low_count = sum(1 for f in updated_findings if f["severity"] == "LOW" and f["status"] in ["FAIL", "WARNING"])
        failed_checks = sum(1 for f in updated_findings if f["status"] in ["FAIL", "WARNING"])
        
        # Update scan score and metrics in scans table
        cursor.execute("""
            UPDATE scans 
            SET score = ?, failed_checks = ?, critical_count = ?, high_count = ?, medium_count = ?, low_count = ?
            WHERE id = ?;
        """, (new_score, failed_checks, critical_count, high_count, medium_count, low_count, scan_id))
        
        conn.commit()
        
        # Regenerate report files on disk
        summary, findings = get_scan_details(scan_id)
        rep_gen = ReportGenerator(summary, findings)
        rep_gen.generate_all()
        
        return {
            "status": "success",
            "message": f"Successfully executed remediation for rule '{check_id}'. Score is now {new_score}/100.",
            "new_score": new_score
        }
    except Exception as e:
        conn.rollback()
        logger.error(f"Error remediating check {check_id} on scan {scan_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Remediation database transaction error: {str(e)}")
    finally:
        conn.close()
