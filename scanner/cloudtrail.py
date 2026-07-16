import logging
from botocore.exceptions import ClientError
from scanner.base import BaseScanner

logger = logging.getLogger("cspm.scanner.cloudtrail")

class CloudTrailScanner(BaseScanner):
    """Scanner for AWS CloudTrail auditing logs."""
    
    def run_checks(self) -> list:
        findings = []
        if not self.session:
            logger.warning("No active session provided to CloudTrailScanner.")
            return findings

        # CloudTrail trails can be inspected from a main region (e.g. us-east-1)
        region = self.regions[0] if self.regions else "us-east-1"
        try:
            ct_client = self.session.client("cloudtrail", region_name=region)
        except ClientError as e:
            logger.error(f"Failed to create CloudTrail client in {region}: {e}")
            return findings

        try:
            resp = ct_client.describe_trails()
            trails = resp.get("trailList", [])
        except ClientError as e:
            logger.error(f"Failed to describe CloudTrails: {e}")
            findings.append(self.create_finding(
                "CLOUDTRAIL_DESCRIBE_ERROR", "Read CloudTrail Status", "HIGH", "FAIL",
                "cloudtrail-service", region,
                f"Error listing CloudTrails: {e}",
                "Ensure scanner IAM permissions permit cloudtrail:DescribeTrails."
            ))
            return findings

        if not trails:
            findings.append(self.create_finding(
                "CLOUDTRAIL_ENABLED", "CloudTrail Enabled", "HIGH", "FAIL",
                "account-trails", region,
                "No CloudTrail audit trails were found in this account.",
                "Create a new CloudTrail trail in the AWS console to start tracking account APIs."
            ))
        else:
            for trail in trails:
                trail_arn = trail["TrailARN"]
                trail_name = trail["Name"]
                trail_region = trail.get("HomeRegion", region)
                
                # Check status
                try:
                    status_resp = ct_client.get_trail_status(Name=trail_arn)
                    is_logging = status_resp.get("IsLogging", False)
                except ClientError:
                    is_logging = True  # Fallback if status reading fails
                
                # Trail Enabled
                if is_logging:
                    findings.append(self.create_finding(
                        "CLOUDTRAIL_ENABLED", "CloudTrail Enabled", "HIGH", "PASS",
                        trail_arn, trail_region,
                        f"CloudTrail trail '{trail_name}' is enabled and active.",
                        "None required."
                    ))
                else:
                    findings.append(self.create_finding(
                        "CLOUDTRAIL_ENABLED", "CloudTrail Enabled", "HIGH", "FAIL",
                        trail_arn, trail_region,
                        f"CloudTrail trail '{trail_name}' exists but is not logging activity.",
                        f"Start logging on CloudTrail trail '{trail_name}' properties."
                    ))

                # Multi-region Trail
                is_multi_region = trail.get("IsMultiRegionTrail", False)
                if is_multi_region:
                    findings.append(self.create_finding(
                        "CLOUDTRAIL_MULTI_REGION", "Multi-region Trail", "MEDIUM", "PASS",
                        trail_arn, trail_region,
                        f"CloudTrail trail '{trail_name}' is set to receive events from all regions.",
                        "None required."
                    ))
                else:
                    findings.append(self.create_finding(
                        "CLOUDTRAIL_MULTI_REGION", "Multi-region Trail", "MEDIUM", "FAIL",
                        trail_arn, trail_region,
                        f"CloudTrail trail '{trail_name}' is single-region (configured only in {trail_region}).",
                        f"Update the configuration of CloudTrail '{trail_name}' to apply to all AWS regions."
                    ))

                # Log Validation
                log_validation = trail.get("LogFileValidationEnabled", False)
                if log_validation:
                    findings.append(self.create_finding(
                        "CLOUDTRAIL_LOG_VALIDATION", "Log Validation Enabled", "LOW", "PASS",
                        trail_arn, trail_region,
                        f"Log file integrity validation is enabled for trail '{trail_name}'.",
                        "None required."
                    ))
                else:
                    findings.append(self.create_finding(
                        "CLOUDTRAIL_LOG_VALIDATION", "Log Validation Enabled", "LOW", "FAIL",
                        trail_arn, trail_region,
                        f"Log file integrity validation is disabled for trail '{trail_name}'.",
                        f"Enable log file validation on CloudTrail '{trail_name}' to protect audit logs from tampering."
                    ))

        return findings
