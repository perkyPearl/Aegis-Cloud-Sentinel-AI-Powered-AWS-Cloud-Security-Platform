import random
from typing import Any, Dict, List

def generate_mock_findings() -> List[Dict[str, Any]]:
    """Generate a rich, realistic list of AWS security scan findings for demonstration/testing."""
    findings = [
        # --- IAM ---
        {
            "check_id": "IAM_ROOT_MFA",
            "service": "IAM",
            "check_name": "Root MFA Enabled",
            "severity": "CRITICAL",
            "status": "FAIL",
            "resource_id": "arn:aws:iam::123456789012:root",
            "region": "global",
            "message": "Root account does not have Multi-Factor Authentication (MFA) enabled. This is a severe security risk.",
            "remediation": "Log in as the root user, go to the IAM console, select 'Security credentials', and enable MFA (Virtual or Hardware U2F)."
        },
        {
            "check_id": "IAM_USER_MFA",
            "service": "IAM",
            "check_name": "IAM Users Without MFA",
            "severity": "HIGH",
            "status": "FAIL",
            "resource_id": "arn:aws:iam::123456789012:user/developer-bob",
            "region": "global",
            "message": "IAM User 'developer-bob' does not have MFA enabled.",
            "remediation": "Have the user log in and configure MFA, or enforce MFA through an IAM Policy for all console operations."
        },
        {
            "check_id": "IAM_USER_MFA",
            "service": "IAM",
            "check_name": "IAM Users Without MFA",
            "severity": "HIGH",
            "status": "PASS",
            "resource_id": "arn:aws:iam::123456789012:user/admin-alice",
            "region": "global",
            "message": "IAM User 'admin-alice' has MFA configured properly.",
            "remediation": "None required."
        },
        {
            "check_id": "IAM_ACCESS_KEY_AGE",
            "service": "IAM",
            "check_name": "Access Keys Older Than 90 Days",
            "severity": "MEDIUM",
            "status": "FAIL",
            "resource_id": "arn:aws:iam::123456789012:user/jenkins-ci (Key: AKIAIOSFODNN7EXAMPLE)",
            "region": "global",
            "message": "Access Key 'AKIAIOSFODNN7EXAMPLE' is 142 days old (threshold: 90 days).",
            "remediation": "Generate a new access key, swap it in your applications, and deactivate/delete the old key."
        },
        {
            "check_id": "IAM_ADMIN_ACCESS",
            "service": "IAM",
            "check_name": "Users with AdministratorAccess",
            "severity": "HIGH",
            "status": "WARNING",
            "resource_id": "arn:aws:iam::123456789012:user/admin-alice",
            "region": "global",
            "message": "IAM User 'admin-alice' has direct AdministratorAccess. It is recommended to use IAM roles instead.",
            "remediation": "Remove the AdministratorAccess policy from the user and assign them to an IAM Group or Role with specific permissions."
        },
        {
            "check_id": "IAM_WILDCARD_POLICIES",
            "service": "IAM",
            "check_name": "Wildcard IAM Policies",
            "severity": "HIGH",
            "status": "FAIL",
            "resource_id": "arn:aws:iam::123456789012:policy/UnsafeS3AdminPolicy",
            "region": "global",
            "message": "IAM Policy 'UnsafeS3AdminPolicy' allows wildcard access (s3:*) on all resources (*).",
            "remediation": "Restrict the policy by specifying exact S3 actions (e.g. s3:GetObject) and target bucket ARNs."
        },
        {
            "check_id": "IAM_INACTIVE_USERS",
            "service": "IAM",
            "check_name": "Inactive IAM Users",
            "severity": "MEDIUM",
            "status": "FAIL",
            "resource_id": "arn:aws:iam::123456789012:user/retired-charlie",
            "region": "global",
            "message": "IAM User 'retired-charlie' has not logged in or used credentials for 180 days.",
            "remediation": "Deactivate user credentials, remove them from groups, and delete the user account if no longer needed."
        },
        {
            "check_id": "IAM_UNUSED_ROLES",
            "service": "IAM",
            "check_name": "Unused IAM Roles",
            "severity": "LOW",
            "status": "WARNING",
            "resource_id": "arn:aws:iam::123456789012:role/LegacyLambdaExecutionRole",
            "region": "global",
            "message": "IAM Role 'LegacyLambdaExecutionRole' has not been assumed for 120 days.",
            "remediation": "Verify if the role is still used. If not, delete the role to reduce security surface area."
        },
        
        # --- S3 ---
        {
            "check_id": "S3_PUBLIC_BUCKETS",
            "service": "S3",
            "check_name": "Public Buckets",
            "severity": "CRITICAL",
            "status": "FAIL",
            "resource_id": "my-public-reports-bucket",
            "region": "us-east-1",
            "message": "S3 Bucket 'my-public-reports-bucket' has public access enabled via bucket policy.",
            "remediation": "Edit the bucket policy to restrict access to VPC endpoints or specific IAM accounts, and enable Block Public Access."
        },
        {
            "check_id": "S3_PUBLIC_BUCKETS",
            "service": "S3",
            "check_name": "Public Buckets",
            "severity": "CRITICAL",
            "status": "PASS",
            "resource_id": "secure-financials-2026",
            "region": "us-west-2",
            "message": "S3 Bucket 'secure-financials-2026' is private and not exposed to the public.",
            "remediation": "None required."
        },
        {
            "check_id": "S3_BUCKET_ENCRYPTION",
            "service": "S3",
            "check_name": "Bucket Encryption Enabled",
            "severity": "HIGH",
            "status": "FAIL",
            "resource_id": "temp-scratchpad-bucket",
            "region": "us-east-1",
            "message": "S3 Bucket 'temp-scratchpad-bucket' does not have default server-side encryption (SSE) enabled.",
            "remediation": "Go to bucket properties, edit 'Default encryption', select AES-256 (SSE-S3) or AWS-KMS, and save changes."
        },
        {
            "check_id": "S3_VERSIONING_ENABLED",
            "service": "S3",
            "check_name": "Versioning Enabled",
            "severity": "LOW",
            "status": "FAIL",
            "resource_id": "my-public-reports-bucket",
            "region": "us-east-1",
            "message": "S3 Bucket versioning is disabled. Deletions and updates are permanent.",
            "remediation": "Enable bucket versioning in the S3 properties page to protect against accidental deletions."
        },
        {
            "check_id": "S3_LOGGING_ENABLED",
            "service": "S3",
            "check_name": "Logging Enabled",
            "severity": "MEDIUM",
            "status": "FAIL",
            "resource_id": "secure-financials-2026",
            "region": "us-west-2",
            "message": "Server access logging is not enabled on bucket 'secure-financials-2026'.",
            "remediation": "Configure S3 bucket logging to save access logs to a separate dedicated logs bucket."
        },
        {
            "check_id": "S3_BLOCK_PUBLIC_ACCESS",
            "service": "S3",
            "check_name": "Block Public Access Enabled",
            "severity": "HIGH",
            "status": "FAIL",
            "resource_id": "temp-scratchpad-bucket",
            "region": "us-east-1",
            "message": "Block Public Access settings are not fully enabled (currently set to False).",
            "remediation": "Edit Block Public Access settings on the bucket properties page and check 'Block all public access'."
        },

        # --- EC2 ---
        {
            "check_id": "EC2_PUBLIC_INSTANCES",
            "service": "EC2",
            "check_name": "Public Instances",
            "severity": "HIGH",
            "status": "FAIL",
            "resource_id": "i-0abcd1234efgh5678 (prod-webserver)",
            "region": "us-east-1",
            "message": "Instance 'prod-webserver' has a public IP (54.210.43.99) and resides in a public subnet.",
            "remediation": "Move the instance to a private subnet and route outbound traffic through a NAT Gateway."
        },
        {
            "check_id": "EC2_SG_EXPOSED_SSH",
            "service": "EC2",
            "check_name": "Security Groups Exposing SSH (22)",
            "severity": "HIGH",
            "status": "FAIL",
            "resource_id": "sg-0123456789abcdef0 (dev-sg)",
            "region": "us-east-1",
            "message": "Security group 'dev-sg' exposes SSH port 22 to the public internet (0.0.0.0/0).",
            "remediation": "Edit the security group inbound rules. Limit port 22 access to your company's corporate IP range."
        },
        {
            "check_id": "EC2_SG_EXPOSED_RDP",
            "service": "EC2",
            "check_name": "Security Groups Exposing RDP (3389)",
            "severity": "HIGH",
            "status": "PASS",
            "resource_id": "sg-0987654321fedcba0 (prod-win-sg)",
            "region": "us-west-2",
            "message": "RDP port 3389 is closed or restricted to specific IPs.",
            "remediation": "None required."
        },
        {
            "check_id": "EC2_SG_OPEN_ALL_TRAFFIC",
            "service": "EC2",
            "check_name": "Open 'All Traffic' Rules",
            "severity": "CRITICAL",
            "status": "FAIL",
            "resource_id": "sg-0123456789abcdef0 (dev-sg)",
            "region": "us-east-1",
            "message": "Security group 'dev-sg' contains an inbound rule allowing ALL traffic (Protocols: All, Ports: All) from 0.0.0.0/0.",
            "remediation": "Delete the all-traffic wildcard rule and add specific rules only for required ports (e.g. 443)."
        },
        {
            "check_id": "EC2_UNENCRYPTED_EBS",
            "service": "EC2",
            "check_name": "Unencrypted EBS Volumes",
            "severity": "MEDIUM",
            "status": "FAIL",
            "resource_id": "vol-0a1b2c3d4e5f6g7h8",
            "region": "us-east-1",
            "message": "EBS volume 'vol-0a1b2c3d4e5f6g7h8' is unencrypted.",
            "remediation": "Snapshot the volume, copy the snapshot with encryption enabled, create a new volume from that snapshot, and swap it."
        },

        # --- CloudTrail ---
        {
            "check_id": "CLOUDTRAIL_ENABLED",
            "service": "CloudTrail",
            "check_name": "CloudTrail Enabled",
            "severity": "HIGH",
            "status": "PASS",
            "resource_id": "arn:aws:cloudtrail:us-east-1:123456789012:trail/organization-default",
            "region": "us-east-1",
            "message": "CloudTrail is active and logging security events.",
            "remediation": "None required."
        },
        {
            "check_id": "CLOUDTRAIL_MULTI_REGION",
            "service": "CloudTrail",
            "check_name": "Multi-region Trail",
            "severity": "MEDIUM",
            "status": "FAIL",
            "resource_id": "arn:aws:cloudtrail:us-east-1:123456789012:trail/local-trail-debug",
            "region": "us-east-1",
            "message": "CloudTrail 'local-trail-debug' is not configured as a multi-region trail. It only captures events in us-east-1.",
            "remediation": "Go to Trail configuration settings and enable 'Apply trail to all regions'."
        },
        {
            "check_id": "CLOUDTRAIL_LOG_VALIDATION",
            "service": "CloudTrail",
            "check_name": "Log Validation Enabled",
            "severity": "LOW",
            "status": "FAIL",
            "resource_id": "arn:aws:cloudtrail:us-east-1:123456789012:trail/local-trail-debug",
            "region": "us-east-1",
            "message": "Log file integrity validation is disabled. Logs could be altered without detection.",
            "remediation": "Enable log file validation in the trail settings to sign log files and verify integrity."
        },

        # --- Networking ---
        {
            "check_id": "NET_DEFAULT_VPC",
            "service": "Networking",
            "check_name": "Default VPC in Use",
            "severity": "LOW",
            "status": "WARNING",
            "resource_id": "vpc-0abcd12345",
            "region": "us-east-1",
            "message": "Default VPC is active. Default VPC layouts are standard across accounts and more vulnerable to probing.",
            "remediation": "Create custom VPCs with distinct subnet structures, and deploy your critical resources there instead of the default VPC."
        },
        {
            "check_id": "NET_DEFAULT_SG_RULES",
            "service": "Networking",
            "check_name": "Default Security Groups Restricted",
            "severity": "HIGH",
            "status": "FAIL",
            "resource_id": "sg-default (vpc-0abcd12345)",
            "region": "us-east-1",
            "message": "The default security group 'sg-default' allows all inbound traffic from within itself (making lateral movement easy).",
            "remediation": "Remove all inbound and outbound rules from the default security groups in all VPCs."
        },
        {
            "check_id": "NET_INTERNET_FACING_SG",
            "service": "Networking",
            "check_name": "Internet-facing Security Groups",
            "severity": "MEDIUM",
            "status": "WARNING",
            "resource_id": "sg-open-web-sg (vpc-0abcd12345)",
            "region": "us-east-1",
            "message": "Security group exposes port 80 and 443 to the internet. This is expected for web servers, but check if correct.",
            "remediation": "Verify that only the intended HTTP/HTTPS ports are open and that they point to load balancers rather than direct instances."
        },
        {
            "check_id": "NET_OPEN_CIDR",
            "service": "Networking",
            "check_name": "Open CIDR Ranges",
            "severity": "MEDIUM",
            "status": "FAIL",
            "resource_id": "sg-testing-sg (vpc-0abcd12345)",
            "region": "us-east-1",
            "message": "Security group contains rules exposing custom ports (8080, 9000) to 0.0.0.0/0.",
            "remediation": "Restrict custom ports to specific developer IPs or use a VPN/Bastion Host for remote access."
        }
    ]
    return findings
