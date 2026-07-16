import logging
from botocore.exceptions import ClientError
from scanner.base import BaseScanner

logger = logging.getLogger("cspm.scanner.s3")

class S3Scanner(BaseScanner):
    """Scanner for Amazon S3 security configurations."""
    
    def run_checks(self) -> list:
        findings = []
        if not self.session:
            logger.warning("No active session provided to S3Scanner.")
            return findings

        try:
            s3_client = self.session.client("s3")
        except ClientError as e:
            logger.error(f"Failed to create S3 client: {e}")
            return findings

        # List buckets
        try:
            buckets_response = s3_client.list_buckets()
            buckets = buckets_response.get("Buckets", [])
        except ClientError as e:
            logger.error(f"Failed to list S3 buckets: {e}")
            findings.append(self.create_finding(
                "S3_LIST_BUCKETS_ERROR", "List S3 Buckets Access", "HIGH", "FAIL",
                "s3-service", "global",
                f"Error retrieving S3 buckets: {e}",
                "Ensure scanner IAM permissions permit s3:ListAllMyBuckets."
            ))
            return findings

        for bucket in buckets:
            bucket_name = bucket["Name"]
            
            # Find the bucket region
            try:
                location = s3_client.get_bucket_location(Bucket=bucket_name)
                bucket_region = location.get("LocationConstraint") or "us-east-1"
            except ClientError:
                bucket_region = "us-east-1"
                
            # If the user specified regions to scan, filter buckets by region
            if self.regions and bucket_region not in self.regions:
                continue

            # Run individual bucket checks
            findings.extend(self._check_public_access(s3_client, bucket_name, bucket_region))
            findings.extend(self._check_encryption(s3_client, bucket_name, bucket_region))
            findings.extend(self._check_versioning(s3_client, bucket_name, bucket_region))
            findings.extend(self._check_logging(s3_client, bucket_name, bucket_region))
            findings.extend(self._check_block_public_access(s3_client, bucket_name, bucket_region))

        return findings

    def _check_public_access(self, client, bucket_name: str, region: str) -> list:
        findings = []
        is_public = False
        reason = "Bucket is private."

        try:
            # Check Policy Status (AWS evaluates policy + ACLs to mark is_public)
            status_resp = client.get_bucket_policy_status(Bucket=bucket_name)
            if status_resp.get("PolicyStatus", {}).get("IsPublic", False):
                is_public = True
                reason = "Bucket policy allows public access."
        except ClientError as e:
            # PolicyStatus throws error if there is no bucket policy
            if e.response["Error"]["Code"] != "NoSuchBucketPolicy":
                logger.warning(f"Error checking policy status for {bucket_name}: {e}")

        # Check ACLs for public grantees
        if not is_public:
            try:
                acl = client.get_bucket_acl(Bucket=bucket_name)
                for grant in acl.get("Grants", []):
                    grantee = grant.get("Grantee", {})
                    if grantee.get("URI") in [
                        "http://acs.amazonaws.com/groups/global/AllUsers",
                        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
                    ]:
                        is_public = True
                        reason = "Bucket ACL allows public access."
                        break
            except ClientError as e:
                logger.warning(f"Error reading ACL for {bucket_name}: {e}")

        if is_public:
            findings.append(self.create_finding(
                "S3_PUBLIC_BUCKETS", "Public Buckets", "CRITICAL", "FAIL",
                bucket_name, region,
                f"S3 Bucket '{bucket_name}' allows public access: {reason}",
                f"Disable public ACLs or change bucket policy for '{bucket_name}' to restrict external access."
            ))
        else:
            findings.append(self.create_finding(
                "S3_PUBLIC_BUCKETS", "Public Buckets", "CRITICAL", "PASS",
                bucket_name, region,
                f"S3 Bucket '{bucket_name}' is private.",
                "None required."
            ))

        return findings

    def _check_encryption(self, client, bucket_name: str, region: str) -> list:
        findings = []
        try:
            client.get_bucket_encryption(Bucket=bucket_name)
            findings.append(self.create_finding(
                "S3_BUCKET_ENCRYPTION", "Bucket Encryption Enabled", "HIGH", "PASS",
                bucket_name, region,
                f"Default encryption is enabled for S3 bucket '{bucket_name}'.",
                "None required."
            ))
        except ClientError as e:
            if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
                findings.append(self.create_finding(
                    "S3_BUCKET_ENCRYPTION", "Bucket Encryption Enabled", "HIGH", "FAIL",
                    bucket_name, region,
                    f"S3 bucket '{bucket_name}' does not have default encryption configured.",
                    f"Enable default encryption (SSE-S3 or SSE-KMS) on S3 bucket '{bucket_name}' properties."
                ))
            else:
                logger.warning(f"Error checking encryption for {bucket_name}: {e}")
        return findings

    def _check_versioning(self, client, bucket_name: str, region: str) -> list:
        findings = []
        try:
            resp = client.get_bucket_versioning(Bucket=bucket_name)
            status = resp.get("Status")
            if status == "Enabled":
                findings.append(self.create_finding(
                    "S3_VERSIONING_ENABLED", "Versioning Enabled", "LOW", "PASS",
                    bucket_name, region,
                    f"Versioning is enabled on S3 bucket '{bucket_name}'.",
                    "None required."
                ))
            else:
                findings.append(self.create_finding(
                    "S3_VERSIONING_ENABLED", "Versioning Enabled", "LOW", "FAIL",
                    bucket_name, region,
                    f"Versioning is disabled on S3 bucket '{bucket_name}' (Status: {status or 'Disabled'}).",
                    f"Enable Versioning on S3 bucket '{bucket_name}' properties to protect against data loss."
                ))
        except ClientError as e:
            logger.warning(f"Error checking versioning for {bucket_name}: {e}")
        return findings

    def _check_logging(self, client, bucket_name: str, region: str) -> list:
        findings = []
        try:
            resp = client.get_bucket_logging(Bucket=bucket_name)
            if "LoggingEnabled" in resp:
                findings.append(self.create_finding(
                    "S3_LOGGING_ENABLED", "Logging Enabled", "MEDIUM", "PASS",
                    bucket_name, region,
                    f"Server access logging is enabled for bucket '{bucket_name}'. Target: {resp['LoggingEnabled']['TargetBucket']}",
                    "None required."
                ))
            else:
                findings.append(self.create_finding(
                    "S3_LOGGING_ENABLED", "Logging Enabled", "MEDIUM", "FAIL",
                    bucket_name, region,
                    f"Server access logging is disabled for S3 bucket '{bucket_name}'.",
                    f"Enable S3 Server Access Logging under Properties for bucket '{bucket_name}' to record file accesses."
                ))
        except ClientError as e:
            logger.warning(f"Error checking logging for {bucket_name}: {e}")
        return findings

    def _check_block_public_access(self, client, bucket_name: str, region: str) -> list:
        findings = []
        try:
            resp = client.get_public_access_block(Bucket=bucket_name)
            config = resp.get("PublicAccessBlockConfiguration", {})
            
            all_blocked = (
                config.get("BlockPublicAcls", False) and
                config.get("IgnorePublicAcls", False) and
                config.get("BlockPublicPolicy", False) and
                config.get("RestrictPublicBuckets", False)
            )
            
            if all_blocked:
                findings.append(self.create_finding(
                    "S3_BLOCK_PUBLIC_ACCESS", "Block Public Access Enabled", "HIGH", "PASS",
                    bucket_name, region,
                    f"All S3 Block Public Access configurations are enabled for bucket '{bucket_name}'.",
                    "None required."
                ))
            else:
                findings.append(self.create_finding(
                    "S3_BLOCK_PUBLIC_ACCESS", "Block Public Access Enabled", "HIGH", "FAIL",
                    bucket_name, region,
                    f"S3 Block Public Access settings are not fully enabled for bucket '{bucket_name}'.",
                    f"Enable 'Block all public access' settings under Permissions for S3 bucket '{bucket_name}'."
                ))
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                findings.append(self.create_finding(
                    "S3_BLOCK_PUBLIC_ACCESS", "Block Public Access Enabled", "HIGH", "FAIL",
                    bucket_name, region,
                    f"S3 Block Public Access is disabled (no configuration) for bucket '{bucket_name}'.",
                    f"Create and enable a Public Access Block Configuration for S3 bucket '{bucket_name}'."
                ))
            else:
                logger.warning(f"Error checking block public access for {bucket_name}: {e}")
        return findings
