import logging
from datetime import datetime, timezone
import boto3
from botocore.exceptions import ClientError
from scanner.base import BaseScanner

logger = logging.getLogger("cspm.scanner.iam")

class IAMScanner(BaseScanner):
    """Scanner for IAM service configurations."""
    
    def run_checks(self) -> list:
        findings = []
        if not self.session:
            logger.warning("No active session provided to IAMScanner.")
            return findings

        try:
            iam_client = self.session.client("iam")
        except ClientError as e:
            logger.error(f"Failed to create IAM client: {e}")
            return findings

        # Run checks
        findings.extend(self._check_root_mfa(iam_client))
        
        # Retrieve users list (paginated)
        users = []
        try:
            paginator = iam_client.get_paginator("list_users")
            for page in paginator.paginate():
                users.extend(page["Users"])
        except ClientError as e:
            logger.error(f"Failed to list IAM users: {e}")
            findings.append(self.create_finding(
                "IAM_LIST_USERS_ERROR", "List IAM Users Access", "HIGH", "FAIL",
                "iam-service", "global",
                f"Error retrieving IAM users list: {e}",
                "Ensure scanner IAM permissions permit iam:ListUsers."
            ))
            return findings

        # Check users
        findings.extend(self._check_users_mfa_and_keys(iam_client, users))
        findings.extend(self._check_admin_access_and_wildcards(iam_client, users))
        findings.extend(self._check_unused_roles(iam_client))

        return findings

    def _check_root_mfa(self, client) -> list:
        findings = []
        try:
            summary = client.get_account_summary()
            mfa_enabled = summary.get("SummaryMap", {}).get("AccountMFAEnabled", 0)
            if mfa_enabled == 1:
                findings.append(self.create_finding(
                    "IAM_ROOT_MFA", "Root MFA Enabled", "CRITICAL", "PASS",
                    "root-account", "global",
                    "Root user Multi-Factor Authentication (MFA) is enabled.",
                    "None required."
                ))
            else:
                findings.append(self.create_finding(
                    "IAM_ROOT_MFA", "Root MFA Enabled", "CRITICAL", "FAIL",
                    "root-account", "global",
                    "Root user Multi-Factor Authentication (MFA) is not enabled.",
                    "Log in as the AWS account root user and enable MFA immediately under My Security Credentials."
                ))
        except ClientError as e:
            logger.warning(f"Unable to read IAM account summary for Root MFA: {e}")
            findings.append(self.create_finding(
                "IAM_ROOT_MFA_ERROR", "Read Root MFA Status", "MEDIUM", "WARNING",
                "root-account", "global",
                f"Unable to verify Root MFA due to permission limits: {e}",
                "Add iam:GetAccountSummary permission to the scanner identity."
            ))
        return findings

    def _check_users_mfa_and_keys(self, client, users: list) -> list:
        findings = []
        now = datetime.now(timezone.utc)
        
        for user in users:
            username = user["UserName"]
            user_arn = user["Arn"]
            
            # Check MFA
            try:
                mfa_devices = client.list_mfa_devices(UserName=username)
                if not mfa_devices.get("MFADevices"):
                    findings.append(self.create_finding(
                        "IAM_USER_MFA", "IAM Users Without MFA", "HIGH", "FAIL",
                        user_arn, "global",
                        f"IAM user '{username}' has no MFA device configured.",
                        f"Enforce MFA for user '{username}' via security guidelines or group policies."
                    ))
                else:
                    findings.append(self.create_finding(
                        "IAM_USER_MFA", "IAM Users Without MFA", "HIGH", "PASS",
                        user_arn, "global",
                        f"IAM user '{username}' has MFA enabled.",
                        "None required."
                    ))
            except ClientError as e:
                logger.warning(f"Error listing MFA devices for user {username}: {e}")

            # Check Access Key Age
            try:
                keys = client.list_access_keys(UserName=username)
                for key in keys.get("AccessKeyMetadata", []):
                    key_id = key["AccessKeyId"]
                    create_date = key["CreateDate"]
                    age_days = (now - create_date).days
                    if age_days > 90:
                        findings.append(self.create_finding(
                            "IAM_ACCESS_KEY_AGE", "Access Keys Older Than 90 Days", "MEDIUM", "FAIL",
                            f"{user_arn} (Key: {key_id})", "global",
                            f"Access key '{key_id}' for user '{username}' is {age_days} days old.",
                            f"Rotate the access key '{key_id}' for user '{username}' immediately."
                        ))
                    else:
                        findings.append(self.create_finding(
                            "IAM_ACCESS_KEY_AGE", "Access Keys Older Than 90 Days", "MEDIUM", "PASS",
                            f"{user_arn} (Key: {key_id})", "global",
                            f"Access key '{key_id}' for user '{username}' is {age_days} days old (within limits).",
                            "None required."
                        ))
            except ClientError as e:
                logger.warning(f"Error checking access keys for user {username}: {e}")

            # Check Inactive User (no login or activity in 90 days)
            last_used = user.get("PasswordLastUsed")
            if last_used:
                days_inactive = (now - last_used).days
                if days_inactive > 90:
                    findings.append(self.create_finding(
                        "IAM_INACTIVE_USERS", "Inactive IAM Users", "MEDIUM", "FAIL",
                        user_arn, "global",
                        f"IAM user '{username}' password has not been used in {days_inactive} days.",
                        f"Disable console access or delete user '{username}' if no longer needed."
                    ))
            else:
                # User exists but has never logged in. Let's check when user was created.
                create_date = user["CreateDate"]
                age_days = (now - create_date).days
                if age_days > 90:
                    findings.append(self.create_finding(
                        "IAM_INACTIVE_USERS", "Inactive IAM Users", "MEDIUM", "WARNING",
                        user_arn, "global",
                        f"IAM user '{username}' was created {age_days} days ago and has never logged in.",
                        f"Investigate if user '{username}' is active or if their account should be deactivated."
                    ))

        return findings

    def _check_admin_access_and_wildcards(self, client, users: list) -> list:
        findings = []
        for user in users:
            username = user["UserName"]
            user_arn = user["Arn"]
            
            # Check attached user policies
            try:
                attached_policies = client.list_attached_user_policies(UserName=username)
                for policy in attached_policies.get("AttachedPolicies", []):
                    policy_arn = policy.get("PolicyArn")
                    policy_name = policy.get("PolicyName", "UnknownPolicy")
                    if not policy_arn:
                        continue

                    if policy_name == "AdministratorAccess":
                        findings.append(self.create_finding(
                            "IAM_ADMIN_ACCESS", "Users with AdministratorAccess", "HIGH", "WARNING",
                            user_arn, "global",
                            f"IAM user '{username}' has AdministratorAccess policy directly attached.",
                            f"Remove the AdministratorAccess policy from user '{username}' and assign roles/groups."
                        ))
            except ClientError as e:
                logger.warning(f"Error listing attached policies for user {username}: {e}")

        # Check Wildcard Customer Managed Policies (runs once, not per-user)
        try:
            policies = client.list_policies(Scope="Local", OnlyAttached=False)
            for policy in policies.get("Policies", []):
                policy_arn = policy.get("PolicyArn")
                version_id = policy.get("DefaultVersionId")
                if not policy_arn or not version_id:
                    continue
                
                try:
                    policy_ver = client.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
                    doc = policy_ver.get("PolicyVersion", {}).get("Document", {})
                    statements = doc.get("Statement", [])
                    if isinstance(statements, dict):
                        statements = [statements]
                        
                    wildcard_found = False
                    for stmt in statements:
                        if stmt.get("Effect") == "Allow":
                            action = stmt.get("Action", [])
                            resource = stmt.get("Resource", [])
                            
                            actions_list = [action] if isinstance(action, str) else action
                            resources_list = [resource] if isinstance(resource, str) else resource
                            
                            if "*" in actions_list and "*" in resources_list:
                                wildcard_found = True
                                break
                                
                    if wildcard_found:
                        findings.append(self.create_finding(
                            "IAM_WILDCARD_POLICIES", "Wildcard IAM Policies", "HIGH", "FAIL",
                            policy_arn, "global",
                            f"IAM policy '{policy['PolicyName']}' allows full admin access (*:*) via wildcards.",
                            f"Revise policy '{policy['PolicyName']}' to enforce least privilege access."
                        ))
                except ClientError as e:
                    logger.warning(f"Error reading policy document for {policy_arn}: {e}")
        except ClientError as e:
            logger.warning(f"Error listing custom managed policies: {e}")

        return findings

    def _check_unused_roles(self, client) -> list:
        findings = []
        now = datetime.now(timezone.utc)
        
        try:
            roles = []
            paginator = client.get_paginator("list_roles")
            for page in paginator.paginate():
                roles.extend(page["Roles"])
                
            for role in roles:
                role_name = role["RoleName"]
                role_arn = role["Arn"]
                path = role["Path"]
                
                # Skip AWS service roles
                if path.startswith("/aws-service-role/"):
                    continue
                    
                last_used = role.get("RoleLastUsed", {}).get("LastUsedDate")
                if last_used:
                    days_unused = (now - last_used).days
                    if days_unused > 90:
                        findings.append(self.create_finding(
                            "IAM_UNUSED_ROLES", "Unused IAM Roles", "LOW", "WARNING",
                            role_arn, "global",
                            f"IAM Role '{role_name}' has not been used in {days_unused} days.",
                            f"Audit role '{role_name}' usage. Delete it if it is obsolete."
                        ))
                else:
                    # Role created but never used. Check age.
                    create_date = role["CreateDate"]
                    age_days = (now - create_date).days
                    if age_days > 90:
                        findings.append(self.create_finding(
                            "IAM_UNUSED_ROLES", "Unused IAM Roles", "LOW", "WARNING",
                            role_arn, "global",
                            f"IAM Role '{role_name}' has never been used and is {age_days} days old.",
                            f"Delete the unused IAM Role '{role_name}' to reduce privilege risk."
                        ))
        except ClientError as e:
            logger.warning(f"Error listing or auditing roles: {e}")
            
        return findings
