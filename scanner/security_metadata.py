# Security Knowledge Base & Metadata for Aegis Cloud Sentinel
SECURITY_METADATA = {
    "IAM_ROOT_MFA": {
        "check_id": "IAM_ROOT_MFA",
        "title": "Root Account MFA Disabled",
        "why_dangerous": "The root user is the ultimate super-administrative account in AWS. If MFA is not active, any password leak or compromise grants an attacker unrestricted, irrevocable access to delete everything, spawn expensive resources, or steal sensitive data without secondary checks.",
        "estimated_impact": "CRITICAL - Complete account takeover, data exfiltration, permanent resource deletion, and potential massive financial billing abuse (e.g. crypto-jacking).",
        "mitre_attack": "T1586.003 - Access Accounts: Cloud Accounts",
        "cis_benchmark": "CIS 1.1 - Avoid the use of the 'root' user (Level 1)",
        "real_world_incident": "In 2021, an enterprise cloud account without root MFA had its root credentials guessed/phished. The attacker logged in, deleted all databases and backups, and held the company hostage for a $1.2M ransom.",
        "exploitation_example": "An attacker uses phished credentials to log in to the AWS Console via browser as the root user. Since no MFA prompt exists, they bypass security checks, deactivate CloudTrail, and delete core subnets.",
        "aws_docs": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_virtual.html",
        "fix_terraform": """# Root MFA cannot be fully configured via Terraform API. 
# You must lock root access and use IAM Admin roles.
# To enforce MFA for all other admins:
resource "aws_iam_policy" "enforce_mfa" {
  name        = "EnforceMFAPolicy"
  description = "Allows users to manage credentials only when authenticated with MFA"
  policy      = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "BlockAllExceptIndividualMFA"
        Effect   = "Deny"
        NotAction = [
          "iam:CreateVirtualMFADevice",
          "iam:EnableMFADevice",
          "iam:ListMFADevices",
          "iam:ListVirtualMFADevices"
        ]
        Resource = "*"
        Condition = {
          Bool = { "aws:MultiFactorAuthPresent" = "false" }
        }
      }
    ]
  })
}""",
        "fix_cli": """# Enable MFA via CLI (Virtual MFA)
# 1. Create the virtual MFA device:
aws iam create-virtual-mfa-device \\
    --virtual-mfa-device-name RootMFADevice \\
    --outfileQRCodePng /tmp/qrcode.png

# 2. Scan QR code with Authenticator app. Enter two consecutive codes:
aws iam enable-mfa-device \\
    --user-name root \\
    --serial-number arn:aws:iam::123456789012:mfa/RootMFADevice \\
    --authentication-code1 123456 \\
    --authentication-code2 789012""",
        "fix_cfn": """# MFA configuration for root users cannot be declared directly in CloudFormation.
# Recommend enforcing MFA on all developer groups:
Resources:
  MFAEnforcerGroup:
    Type: AWS::IAM::Group
    Properties:
      GroupName: MFA-Enforced-Admins
      Policies:
        - PolicyName: ForceMFA
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Sid: DenyOutsideMFA
                Effect: Deny
                NotAction: "iam:*VirtualMFADevice"
                Resource: "*"
                Condition:
                  Bool:
                    aws:MultiFactorAuthPresent: "false"
""",
        "fix_console": "1. Log in to the AWS Console using root credentials.\\n2. Click your account name at the top-right and select 'Security credentials'.\\n3. Locate 'Multi-factor authentication (MFA)' and click 'Assign MFA device'.\\n4. Select 'Authenticator app' or 'Security Key', capture the QR code, and enter two consecutive codes to activate."
    },
    "IAM_USER_MFA": {
        "check_id": "IAM_USER_MFA",
        "title": "IAM Users Without MFA",
        "why_dangerous": "Console user accounts without Multi-Factor Authentication are highly susceptible to credential stuffing, brute-forcing, and credential leaks. Compromise of an administrator console account grants full infrastructure control.",
        "estimated_impact": "HIGH - Access escalation, unauthorized resource deployment, and modifications of security groups to permit internet exposure.",
        "mitre_attack": "T1078.004 - Valid Accounts: Cloud Accounts",
        "cis_benchmark": "CIS 1.10 - Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password (Level 1)",
        "real_world_incident": "A junior developer committed console passwords to a public GitHub repo. The attacker logged in without MFA, spawned hundreds of GPU EC2 instances, and ran cryptominers costing $60k in 18 hours.",
        "exploitation_example": "Attacker obtains a leaked password for user 'developer-bob'. They navigate to the AWS console login URL, input username and password, and immediately gain access without MFA intervention.",
        "aws_docs": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html",
        "fix_terraform": """# To enforce MFA on user creation via policy:
resource "aws_iam_group" "enforced" {
  name = "mfa-enforced-users"
}

resource "aws_iam_group_policy_attachment" "attach" {
  group      = aws_iam_group.enforced.name
  policy_arn = "arn:aws:iam::aws:policy/IAMUserChangePassword"
}""",
        "fix_cli": """# Deactivate console access for users without MFA until enabled:
aws iam delete-login-profile --user-name developer-bob

# Enable MFA device for user:
aws iam enable-mfa-device \\
    --user-name developer-bob \\
    --serial-number arn:aws:iam::123456789012:mfa/dev-bob-mfa \\
    --authentication-code1 111111 \\
    --authentication-code2 222222""",
        "fix_cfn": """# Define IAM User Group with MFA-enforced password policy:
Resources:
  UserGroupWithMFA:
    Type: AWS::IAM::Group
    Properties:
      GroupName: mfa-compulsory-group
""",
        "fix_console": "1. Log in to AWS IAM Console.\\n2. Go to 'Users', click on the target user (e.g., developer-bob).\\n3. Click the 'Security credentials' tab.\\n4. Select 'Assign MFA device' and follow the prompt."
    },
    "IAM_ACCESS_KEY_AGE": {
        "check_id": "IAM_ACCESS_KEY_AGE",
        "title": "Access Keys Older Than 90 Days",
        "why_dangerous": "The longer access keys are active, the higher the risk they are leaked, shared, hardcoded in repositories, or left orphaned in long-forgotten scripts. Regular key rotation minimizes the compromise window.",
        "estimated_impact": "MEDIUM - Extended compromise duration by leaked or misplaced API keys.",
        "mitre_attack": "T1586 - Access Accounts",
        "cis_benchmark": "CIS 1.14 - Ensure access keys are rotated every 90 days or less (Level 1)",
        "real_world_incident": "Uber leaked access credentials stored in a public Github repo. The credentials were over 6 months old and had never been rotated, allowing attackers to access customer data backups.",
        "exploitation_example": "An attacker discovers an old key `AKIAIOSFODNN7EXAMPLE` inside a backup filesystem. Because it was never rotated, they use it with aws-cli to query S3 buckets successfully.",
        "aws_docs": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html#Using_RotateAccessKey",
        "fix_terraform": """# Terraform does not automate rotation safely.
# Rotate by generating a new key, swapping in application configs, and deleting the old one:
resource "aws_iam_access_key" "new_key" {
  user = "jenkins-ci"
}""",
        "fix_cli": """# 1. Create a new access key:
aws iam create-access-key --user-name jenkins-ci

# 2. Deactivate the old key (AKIAIOSFODNN7EXAMPLE):
aws iam update-access-key \\
    --user-name jenkins-ci \\
    --access-key-id AKIAIOSFODNN7EXAMPLE \\
    --status Inactive

# 3. Once applications use the new key, delete the old one:
aws iam delete-access-key \\
    --user-name jenkins-ci \\
    --access-key-id AKIAIOSFODNN7EXAMPLE""",
        "fix_cfn": """# Do not manage raw IAM Access Keys in CloudFormation to avoid exposing secrets.
# Rather, use IAM roles with short-term tokens:
Resources:
  MyTaskRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              Service: ec2.amazonaws.com
            Action: sts:AssumeRole
""",
        "fix_console": "1. Go to IAM Dashboard -> Users.\\n2. Click on the user and select 'Security credentials'.\\n3. Under 'Access keys', create a new key, update the credentials in your script/env, and click 'Deactivate' then 'Delete' next to the old access key."
    },
    "IAM_ADMIN_ACCESS": {
        "check_id": "IAM_ADMIN_ACCESS",
        "title": "Direct AdministratorAccess Assigned",
        "why_dangerous": "Directly assigning 'AdministratorAccess' (`*:*`) to specific users violates the Principle of Least Privilege. If the user credentials are stolen, the attacker has complete authority. Admin tasks should be performed by assuming temporary IAM Roles.",
        "estimated_impact": "HIGH - Unchecked privileges and lateral movement possibilities inside the cloud footprint.",
        "mitre_attack": "T1078 - Valid Accounts",
        "cis_benchmark": "CIS 1.16 - Ensure IAM policies are attached only to groups or roles (Level 1)",
        "real_world_incident": "A security engineer had direct AdministratorAccess attached to their IAM user profile. Their laptop was compromised via malware, exposing local credentials which granted the attacker full cloud control.",
        "exploitation_example": "Attacker steals API keys for 'admin-alice'. They run `aws iam list-attached-user-policies` and find direct admin access, allowing them to spin up unauthorized services without constraint.",
        "aws_docs": "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#delegate-using-groups-roles",
        "fix_terraform": """# Detach admin policy from individual user. Attach to an IAM Role instead:
resource "aws_iam_role" "admin_role" {
  name = "AdministratorRole"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { AWS = "arn:aws:iam::123456789012:root" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "admin_attach" {
  role       = aws_iam_role.admin_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}""",
        "fix_cli": """# 1. Detach policy from user:
aws iam detach-user-policy \\
    --user-name admin-alice \\
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# 2. Add user to an IAM Group with restricted policies:
aws iam add-user-to-group \\
    --user-name admin-alice \\
    --group-name ReadOnlyEngineers""",
        "fix_cfn": """# Enforce attaching policy to groups/roles, not users:
Resources:
  AdminRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: AdminOperationsRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/AdministratorAccess
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              AWS: !Sub "arn:aws:iam::${AWS::AccountId}:root"
            Action: sts:AssumeRole
""",
        "fix_console": "1. Open IAM Console -> Users -> admin-alice.\\n2. In the 'Permissions' tab, find the AdministratorAccess policy.\\n3. Click 'Remove' or 'Detach' to revoke direct user privileges."
    },
    "IAM_WILDCARD_POLICIES": {
        "check_id": "IAM_WILDCARD_POLICIES",
        "title": "Wildcard IAM Policies Detected",
        "why_dangerous": "IAM policies containing wildcards on both actions (`*`) and resources (`*`) provide unrestricted admin rights. Compromise of a role/user with this policy allows the attacker to execute arbitrary APIs across all services.",
        "estimated_impact": "HIGH - Massive privilege escalation potential. Compromising a minor service instance could result in administrative access.",
        "mitre_attack": "T1098 - Account Manipulation",
        "cis_benchmark": "CIS 1.20 - Support Least Privilege access configurations (Level 1)",
        "real_world_incident": "A policy named 'UnsafeS3AdminPolicy' allowed `s3:*` on `*`. An attacker compromised an EC2 instance with this profile and used it to read and delete objects in the main database backup bucket.",
        "exploitation_example": "An attacker gains access to an IAM Role using `UnsafeS3AdminPolicy` and executes `aws s3api delete-bucket` to destroy corporate buckets.",
        "aws_docs": "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html",
        "fix_terraform": """# Restrict wildcard resources to specific bucket ARNs:
resource "aws_iam_policy" "restricted_s3" {
  name = "RestrictedS3Policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = "arn:aws:s3:::my-secure-reports-bucket/*"
      }
    ]
  })
}""",
        "fix_cli": """# 1. Create a restricted policy version:
aws iam create-policy-version \\
    --policy-arn arn:aws:iam::123456789012:policy/UnsafeS3AdminPolicy \\
    --policy-document file://restricted_policy.json \\
    --set-as-default""",
        "fix_cfn": """# Define restricted resource scope:
Resources:
  RestrictedPolicy:
    Type: AWS::IAM::Policy
    Properties:
      PolicyName: RestrictedS3Access
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Action:
              - s3:GetObject
              - s3:PutObject
            Resource: "arn:aws:s3:::my-secure-reports-bucket/*"
      Roles:
        - !Ref WebServerRole
""",
        "fix_console": "1. Open IAM Console -> Policies -> UnsafeS3AdminPolicy.\\n2. Click 'Edit Policy' and switch to JSON view.\\n3. Replace `\"Resource\": \"*\"` and `\"Action\": \"s3:*\"` with exact bucket ARNs and actions."
    },
    "IAM_INACTIVE_USERS": {
        "check_id": "IAM_INACTIVE_USERS",
        "title": "Inactive IAM Users",
        "why_dangerous": "Inactive accounts are dormant credentials. They are rarely monitored, and if they are compromised (e.g. through credential leaks), the infiltration can go unnoticed for a long time.",
        "estimated_impact": "MEDIUM - Dormant credential misuse and backdoor persistence opportunities.",
        "mitre_attack": "T1078.004 - Cloud Accounts",
        "cis_benchmark": "CIS 1.12 - Ensure credentials of unused IAM users are deactivated/removed (Level 1)",
        "real_world_incident": "An employee left a company but their IAM console user remained active. Six months later, their leaked personal credentials were used to log into the AWS account to download proprietary schemas.",
        "exploitation_example": "Attacker tests a list of leaked email-password combinations on the AWS login page. They successfully authenticate as 'retired-charlie', who has not logged in for 180 days.",
        "aws_docs": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_finding-unused.html",
        "fix_terraform": """# Automate credential cleanup or delete resources:
# (Terraform cannot auto-detect unused status, must be deleted manually)
# Example of removing the user:
# Remove 'aws_iam_user.retired_charlie' resource from code.""",
        "fix_cli": """# 1. Deactivate console password:
aws iam delete-login-profile --user-name retired-charlie

# 2. Deactivate access keys for the user:
aws iam update-access-key \\
    --user-name retired-charlie \\
    --access-key-id AKIAIOSFODNN7EXAMPLE \\
    --status Inactive

# 3. Delete user account:
aws iam delete-user --user-name retired-charlie""",
        "fix_cfn": """# CloudFormation does not manage deletion of dynamic users.
# Best practice is to delete user resources in template files when they leave.""",
        "fix_console": "1. Go to IAM Console -> Users.\\n2. Inspect 'Last console sign-in' column.\\n3. Click 'retired-charlie', delete credentials, and delete the user profile."
    },
    "IAM_UNUSED_ROLES": {
        "check_id": "IAM_UNUSED_ROLES",
        "title": "Unused IAM Roles",
        "why_dangerous": "Orphaned IAM roles are security risks because they can be assumed by unauthorized services or users if their trust policies are overly permissive, creating paths for privilege escalation.",
        "estimated_impact": "LOW - Bloated permissions surface area and role assumption risks.",
        "mitre_attack": "T1078 - Valid Accounts",
        "cis_benchmark": "CIS 1.22 - Ensure unused IAM roles are deleted regularly (Level 2)",
        "real_world_incident": "An old testing role 'LegacyLambdaExecutionRole' was left in an account. An attacker exploited a vulnerable Lambda function and assumed this unused role to gain access to databases.",
        "exploitation_example": "Attacker lists account roles via `aws iam list-roles` and identifies an old role that trusts any account in the organization. They assume the role via STS API.",
        "aws_docs": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html",
        "fix_terraform": """# Remove the unused role resource from your configuration:
# Delete 'aws_iam_role.legacy_role' from your main.tf file.""",
        "fix_cli": """# Delete the unused IAM Role via CLI:
# 1. Remove role from instance profile if attached:
aws iam remove-role-from-instance-profile --instance-profile-name MyProfile --role-name LegacyLambdaExecutionRole

# 2. Delete role policies:
aws iam delete-role-policy --role-name LegacyLambdaExecutionRole --policy-name UnusedPolicy

# 3. Delete the role:
aws iam delete-role --role-name LegacyLambdaExecutionRole""",
        "fix_cfn": """# Delete the role resource definition directly from your CloudFormation stack.""",
        "fix_console": "1. Go to IAM Console -> Roles.\\n2. Search for 'LegacyLambdaExecutionRole'.\\n3. Click 'Delete role' and confirm."
    },
    "S3_PUBLIC_BUCKETS": {
        "check_id": "S3_PUBLIC_BUCKETS",
        "title": "S3 Bucket is Publicly Accessible",
        "why_dangerous": "This bucket allows anonymous internet access. Anyone on the internet can read, list, or download the contents without any authentication. This is the single most common cause of cloud data breaches.",
        "estimated_impact": "CRITICAL - Direct exposure of sensitive files (customer data, source code, credentials) to the public web, leading to regulatory fines (GDPR/HIPAA).",
        "mitre_attack": "T1530 - Data from Cloud Storage Object",
        "cis_benchmark": "CIS 2.1.1 - Ensure S3 Bucket Policy is secure (Level 1)",
        "real_world_incident": "The Capital One data breach (2019) was caused by a misconfigured S3 bucket and firewall rules, allowing an attacker to access 100 million customer records.",
        "exploitation_example": "An attacker runs `aws s3 ls s3://my-public-reports-bucket --no-sign-request` and downloads all files anonymously.",
        "aws_docs": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
        "fix_terraform": """resource "aws_s3_bucket_public_access_block" "block_public" {
  bucket = "my-public-reports-bucket"

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}""",
        "fix_cli": """# Enforce Block Public Access on the bucket:
aws s3api put-public-access-block \\
    --bucket my-public-reports-bucket \\
    --public-access-block-configuration \\
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
""",
        "fix_cfn": """Resources:
  SecureS3Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: my-secure-reports-bucket
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
""",
        "fix_console": "1. Open S3 Console -> select 'my-public-reports-bucket'.\\n2. Go to 'Permissions' tab.\\n3. Click 'Edit' under 'Block public access (bucket settings)'.\\n4. Check 'Block all public access' and save."
    },
    "S3_BUCKET_ENCRYPTION": {
        "check_id": "S3_BUCKET_ENCRYPTION",
        "title": "S3 Default Encryption Disabled",
        "why_dangerous": "Without default encryption, objects uploaded to the bucket are written to disk as cleartext. If AWS physical storage media is compromised or accessed unauthorized, your data is exposed.",
        "estimated_impact": "HIGH - Compliance failures (SOC2/ISO27001/HIPAA) and data exposure risks.",
        "mitre_attack": "T1530 - Data from Cloud Storage",
        "cis_benchmark": "CIS 2.1.2 - Ensure S3 default encryption is enabled (Level 1)",
        "real_world_incident": "A security audit of a healthcare app flagged unencrypted S3 buckets containing patient PDFs. The company faced a $50k penalty for HIPAA compliance failures.",
        "exploitation_example": "An attacker with read access to the underlying storage media bypasses host OS security to read unencrypted raw bytes from S3 disks.",
        "aws_docs": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html",
        "fix_terraform": """resource "aws_s3_bucket_server_side_encryption_configuration" "encrypt" {
  bucket = "temp-scratchpad-bucket"
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}""",
        "fix_cli": """# Enable AES256 server side default encryption:
aws s3api put-bucket-encryption \\
    --bucket temp-scratchpad-bucket \\
    --server-side-encryption-configuration '{
        "Rules": [
            {
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "AES256"
                }
            }
        ]
    }'""",
        "fix_cfn": """Resources:
  EncryptedBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: temp-scratchpad-bucket
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              SSEAlgorithm: AES256""",
        "fix_console": "1. S3 Console -> select 'temp-scratchpad-bucket'.\\n2. Go to 'Properties' tab.\\n3. Locate 'Default encryption' and click 'Edit'.\\n4. Select 'Enable' and choose 'Amazon S3 managed keys (SSE-S3)' or AWS-KMS."
    },
    "S3_VERSIONING_ENABLED": {
        "check_id": "S3_VERSIONING_ENABLED",
        "title": "S3 Versioning Disabled",
        "why_dangerous": "If versioning is disabled, overwriting or deleting an object permanently deletes it. Ransomware or accidental operations can cause permanent data loss.",
        "estimated_impact": "LOW - Ransomware vulnerability, data loss, and recovery difficulties.",
        "mitre_attack": "T1485 - Data Destruction",
        "cis_benchmark": "CIS 2.1.4 - Ensure S3 versioning is enabled (Level 1)",
        "real_world_incident": "A disgruntled employee deleted the main media bucket. Since versioning was disabled, the company lost all user assets permanently, costing 3 weeks of restore attempts.",
        "exploitation_example": "Attacker runs `aws s3 rm s3://my-public-reports-bucket/backup.tar.gz` and the file is permanently deleted with no backup history.",
        "aws_docs": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html",
        "fix_terraform": """resource "aws_s3_bucket_versioning" "versioning" {
  bucket = "my-public-reports-bucket"
  versioning_configuration {
    status = "Enabled"
  }
}""",
        "fix_cli": """# Enable versioning on S3 bucket:
aws s3api put-bucket-versioning \\
    --bucket my-public-reports-bucket \\
    --versioning-configuration Status=Enabled""",
        "fix_cfn": """Resources:
  VersionedBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: my-public-reports-bucket
      VersioningConfiguration:
        Status: Enabled""",
        "fix_console": "1. S3 Console -> my-public-reports-bucket.\\n2. In 'Properties' tab, locate 'Bucket Versioning'.\\n3. Click 'Edit', select 'Enable' and save."
    },
    "S3_LOGGING_ENABLED": {
        "check_id": "S3_LOGGING_ENABLED",
        "title": "S3 Access Logging Disabled",
        "why_dangerous": "Without access logs, you cannot audit who accessed or downloaded files. If a security breach occurs, you will have no forensics to trace the attacker's actions.",
        "estimated_impact": "MEDIUM - Loss of security forensics and visibility during audit investigations.",
        "mitre_attack": "T1007 - System Information Discovery",
        "cis_benchmark": "CIS 2.1.3 - Ensure S3 Bucket Access Logging is enabled (Level 1)",
        "real_world_incident": "A database backup bucket was leaked. Because logging was disabled, the security team could not tell if the files had been downloaded by attackers, necessitating a costly mass user notification.",
        "exploitation_example": "An attacker logs in and downloads files from 'secure-financials-2026'. Because logs are disabled, no record of their requests is generated in the AWS account.",
        "aws_docs": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html",
        "fix_terraform": """resource "aws_s3_bucket_logging" "logging" {
  bucket        = "secure-financials-2026"
  target_bucket = "my-company-logs-bucket"
  target_prefix = "s3-access-logs/"
}""",
        "fix_cli": """# Configure server access logging for the bucket:
aws s3api put-bucket-logging \\
    --bucket secure-financials-2026 \\
    --bucket-logging-status '{
        "LoggingEnabled": {
            "TargetBucket": "my-company-logs-bucket",
            "TargetPrefix": "s3-access-logs/"
        }
    }'""",
        "fix_cfn": """Resources:
  LoggedBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: secure-financials-2026
      LoggingConfiguration:
        DestinationBucketName: my-company-logs-bucket
        LogFilePrefix: s3-access-logs/""",
        "fix_console": "1. S3 Console -> select 'secure-financials-2026'.\\n2. Open 'Properties' tab.\\n3. Click 'Edit' under 'Server access logging', select 'Enable', choose target logging bucket and save."
    },
    "S3_BLOCK_PUBLIC_ACCESS": {
        "check_id": "S3_BLOCK_PUBLIC_ACCESS",
        "title": "Block Public Access Disabled",
        "why_dangerous": "Leaving Block Public Access disabled means users can accidentally make files or the bucket public via ACLs or bucket policies later. Enabling it at the bucket level acts as a master switch to prevent public exposure.",
        "estimated_impact": "HIGH - Accidental data exposure risk due to user errors or script bugs.",
        "mitre_attack": "T1562 - Impair Defenses",
        "cis_benchmark": "CIS 2.1.1 - Block Public Access (Level 1)",
        "real_world_incident": "A developer updated a bucket policy to solve an app connection issue, which inadvertently allowed global read access because the Block Public Access safety guard was inactive.",
        "exploitation_example": "An attacker leverages a minor application bug to create a public object ACL on 'temp-scratchpad-bucket'. The bucket allows the ACL because Block Public Access is disabled.",
        "aws_docs": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
        "fix_terraform": """resource "aws_s3_bucket_public_access_block" "block_public" {
  bucket = "temp-scratchpad-bucket"

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}""",
        "fix_cli": """aws s3api put-public-access-block \\
    --bucket temp-scratchpad-bucket \\
    --public-access-block-configuration \\
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
""",
        "fix_cfn": """Resources:
  SecureBucketBlock:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: temp-scratchpad-bucket
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true""",
        "fix_console": "1. S3 Console -> temp-scratchpad-bucket.\\n2. Open 'Permissions' tab.\\n3. Click 'Edit' next to 'Block public access (bucket settings)'.\\n4. Check 'Block all public access' and save."
    },
    "EC2_PUBLIC_INSTANCES": {
        "check_id": "EC2_PUBLIC_INSTANCES",
        "title": "EC2 Instance is Publicly Accessible",
        "why_dangerous": "Instances with public IP addresses in public subnets are directly exposed to the internet. If the instance runs a service with a vulnerability or weak credentials, attackers can exploit it directly.",
        "estimated_impact": "HIGH - Access point for malware, resource compromise, and network scanning entry point.",
        "mitre_attack": "T1083 - File and Directory Discovery",
        "cis_benchmark": "CIS 4.1 - Ensure no security groups allow ingress from 0.0.0.0/0 (Level 1)",
        "real_world_incident": "A production database host was placed in a public subnet with a public IP. Attackers discovered it via automated scanning, brute-forced the access password, and exfiltrated customer information.",
        "exploitation_example": "Attacker runs port scanning on target IP `54.210.43.99`. They locate an open development service port and exploit an outdated version to execute remote shell commands.",
        "aws_docs": "https://docs.aws.amazon.com/AWSCDI/latest/UserGuide/using-instance-addressing.html",
        "fix_terraform": """# Set associate_public_ip_address = false. Place in private subnet:
resource "aws_instance" "secure_web" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"
  subnet_id     = "subnet-private123" # private subnet ID
  associate_public_ip_address = false
}""",
        "fix_cli": """# 1. Create AMI of instance:
aws ec2 create-image --instance-id i-0abcd1234efgh5678 --name "secured-backup"

# 2. Launch instance in private subnet (without associate-public-ip-address) and terminate old one.
# 3. Associate Elastic IP ONLY to an internet-facing Load Balancer.""",
        "fix_cfn": """Resources:
  PrivateInstance:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: ami-0c55b159cbfafe1f0
      InstanceType: t2.micro
      SubnetId: subnet-private123 # Private Subnet ID
""",
        "fix_console": "1. EC2 Dashboard -> select the public instance.\\n2. Actions -> Instance State -> Terminate (if server is disposable).\\n3. To remediate correctly, deploy new instances inside private subnets and place an Application Load Balancer (ALB) in front."
    },
    "EC2_SG_EXPOSED_SSH": {
        "check_id": "EC2_SG_EXPOSED_SSH",
        "title": "SSH Port 22 Exposed to Public",
        "why_dangerous": "Exposing SSH (port 22) to the public internet (`0.0.0.0/0`) allows attackers worldwide to launch brute-force ssh attacks or exploit vulnerabilities in the SSH daemon.",
        "estimated_impact": "HIGH - Access key leakage risk, malware propagation, and brute-force penetration risk.",
        "mitre_attack": "T1021.004 - Remote Services: SSH",
        "cis_benchmark": "CIS 4.1 - Ensure no security groups allow ingress from 0.0.0.0/0 to port 22 (Level 1)",
        "real_world_incident": "A security group had SSH open globally. A botnet discovered the port, successfully cracked a weak local user password via dictionary attacks, and installed cryptocurrency miners.",
        "exploitation_example": "Attacker runs `nmap -p 22 54.210.43.99` and confirms port 22 is OPEN, then runs `hydra` to brute-force usernames and passwords.",
        "aws_docs": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html",
        "fix_terraform": """resource "aws_security_group_rule" "restricted_ssh" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["192.168.1.0/24"] # corporate IP range only
  security_group_id = "sg-0123456789abcdef0"
}""",
        "fix_cli": """# Remove open SSH rule:
aws ec2 revoke-security-group-ingress \\
    --group-id sg-0123456789abcdef0 \\
    --protocol tcp \\
    --port 22 \\
    --cidr 0.0.0.0/0

# Add restricted SSH rule:
aws ec2 authorize-security-group-ingress \\
    --group-id sg-0123456789abcdef0 \\
    --protocol tcp \\
    --port 22 \\
    --cidr 192.168.1.0/24""",
        "fix_cfn": """Resources:
  SecureSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Allowed restricted SSH
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 192.168.1.0/24 # Office IP range only""",
        "fix_console": "1. EC2 Dashboard -> Security Groups -> select dev-sg.\\n2. In 'Inbound rules' tab, click 'Edit inbound rules'.\\n3. Locate SSH (port 22), change Source from 'Anywhere-IPv4' (0.0.0.0/0) to 'My IP' or custom CIDR range."
    },
    "EC2_SG_OPEN_ALL_TRAFFIC": {
        "check_id": "EC2_SG_OPEN_ALL_TRAFFIC",
        "title": "All-Traffic Wildcard Rule Configured",
        "why_dangerous": "An 'All Traffic' ingress rule allowing all protocols and ports from `0.0.0.0/0` completely bypasses firewall rules. This exposes internal services, databases, and configuration panels directly to the internet.",
        "estimated_impact": "CRITICAL - Unmitigated network exposure. Allows bypass of security architecture, enabling scanning and direct service compromise.",
        "mitre_attack": "T1562 - Impair Defenses",
        "cis_benchmark": "CIS 4.2 - Ensure no security groups allow ingress from 0.0.0.0/0 to all ports/protocols (Level 1)",
        "real_world_incident": "A security group was configured with protocol `-1` (all traffic) to troubleshoot an app error. The developer forgot to remove it, and databases on the instances were wiped by an automated ransomware script.",
        "exploitation_example": "Attacker runs network scanners and discovers database ports (3306, 5432) and diagnostic consoles (9000) are open, then connects using default credentials.",
        "aws_docs": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/working-with-security-groups.html",
        "fix_terraform": """# Remove all-traffic rules and replace with explicit ports:
resource "aws_security_group_rule" "http_only" {
  type              = "ingress"
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = "sg-0123456789abcdef0"
}

resource "aws_security_group_rule" "https_only" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = "sg-0123456789abcdef0"
}""",
        "fix_cli": """# 1. Revoke the all-traffic ingress rule:
aws ec2 revoke-security-group-ingress \\
    --group-id sg-0123456789abcdef0 \\
    --ip-permissions '[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]'

# 2. Add secure HTTPS rule:
aws ec2 authorize-security-group-ingress \\
    --group-id sg-0123456789abcdef0 \\
    --protocol tcp \\
    --port 443 \\
    --cidr 0.0.0.0/0""",
        "fix_cfn": """Resources:
  RestrictedSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Allow HTTPS only
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 443
          ToPort: 443
          CidrIp: 0.0.0.0/0""",
        "fix_console": "1. EC2 Dashboard -> Security Groups -> select dev-sg.\\n2. Edit Inbound rules.\\n3. Delete the rule allowing 'All traffic' on all ports from '0.0.0.0/0'.\\n4. Save and configure explicit rules for necessary ports."
    },
    "EC2_UNENCRYPTED_EBS": {
        "check_id": "EC2_UNENCRYPTED_EBS",
        "title": "Unencrypted EBS Volumes",
        "why_dangerous": "Unencrypted EBS volumes store data in cleartext at the block storage layer. If AWS storage disks are physically compromised or local virtualization isolations fail, your static data is compromised.",
        "estimated_impact": "MEDIUM - Data privacy violations and security compliance failures.",
        "mitre_attack": "T1530 - Data from Cloud Storage",
        "cis_benchmark": "CIS 2.2.1 - Ensure EBS volumes are encrypted (Level 1)",
        "real_world_incident": "A finance firm left an EBS volume containing database transaction data unencrypted. A compliance auditor flagged this, causing a SOC2 audit failure and delaying their fundraising round.",
        "exploitation_example": "An attacker with hypervisor access reading block files extracts credentials and API key config data directly from unencrypted sectors.",
        "aws_docs": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html",
        "fix_terraform": """# Set encrypted = true on EBS volumes:
resource "aws_ebs_volume" "encrypted_vol" {
  availability_zone = "us-east-1a"
  size              = 40
  encrypted         = true
}""",
        "fix_cli": """# Enable encryption by default for all new EBS volumes in the region:
aws ec2 enable-ebs-encryption-by-default

# For existing volumes:
# 1. Snapshot the volume:
aws ec2 create-snapshot --volume-id vol-0a1b2c3d4e5f6g7h8

# 2. Copy snapshot with encryption:
aws ec2 copy-snapshot \\
    --source-region us-east-1 \\
    --source-snapshot-id snap-12345 \\
    --encrypted

# 3. Create new volume from encrypted snapshot and swap.""",
        "fix_cfn": """Resources:
  EncryptedEBSVolume:
    Type: AWS::EC2::Volume
    Properties:
      Size: 40
      AvailabilityZone: us-east-1a
      Encrypted: true""",
        "fix_console": "1. Go to EC2 Console -> Volumes -> select 'vol-0a1b2c3d4e5f6g7h8'.\\n2. Click Actions -> Create Snapshot.\\n3. Go to Snapshots, copy it, check 'Enable encryption'.\\n4. Create volume from the encrypted copy, detach the old volume, and attach the encrypted one."
    },
    "CLOUDTRAIL_MULTI_REGION": {
        "check_id": "CLOUDTRAIL_MULTI_REGION",
        "title": "CloudTrail Log is Single-Region",
        "why_dangerous": "If CloudTrail is not configured for all regions, it will not log activity in secondary regions. An attacker compromising your credentials can deploy resources in an unchecked region (e.g. ap-southeast-1) without creating any log entries in your primary audit region.",
        "estimated_impact": "MEDIUM - Hidden compromise activity in unmonitored AWS regions.",
        "mitre_attack": "T1562.001 - Impair Defenses: Disable Cloud Logging",
        "cis_benchmark": "CIS 3.1 - Ensure CloudTrail is enabled in all regions (Level 1)",
        "real_world_incident": "Attackers hijacked an AWS account and launched crypto-mining fleets in a remote region (sa-east-1). Because CloudTrail was configured only for us-east-1, the security team didn't receive any notifications for weeks.",
        "exploitation_example": "Attacker assumes stolen credentials and runs `aws ec2 run-instances --region eu-west-3`. Because no trail logs that region, the action is not recorded.",
        "aws_docs": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/receive-cloudtrail-log-files-from-multiple-regions.html",
        "fix_terraform": """resource "aws_cloudtrail" "multi_region" {
  name                          = "organization-default"
  s3_bucket_name                = "my-cloudtrail-bucket"
  is_multi_region_trail         = true
  include_global_service_events = true
}""",
        "fix_cli": """# Update CloudTrail configuration to enable multi-region:
aws cloudtrail update-trail \\
    --name local-trail-debug \\
    --is-multi-region-trail \\
    --include-global-service-events""",
        "fix_cfn": """Resources:
  MultiRegionTrail:
    Type: AWS::CloudTrail::Trail
    Properties:
      TrailName: organization-default
      S3BucketName: my-cloudtrail-bucket
      IsMultiRegionTrail: true
      IncludeGlobalServiceEvents: true
      IsLogging: true""",
        "fix_console": "1. Go to CloudTrail Console -> Trails.\\n2. Click 'local-trail-debug'.\\n3. Click 'Edit', locate 'Trail log locations', select 'Apply trail to all regions' and save."
    },
    "CLOUDTRAIL_LOG_VALIDATION": {
        "check_id": "CLOUDTRAIL_LOG_VALIDATION",
        "title": "CloudTrail Log Validation Disabled",
        "why_dangerous": "Without log validation, there is no cryptographic guarantee that logs have not been deleted, tampered with, or modified by an attacker attempting to hide their presence. Enabling validation lets you quickly verify log integrity.",
        "estimated_impact": "LOW - Inability to prove historical audit trails have not been altered after breach.",
        "mitre_attack": "T1562.001 - Impair Defenses: Disable Cloud Logging",
        "cis_benchmark": "CIS 3.2 - Ensure CloudTrail log file validation is enabled (Level 1)",
        "real_world_incident": "An insider analyst exfiltrated files and manually edited S3 log objects to remove their IP address. Because validation was off, the modification was not flagged, preventing prosecution.",
        "exploitation_example": "An attacker hacks the S3 bucket housing CloudTrail logs and deletes the logs containing their attack footprint. Without validation signatures, no anomaly is raised.",
        "aws_docs": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-enabling.html",
        "fix_terraform": """resource "aws_cloudtrail" "validation_trail" {
  name                          = "organization-default"
  s3_bucket_name                = "my-cloudtrail-bucket"
  enable_log_file_validation    = true
}""",
        "fix_cli": """aws cloudtrail update-trail \\
    --name local-trail-debug \\
    --enable-log-file-validation""",
        "fix_cfn": """Resources:
  SecureTrail:
    Type: AWS::CloudTrail::Trail
    Properties:
      TrailName: local-trail-debug
      S3BucketName: my-cloudtrail-bucket
      EnableLogFileValidation: true""",
        "fix_console": "1. CloudTrail Console -> Trails -> local-trail-debug.\\n2. Click 'Edit'.\\n3. Under 'Additional configuration', check 'Enable log file validation' and save."
    },
    "NET_DEFAULT_VPC": {
        "check_id": "NET_DEFAULT_VPC",
        "title": "Default VPC In Use",
        "why_dangerous": "Default VPCs have pre-configured CIDRs and standard subnets with routes leading directly to an Internet Gateway. Working within the default VPC increases the risk of launching services publicly by accident.",
        "estimated_impact": "LOW - Standardized setup layout exposure, increasing scan vulnerability.",
        "mitre_attack": "T1580 - Cloud Infrastructure Discovery",
        "cis_benchmark": "CIS 4.3 - Ensure default VPC is not used (Level 1)",
        "real_world_incident": "A startup deployed all their production VMs in the default VPC. An engineer launched a database instance without configuring a subnet, and AWS assigned it a public IP in the default subnet.",
        "exploitation_example": "Attacker probes target using typical default VPC subnet IP ranges (e.g. 172.31.0.0/16) and discovers resources using standard route rules.",
        "aws_docs": "https://docs.aws.amazon.com/vpc/latest/userguide/default-vpc.html",
        "fix_terraform": """# Build custom VPC layout:
resource "aws_vpc" "custom_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
}""",
        "fix_cli": """# 1. Delete Default VPC:
aws ec2 delete-vpc --vpc-id vpc-0abcd12345

# (All active subnets and gateways in the default VPC must be deleted first)""",
        "fix_cfn": """Resources:
  CustomVPC:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.0.0.0/16
      EnableDnsHostnames: true""",
        "fix_console": "1. VPC Console -> select 'Default VPC'.\\n2. Ensure all resources are migrated to custom VPCs.\\n3. Click Actions -> Delete VPC."
    },
    "NET_DEFAULT_SG_RULES": {
        "check_id": "NET_DEFAULT_SG_RULES",
        "title": "Default Security Group Allows Traffic",
        "why_dangerous": "Default security groups exist by default in every VPC. If they allow ingress or egress traffic, resources launched without specifying a security group automatically inherit these open rules, facilitating lateral network movement.",
        "estimated_impact": "HIGH - Facilitates lateral network movement inside the VPC if an entrypoint node is breached.",
        "mitre_attack": "T1083 - File and Directory Discovery",
        "cis_benchmark": "CIS 4.3 - Ensure default security groups restrict all traffic (Level 1)",
        "real_world_incident": "An attacker compromised a web server. Because the default security group allowed internal database communication, they moved laterally from the compromised host to access critical RDS instances.",
        "exploitation_example": "Once inside an EC2 instance, the attacker issues database commands directly to internal databases using the VPC's default security group parameters.",
        "aws_docs": "https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#DefaultSecurityGroup",
        "fix_terraform": """# Clear all default SG rules:
resource "aws_default_security_group" "default" {
  vpc_id = "vpc-0abcd12345"
  # No ingress or egress blocks removes all default rules.
}""",
        "fix_cli": """# Revoke all ingress rules on default security group:
aws ec2 revoke-security-group-ingress \\
    --group-id sg-default \\
    --ip-permissions '[{"IpProtocol": "-1", "UserIdGroupPairs": [{"GroupId": "sg-default"}]}]'""",
        "fix_cfn": """# Ensure default SG is locked:
Resources:
  LockDefaultSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Locked default security group
      VpcId: vpc-0abcd12345
      SecurityGroupIngress: []
      SecurityGroupEgress: []""",
        "fix_console": "1. VPC Console -> Security Groups.\\n2. Filter for 'default' security group.\\n3. Edit 'Inbound rules' and delete all rules. Edit 'Outbound rules' and delete all rules."
    },
    "NET_INTERNET_FACING_SG": {
        "check_id": "NET_INTERNET_FACING_SG",
        "title": "Internet-facing Security Group",
        "why_dangerous": "Exposing open ports (like port 80 or 443) globally is standard for web servers, but needs to be audited to ensure only intended protocols are open and that they target load balancers rather than individual servers directly.",
        "estimated_impact": "MEDIUM - Port scan exposure and direct attack entry vectors.",
        "mitre_attack": "T1046 - Network Service Discovery",
        "cis_benchmark": "CIS 4.1 - Inbound rules audit (Level 1)",
        "real_world_incident": "A security group allowed port 80 globally. The instance was running an obsolete HTTP server version, allowing attackers to perform remote buffer overflow attacks.",
        "exploitation_example": "Attacker connects to server on port 80 and uses software fingerprinting tools to determine version vulnerabilities.",
        "aws_docs": "https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html",
        "fix_terraform": """# Limit ingress traffic strictly to HTTP/HTTPS:
resource "aws_security_group_rule" "https" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = "sg-open-web-sg"
}""",
        "fix_cli": """# Remove any unneeded open ports:
aws ec2 revoke-security-group-ingress \\
    --group-id sg-open-web-sg \\
    --protocol tcp \\
    --port 8080 \\
    --cidr 0.0.0.0/0""",
        "fix_cfn": """Resources:
  WebServerSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Allow HTTPS ingress
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 443
          ToPort: 443
          CidrIp: 0.0.0.0/0""",
        "fix_console": "1. EC2 Console -> Security Groups.\\n2. Select 'sg-open-web-sg'.\\n3. Click 'Edit inbound rules', review ports, and remove any legacy rules (e.g. port 8080)."
    },
    "NET_OPEN_CIDR": {
        "check_id": "NET_OPEN_CIDR",
        "title": "Custom Ports Exposed to 0.0.0.0/0",
        "why_dangerous": "Exposing custom application ports (e.g. 8080, 9000, 27017) globally makes internal application APIs and administrative panels reachable by anyone, opening paths to database dumps or administrative control bypass.",
        "estimated_impact": "MEDIUM - Access to administrative portals and debug services without firewall gates.",
        "mitre_attack": "T1133 - External Remote Services",
        "cis_benchmark": "CIS 4.2 - Limit security group rules to specific CIDRs (Level 2)",
        "real_world_incident": "An administration panel on port 9000 was open to `0.0.0.0/0` for remote management. Attackers brute-forced the panel password and leveraged execution features to control the container.",
        "exploitation_example": "Attacker connects to `http://54.210.43.99:9000` via browser, views dashboard details, and injects payload scripts.",
        "aws_docs": "https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html",
        "fix_terraform": """# Limit custom port 9000 access to your company's network range:
resource "aws_security_group_rule" "restricted_custom" {
  type              = "ingress"
  from_port         = 9000
  to_port           = 9000
  protocol          = "tcp"
  cidr_blocks       = ["192.168.1.0/24"] # Company office subnet only
  security_group_id = "sg-testing-sg"
}""",
        "fix_cli": """# 1. Revoke the open CIDR rule:
aws ec2 revoke-security-group-ingress \\
    --group-id sg-testing-sg \\
    --protocol tcp \\
    --port 9000 \\
    --cidr 0.0.0.0/0

# 2. Add rule with restricted CIDR:
aws ec2 authorize-security-group-ingress \\
    --group-id sg-testing-sg \\
    --protocol tcp \\
    --port 9000 \\
    --cidr 192.168.1.0/24""",
        "fix_cfn": """Resources:
  RestrictedCustomSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Allowed secure admin ports
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 9000
          ToPort: 9000
          CidrIp: 192.168.1.0/24 # Restricted company subnet""",
        "fix_console": "1. EC2 Console -> Security Groups -> sg-testing-sg.\\n2. Select 'Edit inbound rules'.\\n3. Locate port 9000, change Source from 'Anywhere' to your specific office IP."
    }
}
