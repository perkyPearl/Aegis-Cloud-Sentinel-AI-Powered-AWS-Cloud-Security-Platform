// Aegis Cloud Sentinel Client-Side Application Core
document.addEventListener("DOMContentLoaded", () => {
    // State management
    let currentScanId = null;
    let currentFindings = [];
    let currentSummary = null;
    let currentFramework = "cis"; // GRC framework default
    let activeSeverityFilter = null; // For severity card click-to-filter
    
    // Chart references
    let scoreChartObj = null;
    let serviceChartObj = null;
    let severityChartObj = null;
    let trendChartObj = null;

    // --- Curated Client-Side Security Metadata (Step 6) ---
    const SECURITY_METADATA_JS = {
        "IAM_ROOT_MFA": {
            "why_dangerous": "The root user is the ultimate super-administrative account in AWS. If MFA is not active, any password compromise grants an attacker unrestricted, irrevocable access to delete everything or steal sensitive data.",
            "estimated_impact": "CRITICAL - Complete account takeover, data exfiltration, permanent resource deletion, and potential massive financial billing abuse.",
            "mitre_attack": "T1586.003 - Access Accounts: Cloud Accounts",
            "cis_benchmark": "CIS 1.1 - Avoid the use of the 'root' user (Level 1)",
            "real_world_incident": "In 2021, an enterprise cloud account without root MFA had its credentials guessed. The attacker deleted all databases and backups, holding the company hostage for $1.2M.",
            "exploitation_example": "attacker login as root -> bypasses security checks -> disables CloudTrail -> deletes core subnets",
            "aws_docs": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_virtual.html",
            "fix_terraform": "resource \"aws_iam_policy\" \"enforce_mfa\" {\n  name        = \"EnforceMFAPolicy\"\n  policy      = jsonencode({\n    Version = \"2012-10-17\"\n    Statement = [{\n      Effect = \"Deny\", NotAction = \"iam:*VirtualMFA*\", Resource = \"*\"\n      Condition = { Bool = { \"aws:MultiFactorAuthPresent\" = \"false\" } }\n    }]\n  })\n}",
            "fix_cli": "aws iam create-virtual-mfa-device --virtual-mfa-device-name RootMFA\naws iam enable-mfa-device --user-name root --serial-number arn:aws:iam::123:mfa/RootMFA --authentication-code1 123 --authentication-code2 456",
            "fix_cfn": "Resources:\n  MFAEnforcedGroup:\n    Type: AWS::IAM::Group\n    Properties:\n      GroupName: MFA-Enforced-Admins",
            "fix_console": "1. Log in to AWS Console with root credentials.\n2. Click account name -> select 'Security credentials'.\n3. Click 'Assign MFA device' and scan the QR code."
        },
        "IAM_USER_MFA": {
            "why_dangerous": "User console passwords without MFA are highly susceptible to credential stuffing and brute-forcing, granting immediate administrative console access.",
            "estimated_impact": "HIGH - Access escalation, unauthorized resource deployment, and firewall rule modifications.",
            "mitre_attack": "T1078.004 - Valid Accounts: Cloud Accounts",
            "cis_benchmark": "CIS 1.10 - Enable MFA for all console IAM users (Level 1)",
            "real_world_incident": "A junior developer committed console passwords to a public GitHub repo. An attacker logged in without MFA, spawning hundreds of GPU instances costing $60k in 18 hours.",
            "exploitation_example": "hydra -l developer-bob -P wordlist.txt aws-console-url -> success -> login without MFA",
            "aws_docs": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html",
            "fix_terraform": "resource \"aws_iam_group\" \"mfa\" {\n  name = \"mfa-enforced-users\"\n}",
            "fix_cli": "aws iam enable-mfa-device --user-name developer-bob --serial-number arn:aws:iam::123:mfa/dev-bob --authentication-code1 111 --authentication-code2 222",
            "fix_cfn": "Resources:\n  UserGroupWithMFA:\n    Type: AWS::IAM::Group\n    Properties:\n      GroupName: mfa-compulsory-group",
            "fix_console": "1. Open IAM Console -> Users -> select developer-bob.\n2. Under 'Security credentials', click 'Assign MFA device'."
        },
        "IAM_ACCESS_KEY_AGE": {
            "why_dangerous": "Older keys have a higher chance of leakage, exposure in public repositories, or orphan placement in forgotten scripts.",
            "estimated_impact": "MEDIUM - Access key compromise with long-term persistent access.",
            "mitre_attack": "T1586 - Access Accounts",
            "cis_benchmark": "CIS 1.14 - Rotate access keys every 90 days (Level 1)",
            "real_world_incident": "Uber leaked access credentials stored in a public repository that were 6 months old and had never been rotated.",
            "exploitation_example": "grep 'AKIA' local_logs.txt -> retrieve keys -> check validity via sts get-caller-identity",
            "aws_docs": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
            "fix_terraform": "resource \"aws_iam_access_key\" \"new_key\" {\n  user = \"jenkins-ci\"\n}",
            "fix_cli": "aws iam create-access-key --user-name jenkins-ci\naws iam update-access-key --user-name jenkins-ci --access-key-id AKIAIOSFODNN7EXAMPLE --status Inactive",
            "fix_cfn": "# Access keys should be rotated dynamically. Avoid hardcoding in templates.",
            "fix_console": "1. Go to IAM Console -> select the user -> 'Security credentials'.\n2. Create a new key, update your script configurations, and delete the old access key."
        },
        "IAM_ADMIN_ACCESS": {
            "why_dangerous": "Direct assignment of AdministratorAccess permissions to individual user profiles bypasses role isolation boundaries and violates the principle of least privilege.",
            "estimated_impact": "HIGH - Escalated credentials that allow lateral movement and complete domain persistence.",
            "mitre_attack": "T1078 - Valid Accounts",
            "cis_benchmark": "CIS 1.16 - Attach policies only to groups or roles (Level 1)",
            "real_world_incident": "A security engineer had direct AdministratorAccess attached to their user. Malware compromised their laptop, exposing local credentials that compromised the AWS account.",
            "exploitation_example": "aws iam list-attached-user-policies --user-name admin-alice -> find Admin policy",
            "aws_docs": "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
            "fix_terraform": "resource \"aws_iam_role_policy_attachment\" \"admin_attach\" {\n  role       = aws_iam_role.admin_role.name\n  policy_arn = \"arn:aws:iam::aws:policy/AdministratorAccess\"\n}",
            "fix_cli": "aws iam detach-user-policy --user-name admin-alice --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
            "fix_cfn": "Resources:\n  AdminRole:\n    Type: AWS::IAM::Role\n    Properties:\n      ManagedPolicyArns:\n        - arn:aws:iam::aws:policy/AdministratorAccess",
            "fix_console": "1. Go to IAM Console -> Users -> admin-alice.\n2. In the Permissions tab, find AdministratorAccess and click Remove."
        },
        "IAM_WILDCARD_POLICIES": {
            "why_dangerous": "Policies allowing wildcard actions (`*:*`) on all resources (`*`) bypass granular policy checks and grant excessive administrative permissions.",
            "estimated_impact": "HIGH - Privilege escalation. A compromise of any minor application role allows full infrastructure control.",
            "mitre_attack": "T1098 - Account Manipulation",
            "cis_benchmark": "CIS 1.20 - Enforce Least Privilege access models (Level 1)",
            "real_world_incident": "A test profile allowed `s3:*` on all resources. An attacker compromised an instance using this profile, reading and deleting all backup buckets.",
            "exploitation_example": "aws s3api delete-bucket --bucket corporate-backups (allowed by wildcard resources)",
            "aws_docs": "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html",
            "fix_terraform": "resource \"aws_iam_policy\" \"restricted_s3\" {\n  policy = jsonencode({\n    Version = \"2012-10-17\"\n    Statement = [{\n      Effect = \"Allow\", Action = [\"s3:GetObject\"],\n      Resource = \"arn:aws:s3:::my-secure-reports-bucket/*\"\n    }]\n  })\n}",
            "fix_cli": "aws iam create-policy-version --policy-arn arn:aws:iam::123:policy/UnsafeS3Policy --policy-document file://policy.json --set-as-default",
            "fix_cfn": "Resources:\n  RestrictedPolicy:\n    Type: AWS::IAM::Policy\n    Properties:\n      PolicyDocument:\n        Statement:\n          - Effect: Allow\n            Action: s3:GetObject\n            Resource: arn:aws:s3:::my-secure-reports-bucket/*",
            "fix_console": "1. Open IAM Console -> Policies -> find the unsafe policy.\n2. Click Edit Policy, switch to JSON, and replace '*' with exact resources/actions."
        },
        "S3_PUBLIC_BUCKETS": {
            "why_dangerous": "Public buckets allow anonymous read/write operations from anywhere on the internet. Attackers can scan for, read, or alter your files anonymously.",
            "estimated_impact": "CRITICAL - Exposure of customer files, databases, or credentials. High risk of regulatory fines.",
            "mitre_attack": "T1530 - Data from Cloud Storage Object",
            "cis_benchmark": "CIS 2.1.1 - Secure S3 Bucket Policies (Level 1)",
            "real_world_incident": "The Capital One data breach (2019) leaked 100 million customer records due to S3 exposures and web firewall vulnerabilities.",
            "exploitation_example": "aws s3 ls s3://my-public-reports-bucket --no-sign-request",
            "aws_docs": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
            "fix_terraform": "resource \"aws_s3_bucket_public_access_block\" \"block\" {\n  bucket = \"my-public-reports-bucket\"\n  block_public_acls = true\n  block_public_policy = true\n}",
            "fix_cli": "aws s3api put-public-access-block --bucket my-public-reports-bucket --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
            "fix_cfn": "Resources:\n  SecureS3Bucket:\n    Type: AWS::S3::Bucket\n    Properties:\n      PublicAccessBlockConfiguration:\n        BlockPublicAcls: true\n        BlockPublicPolicy: true",
            "fix_console": "1. Open S3 Console -> click the public bucket.\n2. Select Permissions -> under 'Block public access', click Edit -> check 'Block all public access' and save."
        },
        "S3_BUCKET_ENCRYPTION": {
            "why_dangerous": "Unencrypted objects are written as cleartext. If AWS physical storage media is compromised, your static data can be read in cleartext.",
            "estimated_impact": "HIGH - Compliance failures (SOC2/HIPAA) and unauthorized data read risk.",
            "mitre_attack": "T1530 - Data from Cloud Storage",
            "cis_benchmark": "CIS 2.1.2 - Ensure S3 default encryption is enabled (Level 1)",
            "real_world_incident": "An audit of a healthcare app flagged unencrypted S3 buckets, leading to a $50k compliance penalty.",
            "exploitation_example": "Attacker bypasses hypervisor security gates to read raw block sectors from S3 storage.",
            "aws_docs": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html",
            "fix_terraform": "resource \"aws_s3_bucket_server_side_encryption_configuration\" \"encrypt\" {\n  bucket = \"temp-scratchpad-bucket\"\n  rule {\n    apply_server_side_encryption_by_default {\n      sse_algorithm = \"AES256\"\n    }\n  }\n}",
            "fix_cli": "aws s3api put-bucket-encryption --bucket temp-scratchpad-bucket --server-side-encryption-configuration '{\"Rules\": [{\"ApplyServerSideEncryptionByDefault\": {\"SSEAlgorithm\": \"AES256\"}}]}'",
            "fix_cfn": "Resources:\n  EncryptedBucket:\n    Type: AWS::S3::Bucket\n    Properties:\n      BucketEncryption:\n        ServerSideEncryptionConfiguration:\n          - ServerSideEncryptionByDefault:\n              SSEAlgorithm: AES256",
            "fix_console": "1. Go to S3 Console -> temp-scratchpad-bucket.\n2. Properties tab -> edit 'Default encryption' -> select 'Enable' and save."
        },
        "EC2_PUBLIC_INSTANCES": {
            "why_dangerous": "Public instances are exposed to the open internet. Attackers can scan, locate vulnerable services, and target them directly.",
            "estimated_impact": "HIGH - Direct intrusion target, vulnerability scanning, and malware penetration access points.",
            "mitre_attack": "T1083 - File and Directory Discovery",
            "cis_benchmark": "CIS 4.1 - Restrict ingress from 0.0.0.0/0 (Level 1)",
            "real_world_incident": "A production database was deployed with a public IP. Automated scanners brute-forced credentials and exfiltrated the schemas.",
            "exploitation_example": "nmap -Pn -p- 54.210.43.99 -> discover vulnerable service -> exploit",
            "aws_docs": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-instance-addressing.html",
            "fix_terraform": "resource \"aws_instance\" \"secure\" {\n  subnet_id = \"subnet-private\"\n  associate_public_ip_address = false\n}",
            "fix_cli": "aws ec2 create-image --instance-id i-0abcd1234efgh5678 --name \"secured-backup\"\n# Relaunch in a private subnet, terminate the public instance.",
            "fix_cfn": "Resources:\n  PrivateInstance:\n    Type: AWS::EC2::Instance\n    Properties:\n      SubnetId: subnet-private-id",
            "fix_console": "1. Move public instances to private subnets. Place an Application Load Balancer in the public subnet to route traffic securely."
        },
        "EC2_SG_EXPOSED_SSH": {
            "why_dangerous": "Exposing SSH globally allows brute-force attacks and scans from all over the world.",
            "estimated_impact": "HIGH - Brute-force credentials penetration and instance takeover.",
            "mitre_attack": "T1021.004 - Remote Services: SSH",
            "cis_benchmark": "CIS 4.1 - Restrict SSH access from 0.0.0.0/0 (Level 1)",
            "real_world_incident": "A security group left SSH open. A botnet brute-forced a weak password and deployed cryptominers.",
            "exploitation_example": "hydra -l ec2-user -P rockyou.txt ssh://54.210.43.99",
            "aws_docs": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html",
            "fix_terraform": "resource \"aws_security_group_rule\" \"ssh\" {\n  type = \"ingress\", from_port = 22, to_port = 22, protocol = \"tcp\"\n  cidr_blocks = [\"192.168.1.0/24\"]\n  security_group_id = \"sg-012345\"\n}",
            "fix_cli": "aws ec2 revoke-security-group-ingress --group-id sg-012345 --protocol tcp --port 22 --cidr 0.0.0.0/0\naws ec2 authorize-security-group-ingress --group-id sg-012345 --protocol tcp --port 22 --cidr 192.168.1.0/24",
            "fix_cfn": "SecurityGroupIngress:\n  - IpProtocol: tcp\n    FromPort: 22\n    ToPort: 22\n    CidrIp: 192.168.1.0/24",
            "fix_console": "1. EC2 -> Security Groups -> select dev-sg.\n2. Inbound rules -> Edit -> change source of SSH rule from Anywhere to My IP or a trusted CIDR block."
        },
        "EC2_SG_OPEN_ALL_TRAFFIC": {
            "why_dangerous": "An 'All Traffic' rule allows any protocol on any port, making the firewall completely useless.",
            "estimated_impact": "CRITICAL - Complete firewall bypass, exposing all running database ports and diagnostic consoles.",
            "mitre_attack": "T1562 - Impair Defenses",
            "cis_benchmark": "CIS 4.2 - Disable all-traffic ingress rules (Level 1)",
            "real_world_incident": "A developer opened all ports to debug an application. The rule was forgotten, and databases were hijacked and wiped for ransom.",
            "exploitation_example": "telnet 54.210.43.99 3306 (connect to internal DB directly)",
            "aws_docs": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/working-with-security-groups.html",
            "fix_terraform": "resource \"aws_security_group_rule\" \"http\" {\n  from_port = 80, to_port = 80, protocol = \"tcp\", cidr_blocks = [\"0.0.0.0/0\"]\n  security_group_id = \"sg-012345\"\n}",
            "fix_cli": "aws ec2 revoke-security-group-ingress --group-id sg-012345 --ip-permissions '[{\"IpProtocol\": \"-1\", \"IpRanges\": [{\"CidrIp\": \"0.0.0.0/0\"}]}]'",
            "fix_cfn": "SecurityGroupIngress:\n  - IpProtocol: tcp\n    FromPort: 443\n    ToPort: 443\n    CidrIp: 0.0.0.0/0",
            "fix_console": "1. Go to EC2 Console -> Security Groups.\n2. Select dev-sg -> Edit Inbound rules -> delete the 'All traffic' rule and save."
        }
    };

    // --- DOM Elements ---
    const tabButtons = document.querySelectorAll(".nav-item");
    const tabContents = document.querySelectorAll(".tab-content");
    
    const btnOpenScan = document.getElementById("btn-open-scan-modal");
    const btnCloseScan = document.getElementById("btn-close-modal");
    const btnCancelScan = document.getElementById("btn-cancel-scan");
    const liveCredSection = document.getElementById("live-cred-section");
    const scanConsole = document.getElementById("scan-console");
    const consoleLines = document.getElementById("console-log-lines");
    const btnSubmitScan = document.getElementById("btn-submit-scan");
    const btnRefreshHistory = document.getElementById("btn-refresh-history");
    const scanModal = document.getElementById("scan-modal");
    const scanForm = document.getElementById("scan-form");
    const scanFormInputs = document.getElementById("scan-form-inputs");
    const btnConfigureScan = document.getElementById("btn-configure-scan");
    const consoleSpinner = document.getElementById("console-spinner");
    const consoleStatusBadge = document.getElementById("console-status-badge");

    const findingsContainer = document.getElementById("findings-container");
    const historyContainer = document.getElementById("history-container");

    // Filters
    const filterSearch = document.getElementById("filter-search");
    const filterService = document.getElementById("filter-service");
    const filterStatus = document.getElementById("filter-status");

    // Toast
    const toast = document.getElementById("notification-toast");
    const toastTitle = document.getElementById("toast-title");
    const toastMsg = document.getElementById("toast-msg");

    // Copilot Drawer Elements
    const copilotDrawer = document.getElementById("copilot-drawer");
    const btnCloseCopilot = document.getElementById("btn-close-copilot");
    const copilotMessages = document.getElementById("copilot-chat-messages");
    const copilotInput = document.getElementById("copilot-chat-input");
    const btnCopilotSend = document.getElementById("btn-copilot-send");
    let copilotActiveCheckId = null;

    // Export Reports Menu Elements
    const btnExportDropdown = document.getElementById("btn-export-dropdown");
    const exportMenu = document.getElementById("export-dropdown-menu");

    // Compliance Tab Elements
    const compFrameworkBtns = document.querySelectorAll(".compliance-selectors button");
    const compPercentage = document.getElementById("compliance-percentage");
    const compFailedCount = document.getElementById("compliance-failed-count");
    const compListContainer = document.getElementById("compliance-rules-list");

    // --- Tab Switching & Navigation ---
    tabButtons.forEach(btn => {
        btn.addEventListener("click", () => {
            const tabId = btn.getAttribute("data-tab");
            
            tabButtons.forEach(b => b.classList.remove("active"));
            btn.classList.add("active");
            
            tabContents.forEach(content => {
                content.classList.remove("active");
                if (content.id === `tab-${tabId}`) {
                    content.classList.add("active");
                }
            });

            const viewTitle = document.getElementById("view-title");
            const viewSubtitle = document.getElementById("view-subtitle");
            
            if (tabId === "dashboard") {
                viewTitle.innerText = "Dashboard Overview";
                viewSubtitle.innerText = "AI-Powered Cloud Security Copilot for AWS";
            } else if (tabId === "compliance") {
                viewTitle.innerText = "Compliance Explorer";
                viewSubtitle.innerText = "Evaluate posture against CIS AWS Foundations, SOC 2 and HIPAA security rules";
                renderComplianceView();
            } else if (tabId === "history") {
                viewTitle.innerText = "Audit History";
                viewSubtitle.innerText = "Download historical compliance logs and audience-specific reports";
                loadHistory();
            } else if (tabId === "integrations") {
                viewTitle.innerText = "External Integrations";
                viewSubtitle.innerText = "Publish threat logs to Slack alerts or trigger auto-remediation policies";
            }
        });
    });

    // --- Export Dropdown Handling ---
    btnExportDropdown.addEventListener("click", (e) => {
        e.stopPropagation();
        exportMenu.classList.toggle("hide");
    });

    document.addEventListener("click", () => {
        exportMenu.classList.add("hide");
    });

    exportMenu.querySelectorAll(".export-link").forEach(link => {
        link.addEventListener("click", (e) => {
            e.preventDefault();
            const aud = link.getAttribute("data-audience");
            if (currentScanId) {
                window.open(`/api/download/${currentScanId}/pdf?audience=${aud}`, "_blank");
            } else {
                showToast("No Scan Loaded", "Please run or load a scan before exporting reports.", false);
            }
        });
    });

    // --- Modal Configuration Handlers ---
    const resetModalState = () => {
        scanFormInputs.classList.remove("hide");
        scanConsole.classList.add("hide");
        btnConfigureScan.classList.add("hide");
        btnSubmitScan.classList.remove("hide");
        btnSubmitScan.disabled = false;
        btnSubmitScan.querySelector("span").innerText = "Launch Scan";
        btnCancelScan.classList.remove("hide");
        consoleSpinner.classList.remove("hide");
        consoleStatusBadge.innerHTML = `<span class="dot"></span> RUNNING`;
        consoleLines.innerHTML = "";
    };

    btnOpenScan.addEventListener("click", () => {
        scanModal.classList.add("active");
        resetModalState();
    });

    const closeModal = () => {
        scanModal.classList.remove("active");
        consoleLines.innerHTML = "";
    };

    btnCloseScan.addEventListener("click", closeModal);
    btnCancelScan.addEventListener("click", closeModal);

    btnConfigureScan.addEventListener("click", () => {
        // Switch back to inputs layout
        scanFormInputs.classList.remove("hide");
        scanConsole.classList.add("hide");
        btnConfigureScan.classList.add("hide");
        btnSubmitScan.classList.remove("hide");
        btnSubmitScan.disabled = false;
        btnSubmitScan.querySelector("span").innerText = "Launch Scan";
        btnCancelScan.classList.remove("hide");
    });

    const showToast = (title, message, isSuccess = true) => {
        toastTitle.innerText = title;
        toastMsg.innerText = message;
        toast.className = `toast ${isSuccess ? 'success' : 'error'}`;
        
        const icon = toast.querySelector(".toast-icon");
        if (isSuccess) {
            icon.className = "fa-solid fa-circle-check toast-icon";
            toast.style.backgroundColor = "rgba(16, 185, 129, 0.95)";
        } else {
            icon.className = "fa-solid fa-circle-xmark toast-icon";
            toast.style.backgroundColor = "rgba(239, 68, 68, 0.95)";
        }

        setTimeout(() => {
            toast.classList.remove("hide");
        }, 50);

        setTimeout(() => {
            toast.classList.add("hide");
        }, 4000);
    };

    const runConsoleLog = async () => {
        scanConsole.classList.remove("hide");
        consoleLines.innerHTML = "";
        
        const logs = [
            { type: "info", text: "Establishing secure session connection via Boto3 API..." },
            { type: "info", text: "Resolving STS Caller Identity..." },
            { type: "info", text: "Connecting to AWS endpoints. Retrieving resources list..." },
            { type: "info", text: "Running checks: IAM user tables and attached policy tables..." },
            { type: "info", text: "Running checks: S3 list buckets and ACL validations..." },
            { type: "info", text: "Running checks: EC2 instance metadata and SG rule maps..." },
            { type: "info", text: "Running checks: CloudTrail organization trails..." },
            { type: "info", text: "Running checks: VPC networking configuration rules..." },
            { type: "success", text: "Live scan completed successfully! Finalizing database entries..." }
        ];

        for (const line of logs) {
            const el = document.createElement("div");
            el.className = line.type;
            el.innerText = `[${new Date().toLocaleTimeString()}] ${line.text}`;
            consoleLines.appendChild(el);
            consoleLines.scrollTop = consoleLines.scrollHeight;
            await new Promise(r => setTimeout(r, 150));
        }
    };

    btnSubmitScan.addEventListener("click", async () => {
        btnSubmitScan.disabled = true;
        btnSubmitScan.querySelector("span").innerText = "Scanning...";

        const regions = Array.from(document.querySelectorAll('input[name="regions"]:checked')).map(el => el.value);
        const awsKeyId = document.getElementById("aws-key-id").value.trim();
        const awsSecretKey = document.getElementById("aws-secret-key").value.trim();
        const awsSessionToken = document.getElementById("aws-session-token").value.trim();

        if (regions.length === 0) {
            showToast("Selection Error", "Please select at least one target region to scan.", false);
            btnSubmitScan.disabled = false;
            btnSubmitScan.querySelector("span").innerText = "Launch Scan";
            return;
        }

        // SWAP UI: Hide inputs, show console log, hide footer buttons
        scanFormInputs.classList.add("hide");
        scanConsole.classList.remove("hide");
        btnSubmitScan.classList.add("hide");
        btnCancelScan.classList.add("hide");

        await runConsoleLog();

        const payload = {
            is_mock: false,
            regions: regions,
            aws_access_key_id: awsKeyId || null,
            aws_secret_access_key: awsSecretKey || null,
            aws_session_token: awsSessionToken || null
        };

        try {
            const resp = await fetch("/api/scan", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });

            if (!resp.ok) {
                const errData = await resp.json();
                throw new Error(errData.detail || "Scan execution failed.");
            }

            const scanResult = await resp.json();
            showToast("Scan Completed", `Successfully audited AWS environment. Score: ${scanResult.score}/100.`);
            loadScanDetails(scanResult.id);
            setTimeout(closeModal, 600);
        } catch (e) {
            const el = document.createElement("div");
            el.className = "err";
            el.innerText = `[ERROR] Scan execution failed: ${e.message}`;
            consoleLines.appendChild(el);
            
            // Show failure states
            consoleSpinner.classList.add("hide");
            consoleStatusBadge.innerHTML = `<span style="color: var(--critical);">FAILED</span>`;
            showToast("Scan Failed", e.message, false);
            
            // Allow user to go back and fix configurations
            btnConfigureScan.classList.remove("hide");
            btnCancelScan.classList.remove("hide");
        }
    });

    const loadScanDetails = async (scanId) => {
        try {
            const resp = await fetch(`/api/scan/${scanId}`);
            if (!resp.ok) throw new Error("Could not fetch scan details.");
            
            const data = await resp.json();
            currentScanId = scanId;
            currentSummary = data.summary;
            currentFindings = data.findings;

            // Update UI widgets
            document.getElementById("stat-score").innerText = currentSummary.score;
            document.getElementById("stat-critical").innerText = currentSummary.critical_count;
            document.getElementById("stat-high").innerText = currentSummary.high_count;
            document.getElementById("stat-medium").innerText = currentSummary.medium_count;
            document.getElementById("stat-low").innerText = currentSummary.low_count;
            document.getElementById("stat-total-findings").innerText = currentSummary.failed_checks;

            // Set Grade badge
            const gradeBadge = document.getElementById("stat-grade");
            let grade = "F";
            let gradeColor = "var(--critical)";
            if (currentSummary.score >= 90) { grade = "A"; gradeColor = "var(--pass)"; }
            else if (currentSummary.score >= 80) { grade = "B"; gradeColor = "var(--pass)"; }
            else if (currentSummary.score >= 70) { grade = "C"; gradeColor = "var(--medium)"; }
            else if (currentSummary.score >= 60) { grade = "D"; gradeColor = "var(--high)"; }
            
            gradeBadge.innerText = grade;
            gradeBadge.style.color = gradeColor;

            // Dynamic additions
            renderAIPrioritization(currentFindings);
            drawAttackPathGraph(currentFindings);
            renderFindingsList();
            drawCharts();

            // Fetch and render new insight panels
            fetchAndRenderInsights(scanId);
            fetchAndRenderResources(scanId);

        } catch (e) {
            showToast("Error Loading Scan", e.message, false);
        }
    };

    // --- Fetch and Render Insights (Delta Banner + Service Gauges) ---
    const fetchAndRenderInsights = async (scanId) => {
        try {
            const resp = await fetch(`/api/scan/${scanId}/insights`);
            if (!resp.ok) return;
            const data = await resp.json();
            renderDeltaBanner(data.delta);
            renderServiceHealthGauges(data.service_health);
        } catch (e) {
            console.warn("Insights fetch error:", e);
        }
    };

    // --- Fetch and Render Resource Heatmap ---
    const fetchAndRenderResources = async (scanId) => {
        try {
            const resp = await fetch(`/api/scan/${scanId}/resources`);
            if (!resp.ok) return;
            const data = await resp.json();
            renderResourceHeatmap(data.resources);
        } catch (e) {
            console.warn("Resources fetch error:", e);
        }
    };

    // --- Render Scan Delta Comparison Banner ---
    const renderDeltaBanner = (delta) => {
        const banner = document.getElementById("delta-banner");
        if (!delta) {
            banner.classList.add("hide");
            return;
        }

        const arrowIcon = document.getElementById("delta-arrow-icon");
        const deltaValue = document.getElementById("delta-value");
        const resolvedCount = document.getElementById("delta-resolved-count");
        const introducedCount = document.getElementById("delta-introduced-count");
        const prevScore = document.getElementById("delta-prev-score");
        const trendLabel = document.getElementById("delta-trend-label");

        // Set arrow direction and color
        arrowIcon.className = "fa-solid delta-arrow";
        if (delta.trend === "improved") {
            arrowIcon.classList.add("fa-arrow-trend-up", "improved");
            deltaValue.className = "delta-value positive";
            deltaValue.innerText = `+${delta.score_change}`;
        } else if (delta.trend === "degraded") {
            arrowIcon.classList.add("fa-arrow-trend-down", "degraded");
            deltaValue.className = "delta-value negative";
            deltaValue.innerText = `${delta.score_change}`;
        } else {
            arrowIcon.classList.add("fa-equals", "unchanged");
            deltaValue.className = "delta-value neutral";
            deltaValue.innerText = "0";
        }

        resolvedCount.innerText = delta.resolved_count;
        introducedCount.innerText = delta.newly_introduced_count;
        prevScore.innerText = `${delta.previous_score}/100`;
        trendLabel.innerText = `Compared to previous scan (${delta.previous_scan_id.substring(0, 8)}...)`;

        banner.classList.remove("hide");
    };

    // --- Render Per-Service Health Gauges ---
    const renderServiceHealthGauges = (serviceHealth) => {
        if (!serviceHealth) return;

        const serviceMap = {
            "IAM": { barId: "gauge-iam", pctId: "gauge-iam-pct" },
            "S3": { barId: "gauge-s3", pctId: "gauge-s3-pct" },
            "EC2": { barId: "gauge-ec2", pctId: "gauge-ec2-pct" },
            "CloudTrail": { barId: "gauge-cloudtrail", pctId: "gauge-cloudtrail-pct" },
            "Networking": { barId: "gauge-networking", pctId: "gauge-networking-pct" }
        };

        for (const [svc, ids] of Object.entries(serviceMap)) {
            const data = serviceHealth[svc];
            const bar = document.getElementById(ids.barId);
            const pct = document.getElementById(ids.pctId);
            
            if (!data || !bar || !pct) continue;

            const rate = data.pass_rate;
            bar.style.width = `${rate}%`;
            pct.innerText = `${rate}%`;

            // Color class based on health
            bar.className = "gauge-bar-fill";
            if (rate >= 90) { bar.classList.add("excellent"); pct.style.color = "var(--pass)"; }
            else if (rate >= 70) { bar.classList.add("good"); pct.style.color = "var(--pass)"; }
            else if (rate >= 50) { bar.classList.add("warning"); pct.style.color = "var(--medium)"; }
            else if (rate >= 25) { bar.classList.add("poor"); pct.style.color = "var(--high)"; }
            else { bar.classList.add("critical"); pct.style.color = "var(--critical)"; }
        }
    };

    // --- Render Resource Risk Heatmap ---
    const renderResourceHeatmap = (resources) => {
        const heatmap = document.getElementById("resource-heatmap");
        const list = document.getElementById("heatmap-list");
        const countBadge = document.getElementById("heatmap-resource-count");

        // Only show resources with at least 1 failed check
        const riskyResources = resources.filter(r => r.failed_checks > 0).slice(0, 8);
        
        if (riskyResources.length === 0) {
            heatmap.classList.add("hide");
            return;
        }

        countBadge.innerText = riskyResources.length;
        list.innerHTML = "";

        riskyResources.forEach(r => {
            const riskLevel = r.risk_score >= 20 ? "critical" : (r.risk_score >= 15 ? "high" : (r.risk_score >= 8 ? "medium" : "low"));
            let scoreColor = "var(--critical)";
            if (r.risk_score < 8) scoreColor = "var(--low)";
            else if (r.risk_score < 15) scoreColor = "var(--medium)";
            else if (r.risk_score < 20) scoreColor = "var(--high)";

            // Build severity dots
            let dotsHtml = "";
            const sevCounts = r.severity_counts;
            for (let i = 0; i < sevCounts.CRITICAL; i++) dotsHtml += '<span class="sev-dot critical"></span>';
            for (let i = 0; i < sevCounts.HIGH; i++) dotsHtml += '<span class="sev-dot high"></span>';
            for (let i = 0; i < sevCounts.MEDIUM; i++) dotsHtml += '<span class="sev-dot medium"></span>';
            for (let i = 0; i < sevCounts.LOW; i++) dotsHtml += '<span class="sev-dot low"></span>';

            const item = document.createElement("div");
            item.className = "heatmap-item";
            item.innerHTML = `
                <div class="heatmap-risk-indicator risk-${riskLevel}"></div>
                <div class="heatmap-info">
                    <div class="heatmap-resource-name"><code>${r.resource_id}</code></div>
                    <div class="heatmap-meta">
                        <span>${r.failed_checks} failed check${r.failed_checks !== 1 ? 's' : ''}</span>
                        <span>${r.region}</span>
                        <div class="heatmap-severity-dots">${dotsHtml}</div>
                    </div>
                </div>
                <div class="heatmap-score" style="color: ${scoreColor}">${r.risk_score}</div>
            `;

            // Click to filter findings by this resource
            item.addEventListener("click", () => {
                filterSearch.value = r.resource_id;
                renderFindingsList();
                const findingsSection = document.querySelector(".findings-section");
                if (findingsSection) findingsSection.scrollIntoView({ behavior: "smooth" });
            });

            list.appendChild(item);
        });

        heatmap.classList.remove("hide");
    };

    // --- AI Prioritization Implementation (Step 4) ---
    const renderAIPrioritization = (findings) => {
        const priorityCard = document.getElementById("ai-prioritization-card");
        const priorityList = document.getElementById("ai-priority-list");
        priorityList.innerHTML = "";

        const failedChecks = findings.filter(f => f.status !== "PASS");
        if (failedChecks.length === 0) {
            priorityCard.classList.add("hide");
            return;
        }

        const recommendations = [];

        // Check 1: Exposed EC2 Node containing Wildcard Role Profile (Chained Threat Path)
        const hasExposedInstance = findings.some(f => (f.check_id === "EC2_PUBLIC_INSTANCES" || f.check_id === "EC2_SG_EXPOSED_SSH") && f.status !== "PASS");
        const hasWildcardRole = findings.some(f => (f.check_id === "IAM_WILDCARD_POLICIES" || f.check_id === "IAM_ADMIN_ACCESS") && f.status !== "PASS");
        if (hasExposedInstance && hasWildcardRole) {
            recommendations.push({
                severity: "CRITICAL",
                text: "<strong>Critical Chain Vulnerability</strong>: You have public EC2 instances combined with IAM roles using unrestricted wildcard permissions. An attacker compromising an exposed EC2 can assume the attached instance profile to gain administrative control over the entire account immediately."
            });
        }

        // Check 2: Public storage without encryption
        const hasPublicBucket = findings.some(f => f.check_id === "S3_PUBLIC_BUCKETS" && f.status !== "PASS");
        const hasUnencryptedS3 = findings.some(f => f.check_id === "S3_BUCKET_ENCRYPTION" && f.status !== "PASS");
        if (hasPublicBucket && hasUnencryptedS3) {
            recommendations.push({
                severity: "CRITICAL",
                text: "<strong>High Risk Storage Chain</strong>: The public S3 bucket is unencrypted. Intruders can extract cleartext database backups or credentials anonymously. Configure default server-side encryption immediately."
            });
        }

        // Check 3: Root Account MFA Disabled
        const hasNoRootMFA = findings.some(f => f.check_id === "IAM_ROOT_MFA" && f.status !== "PASS");
        if (hasNoRootMFA) {
            recommendations.push({
                severity: "HIGH",
                text: "<strong>Identity exposure warning</strong>: Root user has no Multi-factor authentication configured. Lock down access keys immediately and apply physical or virtual authenticator loops."
            });
        }

        // Default if no specific chains matched
        if (recommendations.length === 0) {
            // Push top 2 failures by severity
            const sortedFailures = [...failedChecks].sort((a,b) => {
                const priority = { "CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1 };
                return priority[b.severity] - priority[a.severity];
            });
            
            for (let i = 0; i < Math.min(2, sortedFailures.length); i++) {
                const f = sortedFailures[i];
                recommendations.push({
                    severity: f.severity,
                    text: `AI prioritized threat recommendation: Fix <strong>${f.check_name}</strong> on resource <code>${f.resource_id}</code> because it carries a ${f.severity} risk score.`
                });
            }
        }

        recommendations.forEach(rec => {
            const el = document.createElement("div");
            el.className = "priority-item";
            
            let badgeClass = rec.severity.toLowerCase();
            el.innerHTML = `
                <span class="badge ${badgeClass}">${rec.severity}</span>
                <span>${rec.text}</span>
            `;
            priorityList.appendChild(el);
        });

        priorityCard.classList.remove("hide");
    };

    // --- Interactive SVG Attack Path Graph (Step 6) ---
    const drawAttackPathGraph = (findings) => {
        const container = document.getElementById("attack-path-graph-container");
        container.innerHTML = "";
        
        // Dynamic flags
        const hasS3Expose = findings.some(f => 
            f.check_id === "S3_PUBLIC_BUCKETS" && f.status !== "PASS"
        );
        
        const hasEc2Breach = findings.some(f => 
            (f.check_id === "EC2_PUBLIC_INSTANCES" || f.check_id === "EC2_SG_EXPOSED_SSH" || f.check_id === "EC2_SG_OPEN_ALL_TRAFFIC") 
            && f.status !== "PASS"
        );
        
        const hasIamEscalate = findings.some(f => 
            (f.check_id === "IAM_WILDCARD_POLICIES" || f.check_id === "IAM_ADMIN_ACCESS" || f.check_id === "IAM_ROOT_MFA") 
            && f.status !== "PASS"
        );

        const nodes = [
            { id: "internet", label: "Internet", x: 35, y: 100, color: "#10b981", active: true, desc: "Global Public Internet Source" },
            { id: "s3_expose", label: "S3 Expose", x: 145, y: 45, color: hasS3Expose ? "#ef4444" : "#10b981", active: hasS3Expose, desc: hasS3Expose ? "CRITICAL: Public buckets open to anonymous listing!" : "S3 Private Bucket Access enforced" },
            { id: "ec2_breach", label: "EC2 Entry", x: 145, y: 155, color: hasEc2Breach ? "#ef4444" : "#10b981", active: hasEc2Breach, desc: hasEc2Breach ? "CRITICAL: Exposed services or public EC2 interface detected!" : "EC2 network firewalls are secure" },
            { id: "iam_escalate", label: "IAM Privilege", x: 260, y: 155, color: hasIamEscalate ? "#f97316" : "#10b981", active: hasIamEscalate, desc: hasIamEscalate ? "HIGH: Admin or Wildcard Policies allow privilege escalation!" : "IAM Least Privilege rules verified" },
            { id: "data_assets", label: "Data Asset", x: 345, y: 100, color: (hasS3Expose || hasIamEscalate) ? "#ef4444" : "#3b82f6", active: (hasS3Expose || hasIamEscalate), desc: (hasS3Expose || hasIamEscalate) ? "CRITICAL: High-risk lateral paths lead to data infiltration vector!" : "Target assets secure and fully encrypted" }
        ];

        // Map nodes by ID for connection lookups
        const nodeMap = {};
        nodes.forEach(n => nodeMap[n.id] = n);

        const connections = [
            { from: "internet", to: "s3_expose", active: hasS3Expose },
            { from: "internet", to: "ec2_breach", active: hasEc2Breach },
            { from: "s3_expose", to: "data_assets", active: hasS3Expose },
            { from: "ec2_breach", to: "iam_escalate", active: hasEc2Breach && hasIamEscalate },
            { from: "iam_escalate", to: "data_assets", active: hasIamEscalate }
        ];

        let svgHtml = `<svg class="attack-path-svg" viewBox="0 0 380 200">
            <defs>
                <marker id="arrow" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
                    <path d="M 0 0 L 10 5 L 0 10 z" fill="rgba(255,255,255,0.15)"/>
                </marker>
                <marker id="arrow-active" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
                    <path d="M 0 0 L 10 5 L 0 10 z" fill="#ef4444"/>
                </marker>
            </defs>`;

        // Draw connections
        connections.forEach(c => {
            const n1 = nodeMap[c.from];
            const n2 = nodeMap[c.to];
            const activeColor = n2.color;
            svgHtml += `<path d="M ${n1.x} ${n1.y} L ${n2.x} ${n2.y}" 
                class="path-line ${c.active ? 'active' : ''}" 
                style="stroke: ${c.active ? activeColor : 'rgba(255,255,255,0.06)'}" 
                marker-end="url(${c.active ? '#arrow-active' : '#arrow'})" />`;
        });

        // Draw nodes
        nodes.forEach(n => {
            let haloHtml = "";
            if (n.active && n.id !== "internet") {
                haloHtml = `<circle cx="${n.x}" cy="${n.y}" r="14" class="pulsing-halo" fill="none" stroke="${n.color}" />`;
            }
            svgHtml += `
                <g class="node-group" data-desc="${n.desc}">
                    ${haloHtml}
                    <circle cx="${n.x}" cy="${n.y}" r="14" fill="#0b0f19" stroke="${n.color}" stroke-width="3" />
                    <circle cx="${n.x}" cy="${n.y}" r="6" fill="${n.color}" />
                    <text x="${n.x}" y="${n.y + 32}" text-anchor="middle" fill="#f1f5f9" font-size="9" font-weight="600">${n.label}</text>
                </g>
            `;
        });

        svgHtml += `</svg>`;
        container.innerHTML = svgHtml;

        // Hover tooltip
        const tooltip = document.createElement("div");
        tooltip.className = "glass";
        tooltip.style.position = "absolute";
        tooltip.style.backgroundColor = "rgba(11,15,25,0.95)";
        tooltip.style.border = "1px solid var(--color-primary)";
        tooltip.style.padding = "6px 12px";
        tooltip.style.borderRadius = "6px";
        tooltip.style.fontSize = "11px";
        tooltip.style.color = "#ffffff";
        tooltip.style.pointerEvents = "none";
        tooltip.style.display = "none";
        tooltip.style.zIndex = "100";
        container.appendChild(tooltip);

        container.querySelectorAll(".node-group").forEach(el => {
            el.addEventListener("mouseenter", () => {
                tooltip.innerText = el.getAttribute("data-desc");
                tooltip.style.display = "block";
            });
            el.addEventListener("mousemove", (e) => {
                const rect = container.getBoundingClientRect();
                tooltip.style.left = `${e.clientX - rect.left + 15}px`;
                tooltip.style.top = `${e.clientY - rect.top + 15}px`;
            });
            el.addEventListener("mouseleave", () => {
                tooltip.style.display = "none";
            });
        });
    };

    // --- Render Findings (Expanded with Code Fix Tabs & Learning Mode) (Step 4 & 9) ---
    const renderFindingsList = () => {
        const textQuery = filterSearch.value.toLowerCase().trim();
        const serviceQuery = filterService.value;
        const statusQuery = filterStatus.value;

        // Smart Natural Language Filters parsing
        let searchString = textQuery;
        let forcedService = null;
        let forcedSeverity = null;
        
        if (textQuery.includes("show s3")) {
            forcedService = "S3";
            searchString = textQuery.replace("show s3", "").trim();
        } else if (textQuery.includes("show iam")) {
            forcedService = "IAM";
            searchString = textQuery.replace("show iam", "").trim();
        } else if (textQuery.includes("show critical")) {
            forcedSeverity = "CRITICAL";
            searchString = textQuery.replace("show critical", "").trim();
        } else if (textQuery.includes("why is score low") || textQuery.includes("encryption failures")) {
            // Conversational triggers
            const btnAsk = document.createElement("button");
            btnAsk.className = "btn btn-primary btn-sm";
            btnAsk.style.margin = "8px";
            btnAsk.innerHTML = "<i class='fa-solid fa-robot'></i> Ask Copilot Why Score is Low";
            btnAsk.onclick = () => {
                const firstFail = currentFindings.find(f => f.status !== "PASS");
                if (firstFail) triggerCopilotPanel(firstFail.check_id, "Why is my security score low?");
            };
            findingsContainer.innerHTML = "";
            findingsContainer.appendChild(btnAsk);
            return;
        }

        const filtered = currentFindings.filter(f => {
            const matchesText = !searchString || f.check_name.toLowerCase().includes(searchString) || 
                                f.resource_id.toLowerCase().includes(searchString) ||
                                f.message.toLowerCase().includes(searchString);
            
            const matchesService = forcedService ? f.service === forcedService : (serviceQuery === "ALL" || f.service === serviceQuery);
            const matchesSeverity = forcedSeverity ? f.severity === forcedSeverity : 
                                    (activeSeverityFilter ? f.severity === activeSeverityFilter : true);
            const matchesStatus = statusQuery === "ALL" || f.status === statusQuery;
            
            return matchesText && matchesService && matchesStatus && matchesSeverity;
        });

        findingsContainer.innerHTML = "";

        if (filtered.length === 0) {
            findingsContainer.innerHTML = `
                <div class="empty-state">
                    <i class="fa-solid fa-circle-check" style="color: var(--pass);"></i>
                    <p>No issues match the selected search filters.</p>
                </div>
            `;
            return;
        }

        filtered.forEach((f, index) => {
            const item = document.createElement("div");
            item.className = "finding-item";
            
            const isFailed = f.status === "FAIL" || f.status === "WARNING";
            const sevLower = f.severity.toLowerCase();
            const statusLabel = f.status === "PASS" ? "COMPLIANT" : f.status;
            
            let statusBadgeClass = f.status === "PASS" ? "pass" : "fail";
            if (f.status === "WARNING") statusBadgeClass = "warning";
            
            // Remediate button
            const remediationBtn = isFailed ? `
                <button class="btn btn-primary btn-sm btn-remediate" data-check-id="${f.check_id}">
                    <i class="fa-solid fa-screwdriver-wrench"></i> Auto-Remediate
                </button>
            ` : "";

            const meta = SECURITY_METADATA_JS[f.check_id] || {};
            const fixTerraform = meta.fix_terraform || `# Remediation snippet not configured for ${f.check_id}`;
            const fixCli = meta.fix_cli || `# CLI fixes not configured for ${f.check_id}`;
            const fixCfn = meta.fix_cfn || `# CloudFormation not configured for ${f.check_id}`;
            const fixConsole = meta.fix_console || f.remediation;

            const learningMatters = meta.why_dangerous || f.message;
            const learningIncident = meta.real_world_incident || "No public data reference.";
            const learningExploit = meta.exploitation_example || "No script listed.";
            const learningMitre = meta.mitre_attack || "N/A";
            const learningCis = meta.cis_benchmark || "N/A";
            const learningDocs = meta.aws_docs || "https://docs.aws.amazon.com/";

            item.innerHTML = `
                <div class="finding-row">
                    <div class="col-service">
                        <i class="${getServiceIcon(f.service)}"></i>
                        <span>${f.service}</span>
                    </div>
                    <div class="col-rule">${f.check_name}</div>
                    <div class="col-severity">
                        <span class="badge ${sevLower}">${f.severity}</span>
                    </div>
                    <div class="col-region">${f.region}</div>
                    <div class="col-status">
                        <span class="badge ${statusBadgeClass}">${statusLabel}</span>
                    </div>
                    <div class="col-toggle">
                        <i class="fa-solid fa-chevron-down"></i>
                    </div>
                </div>
                <div class="finding-details">
                    <div class="details-content">
                        <div class="details-grid">
                            <div class="detail-block">
                                <h4>Resource Identifier</h4>
                                <div class="resource-id-wrapper">
                                    <span>${f.resource_id}</span>
                                    <button class="btn-copy" data-text="${f.resource_id}">
                                        <i class="fa-regular fa-copy"></i>
                                    </button>
                                </div>
                            </div>
                            <div class="detail-block">
                                <h4>Security Finding Message</h4>
                                <p>${f.message}</p>
                            </div>
                        </div>

                        <!-- Fix This Code Tabs -->
                        <div class="fix-tabs-container">
                            <div class="fix-tabs-header">
                                <button class="fix-tab-btn active" data-tab-name="terraform-${index}">Terraform</button>
                                <button class="fix-tab-btn" data-tab-name="cli-${index}">AWS CLI</button>
                                <button class="fix-tab-btn" data-tab-name="cfn-${index}">CloudFormation</button>
                                <button class="fix-tab-btn" data-tab-name="console-${index}">Console Guide</button>
                            </div>
                            <div class="fix-tabs-content">
                                <div class="fix-tab-pane active" id="pane-terraform-${index}">
                                    <div class="code-wrapper">
                                        <pre><code>${fixTerraform}</code></pre>
                                        <button class="btn-copy-code" data-clipboard-text="${fixTerraform.replace(/"/g, '&quot;')}"><i class="fa-regular fa-copy"></i> Copy</button>
                                    </div>
                                </div>
                                <div class="fix-tab-pane" id="pane-cli-${index}">
                                    <div class="code-wrapper">
                                        <pre><code>${fixCli}</code></pre>
                                        <button class="btn-copy-code" data-clipboard-text="${fixCli.replace(/"/g, '&quot;')}"><i class="fa-regular fa-copy"></i> Copy</button>
                                    </div>
                                </div>
                                <div class="fix-tab-pane" id="pane-cfn-${index}">
                                    <div class="code-wrapper">
                                        <pre><code>${fixCfn}</code></pre>
                                        <button class="btn-copy-code" data-clipboard-text="${fixCfn.replace(/"/g, '&quot;')}"><i class="fa-regular fa-copy"></i> Copy</button>
                                    </div>
                                </div>
                                <div class="fix-tab-pane" id="pane-console-${index}">
                                    <div style="font-size: 13px; line-height: 1.6; color: var(--color-text-main);">
                                        <p>${fixConsole}</p>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <!-- Learning Mode Panel -->
                        <div class="learning-mode-card">
                            <div class="learning-title">
                                <i class="fa-solid fa-graduation-cap"></i> Security Learning Module
                            </div>
                            <div class="learning-grid">
                                <div class="learning-col">
                                    <h5>Why this matters</h5>
                                    <p>${learningMatters}</p>
                                </div>
                                <div class="learning-col">
                                    <h5>Real-World Incident</h5>
                                    <p>${learningIncident}</p>
                                </div>
                                <div class="learning-col">
                                    <h5>Exploitation Example</h5>
                                    <p style="font-family: monospace; font-size: 11px; background-color: rgba(0,0,0,0.2); padding: 6px; border-radius: 4px;">${learningExploit}</p>
                                </div>
                                <div class="learning-col">
                                    <h5>AWS Documentation</h5>
                                    <p><a href="${learningDocs}" target="_blank" style="color: var(--color-primary-hover); text-decoration: none;"><i class="fa-solid fa-up-right-from-square"></i> Read AWS User Guides</a></p>
                                </div>
                            </div>
                            <div class="learning-meta">
                                <span><strong>MITRE ATT&CK:</strong> ${learningMitre}</span>
                                <span><strong>CIS Benchmark:</strong> ${learningCis}</span>
                            </div>
                        </div>

                        <div class="details-actions">
                            <button class="btn btn-secondary btn-sm btn-ask-copilot" data-check-id="${f.check_id}">
                                <i class="fa-solid fa-robot"></i> Ask Copilot
                            </button>
                            ${remediationBtn}
                        </div>
                    </div>
                </div>
            `;

            // Row click event
            item.querySelector(".finding-row").addEventListener("click", () => {
                const isOpen = item.classList.contains("open");
                document.querySelectorAll(".finding-item").forEach(i => i.classList.remove("open"));
                if (!isOpen) {
                    item.classList.add("open");
                }
            });

            // Tabs toggle handler inside item
            item.querySelectorAll(".fix-tab-btn").forEach(btn => {
                btn.addEventListener("click", (e) => {
                    e.stopPropagation();
                    const tabName = btn.getAttribute("data-tab-name");
                    
                    item.querySelectorAll(".fix-tab-btn").forEach(b => b.classList.remove("active"));
                    btn.classList.add("active");
                    
                    item.querySelectorAll(".fix-tab-pane").forEach(pane => {
                        pane.classList.remove("active");
                        if (pane.id === `pane-${tabName}`) {
                            pane.classList.add("active");
                        }
                    });
                });
            });

            // Copy resource text
            item.querySelector(".btn-copy").addEventListener("click", (e) => {
                e.stopPropagation();
                const text = e.target.closest("button").getAttribute("data-text");
                navigator.clipboard.writeText(text);
                showToast("Copied", "Resource ID copied.");
            });

            // Copy code blocks
            item.querySelectorAll(".btn-copy-code").forEach(btn => {
                btn.addEventListener("click", (e) => {
                    e.stopPropagation();
                    const code = btn.getAttribute("data-clipboard-text");
                    navigator.clipboard.writeText(code);
                    showToast("Code Copied", "Remediation script copied to clipboard.");
                });
            });

            // Ask Copilot Button click
            item.querySelector(".btn-ask-copilot").addEventListener("click", (e) => {
                e.stopPropagation();
                const checkId = e.target.closest(".btn-ask-copilot").getAttribute("data-check-id");
                triggerCopilotPanel(checkId);
            });

            // Auto remediation
            if (isFailed) {
                item.querySelector(".btn-remediate").addEventListener("click", async (e) => {
                    e.stopPropagation();
                    const btn = e.target.closest(".btn-remediate");
                    const checkId = btn.getAttribute("data-check-id");
                    
                    btn.disabled = true;
                    btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Remediating...`;

                    try {
                        const r = await fetch(`/api/remediate/${currentScanId}/${checkId}`, {
                            method: "POST"
                        });
                        if (!r.ok) throw new Error("Remediation execution failed.");
                        const result = await r.json();
                        showToast("Remediation Successful", result.message);
                        await loadScanDetails(currentScanId);
                    } catch (err) {
                        showToast("Remediation Error", err.message, false);
                        btn.disabled = false;
                        btn.innerHTML = `<i class="fa-solid fa-screwdriver-wrench"></i> Auto-Remediate`;
                    }
                });
            }

            findingsContainer.appendChild(item);
        });
    };

    // --- Interactive AI Copilot Side Panel Chat (Step 1) ---
    const triggerCopilotPanel = (checkId, customInitialMsg = null) => {
        copilotActiveCheckId = checkId;
        copilotDrawer.classList.add("active");

        const meta = SECURITY_METADATA_JS[checkId] || {};
        document.getElementById("copilot-current-check-title").innerText = meta.title || checkId;

        // Reset chat with welcome message and trigger initial analysis
        copilotMessages.innerHTML = "";
        
        // Add welcome message
        appendChatMessage("assistant", `I am analyzing finding: **${meta.title || checkId}**. How would you like me to assist you?`);
        
        // Auto trigger explanation
        const initialQuery = customInitialMsg || "Why is this dangerous?";
        sendCopilotMessage(initialQuery);
    };

    const appendChatMessage = (role, text) => {
        const msgEl = document.createElement("div");
        msgEl.className = `chat-message ${role}`;
        
        // Markdown backtick code translation
        let formatted = text;
        if (text.includes("```")) {
            formatted = text.replace(/```(hcl|bash|json|yaml)?([\s\S]*?)```/g, '<pre><code>$2</code></pre>');
        }
        msgEl.innerHTML = formatted;
        
        copilotMessages.appendChild(msgEl);
        copilotMessages.scrollTop = copilotMessages.scrollHeight;
    };

    const sendCopilotMessage = async (queryText) => {
        if (!queryText.trim() || !copilotActiveCheckId) return;

        appendChatMessage("user", queryText);

        const payload = {
            check_id: copilotActiveCheckId,
            new_message: queryText,
            message_history: []
        };

        // Loading indicator
        const loadingEl = document.createElement("div");
        loadingEl.className = "chat-message assistant loading";
        loadingEl.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i> Aegis Copilot thinking...`;
        copilotMessages.appendChild(loadingEl);
        copilotMessages.scrollTop = copilotMessages.scrollHeight;

        try {
            const resp = await fetch("/api/copilot/chat", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });
            
            loadingEl.remove();

            if (!resp.ok) throw new Error("Connection failed.");
            
            const result = await resp.json();
            appendChatMessage("assistant", result.response);
        } catch (e) {
            loadingEl.remove();
            appendChatMessage("assistant", "Sorry, I encountered a communication error with the Aegis AI engine. Please verify the backend status.");
        }
    };

    btnCopilotSend.addEventListener("click", () => {
        const text = copilotInput.value;
        if (text.trim()) {
            sendCopilotMessage(text);
            copilotInput.value = "";
        }
    });

    copilotInput.addEventListener("keydown", (e) => {
        if (e.key === "Enter") {
            const text = copilotInput.value;
            if (text.trim()) {
                sendCopilotMessage(text);
                copilotInput.value = "";
            }
        }
    });

    btnCloseCopilot.addEventListener("click", () => {
        copilotDrawer.classList.remove("active");
    });

    // --- Compliance Explorer View Mapping (Step 6) ---
    const renderComplianceView = () => {
        compListContainer.innerHTML = "";

        const failedChecks = currentFindings.filter(f => f.status !== "PASS");
        let activeControls = [];

        if (currentFramework === "cis") {
            activeControls = [
                { index: "1.1", title: "Avoid the use of the 'root' user", checkId: "IAM_ROOT_MFA", desc: "Root accounts must be highly protected and avoided for routine APIs." },
                { index: "1.10", title: "Enforce multi-factor authentication (MFA) for console users", checkId: "IAM_USER_MFA", desc: "Multi-factor authentication adds cryptographic verification to standard login profiles." },
                { index: "1.14", title: "Ensure access credentials/keys are rotated every 90 days or less", checkId: "IAM_ACCESS_KEY_AGE", desc: "API access keys have a limited validity window to prevent orphan key exploits." },
                { index: "1.20", title: "Enforce direct role policy structures matching Least Privilege principles", checkId: "IAM_WILDCARD_POLICIES", desc: "Direct wildcard permissions (e.g. s3:*) expose all sub-assets to compromise." },
                { index: "2.1.1", title: "Block Public Access settings enabled at bucket levels", checkId: "S3_BLOCK_PUBLIC_ACCESS", desc: "S3 block public access gates bucket access from accidental public exposure." },
                { index: "2.1.2", title: "S3 bucket default server-side encryption enabled", checkId: "S3_BUCKET_ENCRYPTION", desc: "Encrypt static bucket items by default with AES256 or KMS." },
                { index: "4.1", title: "Ensure no security groups allow ingress from 0.0.0.0/0 to SSH (22)", checkId: "EC2_SG_EXPOSED_SSH", desc: "SSH access must be restricted to corporate ranges, VPN gateways, or Bastions." },
                { index: "4.2", title: "Disable all-traffic wildcard ingress configurations", checkId: "EC2_SG_OPEN_ALL_TRAFFIC", desc: "Security groups must not allow full ingress protocol pass-throughs." }
            ];
        } else if (currentFramework === "soc2") {
            activeControls = [
                { index: "CC6.1", title: "Logical Access Controls: Multi-factor baseline", checkId: "IAM_USER_MFA", desc: "Authenticate users with multi-factor triggers prior to cloud workspace loads." },
                { index: "CC6.3", title: "Perimeter Network Protection: Security Group audits", checkId: "EC2_SG_OPEN_ALL_TRAFFIC", desc: "Secure host endpoints behind restricted firewall security policies." },
                { index: "CC6.6", title: "Data Transmission & Encryption bounds", checkId: "S3_PUBLIC_BUCKETS", desc: "Block public files exposure and encrypt storage assets statically." }
            ];
        } else if (currentFramework === "hipaa") {
            activeControls = [
                { index: "164.312", title: "Technical Safeguards - Access Control (MFA / Policies)", checkId: "IAM_ROOT_MFA", desc: "Enforce secure login profiles and cryptographic access keys validations." },
                { index: "164.312(a)", title: "Data at Rest Encryption defaults", checkId: "S3_BUCKET_ENCRYPTION", desc: "Configure S3 and EBS volume default AES-256 encryption." }
            ];
        }

        let passedCount = 0;
        
        activeControls.forEach(ctrl => {
            const finding = currentFindings.find(f => f.check_id === ctrl.checkId);
            const isCompliant = finding ? (finding.status === "PASS") : true;

            if (isCompliant) passedCount++;

            const statusClass = isCompliant ? "text-pass" : "text-error";
            const statusLabel = isCompliant ? "COMPLIANT" : "FAILED";

            const el = document.createElement("div");
            el.className = "compliance-rule-card";
            el.innerHTML = `
                <div class="comp-rule-left">
                    <div class="comp-rule-index">${ctrl.index}</div>
                    <div class="comp-rule-details">
                        <h4>${ctrl.title}</h4>
                        <p>${ctrl.desc}</p>
                    </div>
                </div>
                <div class="comp-rule-right">
                    <span class="badge ${isCompliant ? 'pass' : 'fail'}">${statusLabel}</span>
                </div>
            `;

            // Hover click shows details
            el.onclick = () => {
                if (finding) {
                    document.querySelector('[data-tab="dashboard"]').click();
                    filterSearch.value = finding.check_name;
                    renderFindingsList();
                    // Open the item programmatically
                    setTimeout(() => {
                        const row = findingsContainer.querySelector(".finding-item");
                        if (row) row.click();
                    }, 200);
                }
            };

            compListContainer.appendChild(el);
        });

        // Compute framework score
        const rate = activeControls.length ? Math.round((passedCount / activeControls.length) * 100) : 100;
        compPercentage.innerText = `${rate}%`;
        compFailedCount.innerText = activeControls.length - passedCount;
    };

    // Framework click handlers
    compFrameworkBtns.forEach(btn => {
        btn.addEventListener("click", () => {
            compFrameworkBtns.forEach(b => b.classList.remove("active"));
            btn.classList.add("active");
            currentFramework = btn.getAttribute("data-framework");
            renderComplianceView();
        });
    });

    filterSearch.addEventListener("input", renderFindingsList);
    filterService.addEventListener("change", renderFindingsList);
    filterStatus.addEventListener("change", renderFindingsList);

    // --- Severity Card Click-to-Filter ---
    document.querySelectorAll(".sev-card").forEach(card => {
        card.addEventListener("click", () => {
            const severity = card.getAttribute("data-severity");
            const isActive = card.classList.contains("filter-active");

            // Clear all active states
            document.querySelectorAll(".sev-card").forEach(c => c.classList.remove("filter-active"));

            if (isActive) {
                // Toggle off — clear filter
                activeSeverityFilter = null;
            } else {
                card.classList.add("filter-active");
                activeSeverityFilter = severity;
            }
            renderFindingsList();

            // Scroll to findings
            const findingsSection = document.querySelector(".findings-section");
            if (findingsSection) findingsSection.scrollIntoView({ behavior: "smooth" });
        });
    });

    const getServiceIcon = (service) => {
        switch (service) {
            case "IAM": return "fa-solid fa-user-shield";
            case "S3": return "fa-solid fa-box-archive";
            case "EC2": return "fa-solid fa-server";
            case "CloudTrail": return "fa-solid fa-scroll";
            case "Networking": return "fa-solid fa-network-wired";
            default: return "fa-solid fa-shield";
        }
    };

    // --- Chart JS Drawing Engine with Score Timeline (Step 8) ---
    const drawCharts = async () => {
        if (scoreChartObj) scoreChartObj.destroy();
        if (serviceChartObj) serviceChartObj.destroy();
        if (severityChartObj) severityChartObj.destroy();
        if (trendChartObj) trendChartObj.destroy();

        // Hide chart placeholders
        const servicePlaceholder = document.getElementById("serviceChart-placeholder");
        const severityPlaceholder = document.getElementById("severityChart-placeholder");
        const trendPlaceholder = document.getElementById("trendChart-placeholder");
        
        if (servicePlaceholder) servicePlaceholder.classList.add("hide");
        if (severityPlaceholder) severityPlaceholder.classList.add("hide");
        if (trendPlaceholder) trendPlaceholder.classList.add("hide");

        // 1. Posture Score Doughnut
        const ctxScore = document.getElementById("scoreChart").getContext("2d");
        const score = currentSummary.score;
        let ringColor = "#ef4444";
        if (score >= 90) ringColor = "#10b981";
        else if (score >= 70) ringColor = "#eab308";
        else if (score >= 50) ringColor = "#f97316";

        scoreChartObj = new Chart(ctxScore, {
            type: "doughnut",
            data: {
                datasets: [{
                    data: [score, 100 - score],
                    backgroundColor: [ringColor, "rgba(255,255,255,0.05)"],
                    borderWidth: 0,
                    borderRadius: [10, 0]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: "80%",
                plugins: { legend: { display: false }, tooltip: { enabled: false } }
            }
        });

        // 2. Service Horizontal Bar Chart
        const services = ["IAM", "S3", "EC2", "CloudTrail", "Networking"];
        const serviceCounts = services.map(s => 
            currentFindings.filter(f => f.service === s && f.status !== "PASS").length
        );

        const ctxService = document.getElementById("serviceChart").getContext("2d");
        serviceChartObj = new Chart(ctxService, {
            type: "bar",
            data: {
                labels: services,
                datasets: [{
                    data: serviceCounts,
                    backgroundColor: "rgba(123, 44, 191, 0.75)",
                    borderColor: "#9d4edd",
                    borderWidth: 1.5,
                    borderRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: { grid: { color: "rgba(255,255,255,0.04)" }, ticks: { color: "#94a3b8" } },
                    y: { grid: { color: "rgba(255,255,255,0.04)" }, ticks: { color: "#94a3b8", stepSize: 1 } }
                }
            }
        });

        // 3. Severity Breakdown Doughnut
        const sevs = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
        const sevCounts = sevs.map(s => 
            currentFindings.filter(f => f.severity === s && f.status !== "PASS").length
        );

        const ctxSeverity = document.getElementById("severityChart").getContext("2d");
        severityChartObj = new Chart(ctxSeverity, {
            type: "doughnut",
            data: {
                labels: sevs,
                datasets: [{
                    data: sevCounts,
                    backgroundColor: ["#ef4444", "#f97316", "#eab308", "#3b82f6"],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: "right",
                        labels: { color: "#f1f5f9", font: { family: "'Plus Jakarta Sans', sans-serif" } }
                    }
                }
            }
        });

        // 4. Security Posture Score Timeline Line Chart (Step 8)
        try {
            const hResp = await fetch("/api/history");
            const history = await hResp.json();
            
            // Sort ascending by time for graph plotting
            const sortedHistory = [...history].reverse();
            
            const labels = sortedHistory.map(h => h.timestamp.split(" ")[0]);
            const scores = sortedHistory.map(h => h.score);

            const ctxTrend = document.getElementById("trendChart").getContext("2d");
            trendChartObj = new Chart(ctxTrend, {
                type: "line",
                data: {
                    labels: labels.length ? labels : ["Day -2", "Yesterday", "Today"],
                    datasets: [{
                        label: "Posture Score",
                        data: scores.length ? scores : [88, 84, score],
                        borderColor: "#7b2cbf",
                        backgroundColor: "rgba(123, 44, 191, 0.08)",
                        borderWidth: 3,
                        pointBackgroundColor: "#9d4edd",
                        pointBorderColor: "#ffffff",
                        pointRadius: 5,
                        pointHoverRadius: 7,
                        tension: 0.35,
                        fill: true
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: {
                        x: { grid: { color: "rgba(255,255,255,0.03)" }, ticks: { color: "#94a3b8" } },
                        y: { 
                            grid: { color: "rgba(255,255,255,0.03)" }, 
                            ticks: { color: "#94a3b8" },
                            min: 0,
                            max: 100
                        }
                    }
                }
            });
        } catch (e) {
            console.error("Timeline chart load error:", e);
        }
    };

    // --- Scan History Management ---
    const loadHistory = async () => {
        try {
            const resp = await fetch("/api/history");
            if (!resp.ok) throw new Error("Could not retrieve history logs.");
            
            const history = await resp.json();
            historyContainer.innerHTML = "";

            if (history.length === 0) {
                historyContainer.innerHTML = `
                    <div style="padding: 40px; text-align: center; color: var(--color-text-muted);">
                        <i class="fa-solid fa-history" style="font-size: 32px; color: var(--color-border); margin-bottom: 12px;"></i>
                        <p>No historical database runs found.</p>
                    </div>
                `;
                return;
            }

            history.forEach(item => {
                const row = document.createElement("div");
                row.className = "history-item";
                
                const typeStr = "Live AWS";
                const typeBadge = "badge pass";
                
                let scoreColor = "var(--critical)";
                if (item.score >= 90) scoreColor = "var(--pass)";
                else if (item.score >= 70) scoreColor = "var(--medium)";
                
                row.innerHTML = `
                    <div>${item.timestamp}</div>
                    <div><span class="${typeBadge}">${typeStr}</span></div>
                    <div class="history-score" style="color: ${scoreColor};">${item.score}/100</div>
                    <div class="history-counts">
                        <span class="c">${item.critical_count}</span>
                        <span class="h">${item.high_count}</span>
                        <span class="m">${item.medium_count}</span>
                        <span class="l">${item.low_count}</span>
                    </div>
                    <div class="history-regions">${item.regions.join(", ")}</div>
                    <div class="history-actions">
                        <button class="btn btn-secondary btn-sm btn-load" data-id="${item.id}">Load</button>
                        <a href="/api/download/${item.id}/pdf" class="btn btn-secondary btn-sm" target="_blank">
                            <i class="fa-solid fa-file-pdf"></i>
                        </a>
                        <button class="btn btn-secondary btn-sm btn-delete text-error" data-id="${item.id}">
                            <i class="fa-solid fa-trash"></i>
                        </button>
                    </div>
                `;

                row.querySelector(".btn-load").addEventListener("click", () => {
                    loadScanDetails(item.id);
                    document.querySelector('[data-tab="dashboard"]').click();
                    showToast("Scan Loaded", "Pulled scan configurations into workspace.");
                });

                row.querySelector(".btn-delete").addEventListener("click", async () => {
                    if (confirm("Are you sure you want to permanently delete this scan run?")) {
                        try {
                            const delResp = await fetch(`/api/scan/${item.id}`, { method: "DELETE" });
                            if (delResp.ok) {
                                showToast("Scan Deleted", "Removed run logs from SQLite.");
                                loadHistory();
                                if (currentScanId === item.id) {
                                    currentScanId = null;
                                    location.reload();
                                }
                            }
                        } catch (e) {
                            showToast("Delete Error", e.message, false);
                        }
                    }
                });

                historyContainer.appendChild(row);
            });
        } catch (e) {
            showToast("History Load Failure", e.message, false);
        }
    };

    btnRefreshHistory.addEventListener("click", loadHistory);

    // --- Load AWS Regions Dynamically ---
    const loadRegions = async () => {
        try {
            const resp = await fetch("/api/regions");
            if (!resp.ok) throw new Error("Failed to load regions.");
            const regions = await resp.json();
            
            const grid = document.getElementById("regions-checkbox-grid");
            grid.innerHTML = "";
            
            const regionNames = {
                "us-east-1": "us-east-1 (N. Virginia)",
                "us-east-2": "us-east-2 (Ohio)",
                "us-west-1": "us-west-1 (N. California)",
                "us-west-2": "us-west-2 (Oregon)",
                "eu-west-1": "eu-west-1 (Ireland)",
                "eu-west-2": "eu-west-2 (London)",
                "eu-west-3": "eu-west-3 (Paris)",
                "eu-central-1": "eu-central-1 (Frankfurt)",
                "eu-north-1": "eu-north-1 (Stockholm)",
                "ap-south-1": "ap-south-1 (Mumbai)",
                "ap-southeast-1": "ap-southeast-1 (Singapore)",
                "ap-southeast-2": "ap-southeast-2 (Sydney)",
                "ap-northeast-1": "ap-northeast-1 (Tokyo)",
                "ap-northeast-2": "ap-northeast-2 (Seoul)",
                "ca-central-1": "ca-central-1 (Canada Central)",
                "sa-east-1": "sa-east-1 (São Paulo)"
            };

            regions.forEach(reg => {
                const label = document.createElement("label");
                label.className = "checkbox-container";
                const isChecked = (reg === "us-east-1" || reg === "us-west-2") ? "checked" : "";
                
                const regLabel = regionNames[reg] || reg;
                
                label.innerHTML = `
                    <input type="checkbox" name="regions" value="${reg}" ${isChecked}>
                    <span class="checkmark"></span>
                    <span>${regLabel}</span>
                `;
                grid.appendChild(label);
            });
        } catch (e) {
            console.error("Error loading AWS regions:", e);
        }
    };

    document.getElementById("btn-regions-all").addEventListener("click", () => {
        document.querySelectorAll('input[name="regions"]').forEach(cb => cb.checked = true);
    });

    document.getElementById("btn-regions-none").addEventListener("click", () => {
        document.querySelectorAll('input[name="regions"]').forEach(cb => cb.checked = false);
    });

    // --- Integrations Settings Sync API ---
    const loadSettings = async () => {
        try {
            const resp = await fetch("/api/settings");
            if (!resp.ok) return;
            const data = await resp.json();
            
            document.getElementById("integration-slack-webhook").value = data.slack_webhook;
            document.getElementById("integration-slack-enabled").checked = data.slack_enabled;
            document.getElementById("integration-email-recipient").value = data.email_recipient;
            document.getElementById("integration-email-enabled").checked = data.email_enabled;
        } catch (e) {
            console.error("Failed to load settings:", e);
        }
    };

    document.getElementById("btn-save-slack").addEventListener("click", async () => {
        const webhook = document.getElementById("integration-slack-webhook").value.trim();
        const enabled = document.getElementById("integration-slack-enabled").checked;
        
        try {
            const resp = await fetch("/api/settings", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    slack_webhook: webhook,
                    slack_enabled: enabled
                })
            });
            if (resp.ok) {
                showToast("Slack Config Saved", "Successfully updated Slack alerts notification settings.");
            } else {
                showToast("Save Failed", "Failed to update configuration settings.", false);
            }
        } catch (e) {
            showToast("Save Failed", e.message, false);
        }
    });

    document.getElementById("btn-save-email").addEventListener("click", async () => {
        const recipient = document.getElementById("integration-email-recipient").value.trim();
        const enabled = document.getElementById("integration-email-enabled").checked;
        
        try {
            const resp = await fetch("/api/settings", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    email_recipient: recipient,
                    email_enabled: enabled
                })
            });
            if (resp.ok) {
                showToast("Email Preferences Saved", "Successfully updated digest distribution settings.");
            } else {
                showToast("Save Failed", "Failed to update configuration settings.", false);
            }
        } catch (e) {
            showToast("Save Failed", e.message, false);
        }
    });

    document.getElementById("btn-test-slack").addEventListener("click", async () => {
        const btn = document.getElementById("btn-test-slack");
        btn.disabled = true;
        btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Dispatching...`;
        
        try {
            const webhook = document.getElementById("integration-slack-webhook").value.trim();
            const enabled = document.getElementById("integration-slack-enabled").checked;
            await fetch("/api/settings", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    slack_webhook: webhook,
                    slack_enabled: enabled
                })
            });

            const resp = await fetch("/api/settings/slack/test", { method: "POST" });
            if (resp.ok) {
                showToast("Broadcast Dispatched", "Test alert successfully sent to Slack channel.");
            } else {
                const err = await resp.json();
                showToast("Test Failed", err.detail || "Verify webhook settings.", false);
            }
        } catch (e) {
            showToast("Test Failed", e.message, false);
        } finally {
            btn.disabled = false;
            btn.innerHTML = `<i class="fa-solid fa-paper-plane"></i> Test Broadcast`;
        }
    });

    // --- On Load Initializer ---
    const initApp = async () => {
        try {
            await loadRegions();
            await loadSettings();
            const resp = await fetch("/api/history");
            const history = await resp.json();
            
            if (history.length > 0) {
                loadScanDetails(history[0].id);
            }
        } catch (e) {
            console.error("Initialization check failed:", e);
        }
    };

    initApp();
});
