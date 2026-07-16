import logging
from botocore.exceptions import ClientError
from scanner.base import BaseScanner

logger = logging.getLogger("cspm.scanner.networking")

class NetworkingScanner(BaseScanner):
    """Scanner for AWS VPC and networking resources."""
    
    def run_checks(self) -> list:
        findings = []
        if not self.session:
            logger.warning("No active session provided to NetworkingScanner.")
            return findings

        regions_to_scan = self.regions if self.regions else ["us-east-1"]
        
        for region in regions_to_scan:
            try:
                ec2_client = self.session.client("ec2", region_name=region)
            except ClientError as e:
                logger.error(f"Failed to create EC2/Networking client in {region}: {e}")
                continue

            findings.extend(self._check_default_vpc(ec2_client, region))
            findings.extend(self._check_default_security_group_rules(ec2_client, region))
            findings.extend(self._check_internet_facing_rules(ec2_client, region))

        return findings

    def _check_default_vpc(self, client, region: str) -> list:
        findings = []
        try:
            vpcs = client.describe_vpcs()
            for vpc in vpcs.get("Vpcs", []):
                vpc_id = vpc["VpcId"]
                is_default = vpc.get("IsDefault", False)
                
                if is_default:
                    findings.append(self.create_finding(
                        "NET_DEFAULT_VPC", "Default VPC in Use", "LOW", "WARNING",
                        vpc_id, region,
                        f"Default VPC '{vpc_id}' is active in region {region}.",
                        "Avoid using the default VPC for production workloads. Create a custom VPC with isolated subnets."
                    ))
                else:
                    findings.append(self.create_finding(
                        "NET_DEFAULT_VPC", "Default VPC in Use", "LOW", "PASS",
                        vpc_id, region,
                        f"VPC '{vpc_id}' is a custom-configured VPC.",
                        "None required."
                    ))
        except ClientError as e:
            logger.warning(f"Error describing VPCs in {region}: {e}")
        return findings

    def _check_default_security_group_rules(self, client, region: str) -> list:
        findings = []
        try:
            sgs = client.describe_security_groups(Filters=[{"Name": "group-name", "Values": ["default"]}])
            for sg in sgs.get("SecurityGroups", []):
                sg_id = sg["GroupId"]
                vpc_id = sg["VpcId"]
                
                # Default security group should have NO inbound rules and NO outbound rules
                inbound_rules = sg.get("IpPermissions", [])
                outbound_rules = sg.get("IpPermissionsEgress", [])
                
                if inbound_rules or outbound_rules:
                    findings.append(self.create_finding(
                        "NET_DEFAULT_SG_RULES", "Default Security Groups Restricted", "HIGH", "FAIL",
                        f"{sg_id} (VPC: {vpc_id})", region,
                        f"Default security group '{sg_id}' allows active inbound/outbound rules.",
                        f"Remove all rules from default security group '{sg_id}'. Create specific security groups for your resources."
                    ))
                else:
                    findings.append(self.create_finding(
                        "NET_DEFAULT_SG_RULES", "Default Security Groups Restricted", "HIGH", "PASS",
                        f"{sg_id} (VPC: {vpc_id})", region,
                        f"Default security group '{sg_id}' has no open rules.",
                        "None required."
                    ))
        except ClientError as e:
            logger.warning(f"Error describing default security groups in {region}: {e}")
        return findings

    def _check_internet_facing_rules(self, client, region: str) -> list:
        findings = []
        try:
            sgs = client.describe_security_groups()
            for sg in sgs.get("SecurityGroups", []):
                sg_id = sg["GroupId"]
                sg_name = sg["GroupName"]
                
                # Skip the default security group rule checks here, focus on custom ones
                if sg_name == "default":
                    continue
                    
                open_rules_count = 0
                for rule in sg.get("IpPermissions", []):
                    # Check if port is exposed to the internet (0.0.0.0/0 or ::/0)
                    is_public = False
                    for ip in rule.get("IpRanges", []):
                        if ip.get("CidrIp") == "0.0.0.0/0":
                            is_public = True
                            break
                    for ipv6 in rule.get("Ipv6Ranges", []):
                        if ipv6.get("CidrIpv6") == "::/0":
                            is_public = True
                            break
                            
                    if is_public:
                        from_port = rule.get("FromPort")
                        to_port = rule.get("ToPort")
                        # Web traffic (80/443) is common. Other ports are higher risk.
                        if from_port is not None:
                            if from_port not in [80, 443]:
                                open_rules_count += 1
                                
                if open_rules_count > 0:
                    findings.append(self.create_finding(
                        "NET_OPEN_CIDR", "Open CIDR Ranges", "MEDIUM", "FAIL",
                        f"{sg_id} ({sg_name})", region,
                        f"Security group allows public internet access to custom/non-web ports.",
                        f"Modify rules on '{sg_id}' to restrict custom ports to specific source CIDR blocks."
                    ))
                else:
                    findings.append(self.create_finding(
                        "NET_OPEN_CIDR", "Open CIDR Ranges", "MEDIUM", "PASS",
                        f"{sg_id} ({sg_name})", region,
                        f"Security group '{sg_name}' restricts public access to non-web ports.",
                        "None required."
                    ))
        except ClientError as e:
            logger.warning(f"Error describing security groups for networking in {region}: {e}")
        return findings
