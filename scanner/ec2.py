import logging
from botocore.exceptions import ClientError
from scanner.base import BaseScanner

logger = logging.getLogger("cspm.scanner.ec2")

class EC2Scanner(BaseScanner):
    """Scanner for Amazon EC2 configurations and security groups."""
    
    def run_checks(self) -> list:
        findings = []
        if not self.session:
            logger.warning("No active session provided to EC2Scanner.")
            return findings

        # Run checks for each specified region
        regions_to_scan = self.regions if self.regions else ["us-east-1"]
        
        for region in regions_to_scan:
            try:
                ec2_client = self.session.client("ec2", region_name=region)
            except ClientError as e:
                logger.error(f"Failed to create EC2 client in {region}: {e}")
                continue

            findings.extend(self._check_public_instances(ec2_client, region))
            findings.extend(self._check_security_groups(ec2_client, region))
            findings.extend(self._check_ebs_volumes(ec2_client, region))

        return findings

    def _check_public_instances(self, client, region: str) -> list:
        findings = []
        try:
            paginator = client.get_paginator("describe_instances")
            for page in paginator.paginate(Filters=[{"Name": "instance-state-name", "Values": ["running", "stopped"]}]):
                for reservation in page.get("Reservations", []):
                    for instance in reservation.get("Instances", []):
                        instance_id = instance["InstanceId"]
                        public_ip = instance.get("PublicIpAddress")
                        
                        # Find name tag
                        name = instance_id
                        for tag in instance.get("Tags", []):
                            if tag["Key"] == "Name":
                                name = f"{instance_id} ({tag['Value']})"
                                break
                        
                        if public_ip:
                            findings.append(self.create_finding(
                                "EC2_PUBLIC_INSTANCES", "Public Instances", "HIGH", "FAIL",
                                name, region,
                                f"Instance has a public IP address ({public_ip}) and is reachable from the internet.",
                                "Move instance to a private subnet, configure NAT Gateways, and associate only with private IPs."
                            ))
                        else:
                            findings.append(self.create_finding(
                                "EC2_PUBLIC_INSTANCES", "Public Instances", "HIGH", "PASS",
                                name, region,
                                "Instance does not have a public IP address.",
                                "None required."
                            ))
        except ClientError as e:
            logger.warning(f"Error describing EC2 instances in {region}: {e}")
            findings.append(self.create_finding(
                "EC2_DESCRIBE_INSTANCES_ERROR", "Read EC2 Instances Status", "MEDIUM", "WARNING",
                "ec2-service", region,
                f"Error retrieving EC2 instances: {e}",
                "Add ec2:DescribeInstances permission to the scanner identity."
            ))
        return findings

    def _check_security_groups(self, client, region: str) -> list:
        findings = []
        try:
            sgs = client.describe_security_groups()
            for sg in sgs.get("SecurityGroups", []):
                sg_id = sg["GroupId"]
                sg_name = sg["GroupName"]
                sg_label = f"{sg_id} ({sg_name})"
                
                # Check rules
                exposes_ssh = False
                exposes_rdp = False
                exposes_all = False
                
                for rule in sg.get("IpPermissions", []):
                    from_port = rule.get("FromPort")
                    to_port = rule.get("ToPort")
                    ip_protocol = rule.get("IpProtocol")
                    
                    # Check CIDRs for 0.0.0.0/0 or ::/0
                    is_wildcard_cidr = False
                    for ip_range in rule.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            is_wildcard_cidr = True
                            break
                    for ipv6_range in rule.get("Ipv6Ranges", []):
                        if ipv6_range.get("CidrIpv6") == "::/0":
                            is_wildcard_cidr = True
                            break
                            
                    if is_wildcard_cidr:
                        # Check port range
                        # Protocol -1 means all traffic
                        if ip_protocol == "-1":
                            exposes_all = True
                        elif from_port is not None and to_port is not None:
                            # Port ranges can encompass SSH (22) or RDP (3389)
                            if from_port <= 22 <= to_port:
                                exposes_ssh = True
                            if from_port <= 3389 <= to_port:
                                exposes_rdp = True

                # Exposing SSH finding
                if exposes_ssh:
                    findings.append(self.create_finding(
                        "EC2_SG_EXPOSED_SSH", "Security Groups Exposing SSH (22)", "HIGH", "FAIL",
                        sg_label, region,
                        f"Security group '{sg_name}' allows SSH inbound access from public internet.",
                        f"Restrict inbound rules on security group '{sg_id}' to allow SSH access only from authorized source IPs."
                    ))
                else:
                    findings.append(self.create_finding(
                        "EC2_SG_EXPOSED_SSH", "Security Groups Exposing SSH (22)", "HIGH", "PASS",
                        sg_label, region,
                        f"Security group '{sg_name}' restricts public SSH access.",
                        "None required."
                    ))

                # Exposing RDP finding
                if exposes_rdp:
                    findings.append(self.create_finding(
                        "EC2_SG_EXPOSED_RDP", "Security Groups Exposing RDP (3389)", "HIGH", "FAIL",
                        sg_label, region,
                        f"Security group '{sg_name}' allows RDP inbound access from public internet.",
                        f"Restrict inbound rules on security group '{sg_id}' to allow RDP access only from authorized source IPs."
                    ))
                else:
                    findings.append(self.create_finding(
                        "EC2_SG_EXPOSED_RDP", "Security Groups Exposing RDP (3389)", "HIGH", "PASS",
                        sg_label, region,
                        f"Security group '{sg_name}' restricts public RDP access.",
                        "None required."
                    ))

                # Open "All Traffic" rules finding
                if exposes_all:
                    findings.append(self.create_finding(
                        "EC2_SG_OPEN_ALL_TRAFFIC", "Open 'All Traffic' Rules", "CRITICAL", "FAIL",
                        sg_label, region,
                        f"Security group '{sg_name}' allows ALL inbound traffic (all protocols/ports) from public internet.",
                        f"Revise security group rules on '{sg_id}' to close all-traffic ports and open only essential services."
                    ))
                else:
                    findings.append(self.create_finding(
                        "EC2_SG_OPEN_ALL_TRAFFIC", "Open 'All Traffic' Rules", "CRITICAL", "PASS",
                        sg_label, region,
                        f"Security group '{sg_name}' does not allow wide open all-traffic connections.",
                        "None required."
                    ))

        except ClientError as e:
            logger.warning(f"Error describing security groups in {region}: {e}")
            
        return findings

    def _check_ebs_volumes(self, client, region: str) -> list:
        findings = []
        try:
            volumes_resp = client.describe_volumes()
            for volume in volumes_resp.get("Volumes", []):
                volume_id = volume["VolumeId"]
                encrypted = volume.get("Encrypted", False)
                
                if not encrypted:
                    findings.append(self.create_finding(
                        "EC2_UNENCRYPTED_EBS", "Unencrypted EBS Volumes", "MEDIUM", "FAIL",
                        volume_id, region,
                        f"EBS volume '{volume_id}' is unencrypted.",
                        f"Enable encryption on volume '{volume_id}' (enable default account encryption or encrypt snapshots before mounting)."
                    ))
                else:
                    findings.append(self.create_finding(
                        "EC2_UNENCRYPTED_EBS", "Unencrypted EBS Volumes", "MEDIUM", "PASS",
                        volume_id, region,
                        f"EBS volume '{volume_id}' is encrypted.",
                        "None required."
                    ))
        except ClientError as e:
            logger.warning(f"Error describing EBS volumes in {region}: {e}")
            
        return findings
