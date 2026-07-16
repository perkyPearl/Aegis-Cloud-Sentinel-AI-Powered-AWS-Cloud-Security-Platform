import logging
from typing import Any, Dict, List
import boto3

logger = logging.getLogger("cspm.scanner")

class BaseScanner:
    """Base class for all AWS service scanners."""
    
    def __init__(self, session: boto3.Session, regions: List[str]):
        self.session = session
        self.regions = regions
        self.service = self.__class__.__name__.replace("Scanner", "")
        
    def run_checks(self) -> List[Dict[str, Any]]:
        """Run all security checks for the service and return findings."""
        raise NotImplementedError("Scanners must implement run_checks()")
        
    def create_finding(
        self,
        check_id: str,
        check_name: str,
        severity: str,
        status: str,
        resource_id: str,
        region: str,
        message: str,
        remediation: str
    ) -> Dict[str, Any]:
        """Utility to create a standardized finding dictionary."""
        return {
            "service": self.service,
            "check_id": check_id,
            "check_name": check_name,
            "severity": severity,
            "status": status,
            "resource_id": resource_id,
            "region": region,
            "message": message,
            "remediation": remediation
        }
