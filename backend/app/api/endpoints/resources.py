# File: backend/app/api/endpoints/resources.py

from fastapi import APIRouter, HTTPException, status, Query
from typing import Optional, List
import logging
from app.core.session_manager import session_manager
from app.api.services.aws_service import AWSService
from app.core.config import settings
from datetime import datetime

router = APIRouter()
logger = logging.getLogger(__name__)

@router.get("/scan")
async def scan_resources(
    session_token: str = Query(..., description="Session token from login"),
    region: Optional[str] = Query(None, description="AWS Region to scan"),
    service: Optional[str] = Query(None, description="Specific AWS service to scan")
):
    """
    Scan AWS resources for a given session.
    Can filter by region and service type.
    """
    logger.info(f"Resource scan request - Session: {session_token[:10]}..., Region: {region}, Service: {service}")
    
    # Validate session
    session = session_manager.get_session(session_token)
    if not session:
        logger.warning(f"Invalid or expired session: {session_token[:10]}...")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session"
        )
    
    logger.info(f"Session validated. Role ARN: {session['role_arn']}")
    
    try:
        aws_service = AWSService(session['role_arn'])
        
        # Determine regions to scan
        regions_to_scan = [region] if region else settings.AWS_REGIONS
        logger.info(f"Scanning regions: {regions_to_scan}")
        
        # Service mapping
        service_functions = {
            'ec2': lambda r: aws_service.get_ec2_instances(r),
            's3': lambda r: aws_service.get_s3_buckets() if r == regions_to_scan[0] else [],
            'snapshots': lambda r: aws_service.get_ebs_snapshots(r),
            'security-groups': lambda r: aws_service.get_security_groups(r),
            'vpc': lambda r: aws_service.get_vpcs(r),
            'iam-roles': lambda r: aws_service.get_iam_roles() if r == regions_to_scan[0] else [],
            'iam-policies': lambda r: aws_service.get_iam_policies() if r == regions_to_scan[0] else [],
            'rds': lambda r: aws_service.get_rds_instances(r),
            'ami': lambda r: aws_service.get_ami_images(r),
            'volumes': lambda r: aws_service.get_ebs_volumes(r),
            'elastic-ip': lambda r: aws_service.get_elastic_ips(r),
            'lambda': lambda r: aws_service.get_lambda_functions(r),
            'cloudtrail': lambda r: aws_service.get_cloudtrail_trails(r)
        }
        
        results = {}
        
        if service and service in service_functions:
            # Scan specific service
            logger.info(f"Scanning specific service: {service}")
            for reg in regions_to_scan:
                resources = service_functions[service](reg)
                if resources:
                    if service not in results:
                        results[service] = []
                    results[service].extend(resources)
        else:
            # Scan all services
            logger.info("Scanning all services")
            for svc_name, svc_func in service_functions.items():
                logger.debug(f"Scanning service: {svc_name}")
                for reg in regions_to_scan:
                    resources = svc_func(reg)
                    if resources:
                        if svc_name not in results:
                            results[svc_name] = []
                        results[svc_name].extend(resources)
        
        # Calculate summary
        summary = {
            'total_resources': sum(len(v) for v in results.values()),
            'services_scanned': len(results),
            'regions_scanned': len(regions_to_scan),
            'timestamp': datetime.utcnow().isoformat()
        }
        
        logger.info(f"Scan complete - Total resources: {summary['total_resources']}, Services: {summary['services_scanned']}")
        
        return {
            'summary': summary,
            'resources': results
        }
    
    except Exception as e:
        logger.exception(f"Failed to scan resources: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to scan resources: {str(e)}"
        )

@router.get("/services")
async def get_available_services():
    """Get list of supported AWS services"""
    logger.debug("Services list requested")
    return {
        'services': [
            {'id': 'ec2', 'name': 'EC2 Instances'},
            {'id': 's3', 'name': 'S3 Buckets'},
            {'id': 'snapshots', 'name': 'EBS Snapshots'},
            {'id': 'security-groups', 'name': 'Security Groups'},
            {'id': 'vpc', 'name': 'VPCs'},
            {'id': 'iam-roles', 'name': 'IAM Roles'},
            {'id': 'iam-policies', 'name': 'IAM Policies'},
            {'id': 'rds', 'name': 'RDS Instances'},
            {'id': 'ami', 'name': 'AMI Images'},
            {'id': 'volumes', 'name': 'EBS Volumes'},
            {'id': 'elastic-ip', 'name': 'Elastic IPs'},
            {'id': 'lambda', 'name': 'Lambda Functions'},
            {'id': 'cloudtrail', 'name': 'CloudTrail'}
        ]
    }

@router.get("/regions")
async def get_available_regions():
    """Get list of supported AWS regions"""
    logger.debug("Regions list requested")
    return {
        'regions': [
            {'id': 'us-east-1', 'name': 'US East (N. Virginia)'},
            {'id': 'us-east-2', 'name': 'US East (Ohio)'},
            {'id': 'us-west-1', 'name': 'US West (N. California)'},
            {'id': 'us-west-2', 'name': 'US West (Oregon)'}
        ]
    }
