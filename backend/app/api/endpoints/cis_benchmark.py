# File: backend/app/api/endpoints/cis_benchmark.py

from fastapi import APIRouter, HTTPException, status, Query
from typing import Optional, Dict, List
from pydantic import BaseModel
from datetime import datetime
import logging
from app.core.session_manager import session_manager
from app.api.services.cis_service import CISBenchmarkService
from app.api.services.cis_remediation_service import CISRemediationService
from app.core.config import settings

router = APIRouter()
logger = logging.getLogger(__name__)

# In-memory storage for remediation history
remediation_history: Dict[str, List[Dict]] = {}

class RemediationRequest(BaseModel):
    session_token: str
    region: str
    check_id: str
    resource_ids: List[str]


@router.get("/scan")
async def scan_cis_benchmarks(
    session_token: str = Query(..., description="Session token from login"),
    region: Optional[str] = Query(None, description="AWS Region to scan"),
    service: Optional[str] = Query(None, description="Specific service to scan")
):
    """
    Scan CIS benchmarks for compliance.
    Returns pass/fail counts and failed resources.
    """
    logger.info(
        f"CIS scan request - Session: {session_token[:10]}..., Region: {region}, Service: {service}"
    )

    # Validate session
    session = session_manager.get_session(session_token)
    if not session:
        logger.warning("Invalid or expired session for CIS scan")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session",
        )

    try:
        cis_service = CISBenchmarkService(session["role_arn"])

        # Determine regions to scan
        regions_to_scan = [region] if region else settings.AWS_REGIONS
        logger.info(f"Scanning CIS benchmarks in regions: {regions_to_scan}")

        # Define all CIS checks with their metadata
        all_checks = {
            "ec2": {
                "EBS_DEFAULT_ENCRYPTION": {
                    "name": "EBS encryption by default enabled",
                    "func": cis_service.check_ebs_default_encryption,
                    "regional": True,
                },
                "EC2_UNTAGGED_INSTANCES": {
                    "name": "EC2 instances have tags",
                    "func": cis_service.check_ec2_untagged_instances,
                    "regional": True,
                },
            },
            "s3": {
                "S3_BLOCK_PUBLIC_ACCESS": {
                    "name": "Block Public Access fully enabled",
                    "func": cis_service.check_s3_block_public_access,
                    "regional": False,
                }
            },
            "snapshots": {
                "SNAPSHOT_ENCRYPTION": {
                    "name": "EBS snapshots are encrypted",
                    "func": cis_service.check_snapshot_encryption,
                    "regional": True,
                },
                "SNAPSHOT_PUBLIC": {
                    "name": "Snapshots are not public",
                    "func": cis_service.check_snapshot_public,
                    "regional": True,
                },
            },
            "security-groups": {
                "SG_SSH_OPEN": {
                    "name": "SSH not open to 0.0.0.0/0",
                    "func": cis_service.check_sg_ssh_open,
                    "regional": True,
                },
                "SG_OUTBOUND_UNRESTRICTED": {
                    "name": "Outbound traffic not unrestricted",
                    "func": cis_service.check_sg_outbound_unrestricted,
                    "regional": True,
                },
            },
            "iam": {
                "IAM_ROOT_MFA": {
                    "name": "Root account MFA enabled",
                    "func": cis_service.check_iam_root_mfa,
                    "regional": False,
                },
                "IAM_ACCESS_ANALYZER": {
                    "name": "IAM Access Analyzer enabled",
                    "func": cis_service.check_iam_access_analyzer,
                    "regional": True,
                },
            },
            "volumes": {
                "VOLUME_ENCRYPTION": {
                    "name": "All EBS volumes are encrypted",
                    "func": cis_service.check_volume_encryption,
                    "regional": True,
                },
                "VOLUME_ORPHANED": {
                    "name": "No orphaned volumes",
                    "func": cis_service.check_volume_orphaned,
                    "regional": True,
                },
            },
            "elastic-ip": {
                "EIP_ATTACHED": {
                    "name": "Elastic IPs are attached",
                    "func": cis_service.check_eip_attached,
                    "regional": True,
                }
            },
        }

        # Filter checks by service if specified
        checks_to_run = (
            {service: all_checks[service]} if service and service in all_checks else all_checks
        )

        # Run checks
        results = {}
        total_passed = 0
        total_failed = 0

        for svc_name, svc_checks in checks_to_run.items():
            results[svc_name] = {}

            for check_id, check_info in svc_checks.items():
                check_result = {
                    "name": check_info["name"],
                    "passed": 0,
                    "failed": 0,
                    "failed_resources": [],
                }

                if check_info["regional"]:
                    # Run for each region
                    for reg in regions_to_scan:
                        passed, failed, failed_res = check_info["func"](reg)
                        check_result["passed"] += passed
                        check_result["failed"] += failed
                        check_result["failed_resources"].extend(failed_res)
                else:
                    # Run once (global service)
                    passed, failed, failed_res = check_info["func"](regions_to_scan[0])
                    check_result["passed"] = passed
                    check_result["failed"] = failed
                    check_result["failed_resources"] = failed_res

                results[svc_name][check_id] = check_result
                total_passed += check_result["passed"]
                total_failed += check_result["failed"]

        logger.info(
            f"CIS scan complete - Passed: {total_passed}, Failed: {total_failed}"
        )

        return {
            "summary": {
                "total_passed": total_passed,
                "total_failed": total_failed,
                "compliance_percentage": round(
                    (total_passed / (total_passed + total_failed) * 100)
                    if (total_passed + total_failed) > 0
                    else 0,
                    2,
                ),
                "timestamp": datetime.utcnow().isoformat(),
                "regions_scanned": len(regions_to_scan),
            },
            "results": results,
        }

    except Exception as e:
        logger.exception(f"Failed to scan CIS benchmarks: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to scan CIS benchmarks: {str(e)}",
        )


@router.post("/remediate")
async def remediate_benchmark(request: RemediationRequest):
    """
    Apply remediation for failed CIS benchmark checks.
    Stores remediation history for rollback.
    """

    logger.info("=== REMEDIATION REQUEST ===")
    logger.info(f"Check ID: {request.check_id}")
    logger.info(f"Region: {request.region}")
    logger.info(f"Resources: {request.resource_ids}")

    # Validate session
    session = session_manager.get_session(request.session_token)
    if not session:
        logger.warning("Invalid or expired session for remediation")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session",
        )

    try:
        remediation_service = CISRemediationService(session["role_arn"])

        results = []

        # Special-case remediations
        if request.check_id == "IAM_ACCESS_ANALYZER":
            logger.info(f"Remediating IAM_ACCESS_ANALYZER in region {request.region}")
            try:
                result = remediation_service.remediate_iam_access_analyzer(request.region)
                results.append(
                    {
                        "resource_id": f"analyzer-{request.region}",
                        "success": result.get("success", False),
                        "message": result.get("message", "Unknown result"),
                        "timestamp": result.get(
                            "timestamp", datetime.utcnow().isoformat()
                        ),
                    }
                )
            except Exception as e:
                logger.error(f"IAM Access Analyzer remediation error: {str(e)}")
                results.append(
                    {
                        "resource_id": f"analyzer-{request.region}",
                        "success": False,
                        "message": f"Error: {str(e)}",
                        "timestamp": datetime.utcnow().isoformat(),
                    }
                )

        elif request.check_id == "EBS_DEFAULT_ENCRYPTION":
            logger.info(f"Remediating EBS_DEFAULT_ENCRYPTION in region {request.region}")
            try:
                result = remediation_service.remediate_ebs_default_encryption(
                    request.region
                )
                results.append(
                    {
                        "resource_id": f"account-{request.region}",
                        "success": result.get("success", False),
                        "message": result.get("message", "Unknown result"),
                        "timestamp": result.get(
                            "timestamp", datetime.utcnow().isoformat()
                        ),
                    }
                )
            except Exception as e:
                logger.error(f"EBS encryption remediation error: {str(e)}")
                results.append(
                    {
                        "resource_id": f"account-{request.region}",
                        "success": False,
                        "message": f"Error: {str(e)}",
                        "timestamp": datetime.utcnow().isoformat(),
                    }
                )

        elif request.check_id == "EC2_UNTAGGED_INSTANCES":
            logger.info("Remediating EC2_UNTAGGED_INSTANCES")
            for resource_id in request.resource_ids:
                try:
                    result = remediation_service.remediate_ec2_untagged_instances(
                        resource_id, request.region
                    )
                    results.append(
                        {
                            "resource_id": resource_id,
                            "success": result.get("success", False),
                            "message": result.get("message", "Unknown result"),
                            "timestamp": result.get(
                                "timestamp", datetime.utcnow().isoformat()
                            ),
                        }
                    )
                except Exception as e:
                    logger.error(
                        f"EC2 termination error for {resource_id}: {str(e)}"
                    )
                    results.append(
                        {
                            "resource_id": resource_id,
                            "success": False,
                            "message": f"Error: {str(e)}",
                            "timestamp": datetime.utcnow().isoformat(),
                        }
                    )

        else:
            remediation_map = {
                "S3_ENCRYPTION": lambda r: remediation_service.remediate_s3_encryption(r),
                "S3_BLOCK_PUBLIC_ACCESS": lambda r: remediation_service.remediate_s3_block_public_access(
                    r
                ),
                "S3_PUBLIC_ACL": lambda r: remediation_service.remediate_s3_public_acl(r),
                "SNAPSHOT_PUBLIC": lambda r: remediation_service.remediate_snapshot_public(
                    r, request.region
                ),
                "SG_SSH_OPEN": lambda r: remediation_service.remediate_sg_ssh_open(
                    r, request.region
                ),
                "RDS_PUBLIC_ACCESS": lambda r: remediation_service.remediate_rds_public_access(
                    r, request.region
                ),
                "RDS_DELETION_PROTECTION": lambda r: remediation_service.remediate_rds_deletion_protection(
                    r, request.region
                ),
                "AMI_NOT_PUBLIC": lambda r: remediation_service.remediate_ami_not_public(
                    r, request.region
                ),
                "EIP_ATTACHED": lambda r: remediation_service.remediate_eip_attached(
                    r, request.region
                ),
            }

            if request.check_id not in remediation_map:
                return {
                    "success": False,
                    "message": f"Automated remediation not available for {request.check_id}",
                    "resources_remediated": 0,
                    "total_resources": len(request.resource_ids),
                    "details": [],
                }

            for resource_id in request.resource_ids:
                try:
                    result = remediation_map[request.check_id](resource_id)
                    results.append(
                        {
                            "resource_id": resource_id,
                            "success": result.get("success", False),
                            "message": result.get("message", "Unknown result"),
                            "timestamp": result.get(
                                "timestamp", datetime.utcnow().isoformat()
                            ),
                        }
                    )
                except Exception as e:
                    results.append(
                        {
                            "resource_id": resource_id,
                            "success": False,
                            "message": f"Error: {str(e)}",
                            "timestamp": datetime.utcnow().isoformat(),
                        }
                    )

        # Store in remediation history
        history_key = f"{request.session_token}:{request.region}"
        remediation_history.setdefault(history_key, []).append(
            {
                "check_id": request.check_id,
                "region": request.region,
                "timestamp": datetime.utcnow().isoformat(),
                "results": results,
            }
        )

        success_count = sum(1 for r in results if r["success"])

        return {
            "success": success_count > 0,
            "message": f"Remediation completed: {success_count}/{len(results)} successful",
            "resources_remediated": success_count,
            "total_resources": len(results),
            "details": results,
        }

    except Exception as e:
        logger.exception(f"Remediation failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Remediation failed: {str(e)}",
        )


@router.get("/remediation-history")
async def get_remediation_history(
    session_token: str = Query(...),
    region: Optional[str] = Query(None),
):
    """Get remediation history for rollback."""

    session = session_manager.get_session(session_token)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session",
        )

    history_key = f"{session_token}:{region}" if region else None

    if history_key and history_key in remediation_history:
        return {"history": remediation_history[history_key]}

    elif not region:
        all_history = [
            entry
            for key, history in remediation_history.items()
            if key.startswith(session_token)
            for entry in history
        ]
        return {"history": all_history}

    return {"history": []}


@router.post("/rollback")
async def rollback_remediation(
    session_token: str,
    region: str,
    remediation_id: str,
):
    """Placeholder for rollback feature."""
    session = session_manager.get_session(session_token)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session",
        )

    return {
        "success": True,
        "message": "Rollback functionality prepared",
        "note": "Actual rollback requires implementing reverse actions",
    }
