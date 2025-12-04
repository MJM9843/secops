# File: backend/app/api/endpoints/auth.py

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
import boto3
import logging
from botocore.exceptions import ClientError
from app.core.session_manager import session_manager

router = APIRouter()
logger = logging.getLogger(__name__)

class LoginRequest(BaseModel):
    role_arn: str = Field(..., description="IAM Role ARN to assume")

class LoginResponse(BaseModel):
    session_token: str
    message: str
    expires_in: int

class LogoutRequest(BaseModel):
    session_token: str

@router.post("/login", response_model=LoginResponse)
async def login(request: LoginRequest):
    """
    Authenticate user by assuming IAM role.
    Validates the role ARN and creates an in-memory session.
    """
    logger.info(f"=== LOGIN REQUEST START ===")
    logger.info(f"Role ARN: {request.role_arn}")
    
    try:
        # Validate ARN format
        if not request.role_arn.startswith("arn:aws:iam::"):
            logger.warning(f"Invalid ARN format: {request.role_arn}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid IAM Role ARN format"
            )
        
        # Attempt to assume the role to validate it
        sts_client = boto3.client('sts')
        
        try:
            logger.info(f"Attempting to assume role...")
            response = sts_client.assume_role(
                RoleArn=request.role_arn,
                RoleSessionName="SecOpsSession",
                DurationSeconds=3600
            )
            
            logger.info(f"Successfully assumed role")
            
            # Role is valid, create session
            session_token = session_manager.create_session(request.role_arn)
            
            logger.info(f"=== LOGIN SUCCESS ===")
            logger.info(f"Session token created: {session_token}")
            logger.info(f"Total sessions: {session_manager.get_all_sessions_count()}")
            
            return LoginResponse(
                session_token=session_token,
                message="Login successful",
                expires_in=14400  # 4 hours
            )
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            
            logger.error(f"AssumeRole failed - Code: {error_code}, Message: {error_message}")
            
            if error_code == 'AccessDenied':
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied. Ensure the role trusts this EC2 instance and has proper permissions."
                )
            elif error_code == 'InvalidIdentityToken':
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid credentials. Check EC2 instance IAM role."
                )
            else:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Failed to assume role: {error_message}"
                )
    
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Unexpected error during login: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Login failed: {str(e)}"
        )

@router.post("/logout")
async def logout(request: LogoutRequest):
    """Logout user by deleting session"""
    logger.info(f"Logout request for session: {request.session_token}")
    
    success = session_manager.delete_session(request.session_token)
    
    if not success:
        logger.warning(f"Session not found during logout")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found"
        )
    
    logger.info("Logout successful")
    return {"message": "Logout successful"}

@router.get("/validate")
async def validate_session(session_token: str):
    """Validate if session is still active"""
    logger.info(f"Validating session: {session_token}")
    
    session = session_manager.get_session(session_token)
    
    if not session:
        logger.warning(f"Session validation failed")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session"
        )
    
    logger.info(f"Session valid")
    
    return {
        "valid": True,
        "expires_at": session["expires_at"].isoformat(),
        "role_arn": session["role_arn"]
    }

@router.get("/stats")
async def get_session_stats():
    """Get session statistics"""
    active_sessions = session_manager.get_all_sessions_count()
    logger.info(f"Session stats - Active: {active_sessions}")
    
    return {
        "active_sessions": active_sessions
    }

@router.get("/debug-sessions")
async def debug_sessions():
    """Debug endpoint to see all active sessions with details"""
    info = session_manager.get_session_info()
    logger.info(f"Debug sessions requested - Total: {info['total_sessions']}")
    return info
