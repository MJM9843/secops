# File: backend/app/core/session_manager.py

import secrets
import logging
from datetime import datetime, timedelta
from typing import Dict, Optional

logger = logging.getLogger(__name__)

class SessionManager:
    """In-memory session manager for storing temporary IAM credentials"""
    
    def __init__(self):
        self._sessions: Dict[str, dict] = {}
        # Session timeout: 4 hours
        self.session_timeout = 14400  # 4 hours in seconds
        logger.info(f"SessionManager initialized with {self.session_timeout}s timeout")
    
    def create_session(self, role_arn: str) -> str:
        """Create a new session and return session token"""
        session_token = secrets.token_urlsafe(32)
        expiry = datetime.utcnow() + timedelta(seconds=self.session_timeout)
        
        self._sessions[session_token] = {
            "role_arn": role_arn,
            "created_at": datetime.utcnow(),
            "expires_at": expiry,
            "last_accessed": datetime.utcnow()
        }
        
        logger.info(f"Created session for role: {role_arn}")
        logger.info(f"Session token: {session_token}")
        logger.info(f"Session expires at: {expiry.isoformat()}")
        logger.info(f"Total sessions in memory: {len(self._sessions)}")
        
        return session_token
    
    def get_session(self, session_token: str) -> Optional[dict]:
        """Get session data if valid and refresh expiry"""
        if not session_token:
            logger.warning("get_session called with empty session_token")
            return None
        
        logger.info(f"Looking for session: {session_token}")
        logger.info(f"Sessions in memory: {len(self._sessions)}")
        logger.debug(f"Available tokens: {list(self._sessions.keys())}")
        
        if session_token not in self._sessions:
            logger.error(f"Session NOT FOUND: {session_token}")
            logger.error(f"Available sessions: {len(self._sessions)}")
            if self._sessions:
                logger.error(f"First available token: {list(self._sessions.keys())[0]}")
            return None
        
        session = self._sessions[session_token]
        now = datetime.utcnow()
        
        # Check if expired
        if now > session["expires_at"]:
            logger.warning(f"Session expired: {session_token}")
            logger.warning(f"Expired at: {session['expires_at'].isoformat()}, Now: {now.isoformat()}")
            del self._sessions[session_token]
            return None
        
        # Update last accessed and extend expiry (sliding window)
        session["last_accessed"] = now
        session["expires_at"] = now + timedelta(seconds=self.session_timeout)
        
        logger.info(f"Session validated and refreshed: {session_token}")
        
        return session
    
    def delete_session(self, session_token: str) -> bool:
        """Delete a session"""
        if session_token in self._sessions:
            logger.info(f"Deleting session: {session_token}")
            del self._sessions[session_token]
            logger.info(f"Sessions remaining: {len(self._sessions)}")
            return True
        logger.warning(f"Attempted to delete non-existent session: {session_token}")
        return False
    
    def cleanup_expired_sessions(self):
        """Remove all expired sessions - ONLY called manually"""
        now = datetime.utcnow()
        expired_tokens = [
            token for token, session in self._sessions.items()
            if now > session["expires_at"]
        ]
        
        for token in expired_tokens:
            logger.info(f"Cleaning up expired session: {token}")
            del self._sessions[token]
        
        if expired_tokens:
            logger.info(f"Cleaned up {len(expired_tokens)} expired sessions")
        
        return len(expired_tokens)
    
    def get_all_sessions_count(self) -> int:
        """Get total number of active sessions WITHOUT cleanup"""
        # DO NOT call cleanup_expired_sessions() here
        return len(self._sessions)
    
    def get_session_info(self) -> dict:
        """Get detailed session information for debugging"""
        sessions_info = []
        now = datetime.utcnow()
        
        for token, data in self._sessions.items():
            time_remaining = (data['expires_at'] - now).total_seconds()
            sessions_info.append({
                'token': token,
                'role_arn': data['role_arn'],
                'created_at': data['created_at'].isoformat(),
                'expires_at': data['expires_at'].isoformat(),
                'last_accessed': data['last_accessed'].isoformat(),
                'time_remaining_seconds': int(time_remaining),
                'is_expired': time_remaining < 0
            })
        
        return {
            'total_sessions': len(sessions_info),
            'sessions': sessions_info
        }

# Global session manager instance
session_manager = SessionManager()
