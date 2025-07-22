"""
Runtime bypass API for emergency situations.

This module provides a controlled way to temporarily bypass validation
in emergency situations, with full audit logging.
"""

import contextlib
import threading
import time
import logging
from typing import Optional, Dict, Any
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class BypassContext:
    """Context for validation bypass with audit trail."""
    
    def __init__(self, reason: str, duration_seconds: int = 300, user: Optional[str] = None):
        """
        Initialize bypass context.
        
        Args:
            reason: Reason for bypass (required for audit)
            duration_seconds: How long bypass is valid (default 5 minutes)
            user: User requesting bypass (for audit)
        """
        self.reason = reason
        self.duration_seconds = duration_seconds
        self.user = user or "unknown"
        self.start_time = time.time()
        self.end_time = self.start_time + duration_seconds
        self.bypass_id = f"bypass_{int(self.start_time)}_{threading.get_ident()}"
        
    def is_active(self) -> bool:
        """Check if bypass is still active."""
        return time.time() < self.end_time
    
    def remaining_seconds(self) -> float:
        """Get remaining bypass time in seconds."""
        return max(0, self.end_time - time.time())
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for logging."""
        return {
            "bypass_id": self.bypass_id,
            "reason": self.reason,
            "user": self.user,
            "start_time": datetime.fromtimestamp(self.start_time).isoformat(),
            "end_time": datetime.fromtimestamp(self.end_time).isoformat(),
            "duration_seconds": self.duration_seconds,
            "remaining_seconds": self.remaining_seconds(),
            "is_active": self.is_active()
        }


class BypassManager:
    """Manages validation bypasses with thread safety."""
    
    def __init__(self):
        self._lock = threading.Lock()
        self._bypasses: Dict[int, BypassContext] = {}  # Thread ID -> BypassContext
        self._global_bypass: Optional[BypassContext] = None
    
    def create_bypass(self, reason: str, duration_seconds: int = 300, 
                     user: Optional[str] = None, global_bypass: bool = False) -> BypassContext:
        """
        Create a new bypass context.
        
        Args:
            reason: Reason for bypass
            duration_seconds: Duration in seconds
            user: User requesting bypass
            global_bypass: If True, affects all threads
            
        Returns:
            BypassContext instance
        """
        bypass = BypassContext(reason, duration_seconds, user)
        
        # Import here to avoid circular dependency
        from .monitoring import record_bypass_use
        
        with self._lock:
            if global_bypass:
                self._global_bypass = bypass
                logger.critical(f"GLOBAL validation bypass activated: {bypass.to_dict()}")
            else:
                thread_id = threading.get_ident()
                self._bypasses[thread_id] = bypass
                logger.warning(f"Thread validation bypass activated: {bypass.to_dict()}")
        
        # Record bypass in metrics
        record_bypass_use(bypass.to_dict())
        
        return bypass
    
    def is_bypass_active(self) -> bool:
        """Check if any bypass is active for current thread."""
        with self._lock:
            # Check global bypass
            if self._global_bypass and self._global_bypass.is_active():
                return True
            
            # Check thread-specific bypass
            thread_id = threading.get_ident()
            if thread_id in self._bypasses:
                bypass = self._bypasses[thread_id]
                if bypass.is_active():
                    return True
                else:
                    # Clean up expired bypass
                    del self._bypasses[thread_id]
            
            return False
    
    def get_active_bypass(self) -> Optional[BypassContext]:
        """Get active bypass for current thread."""
        with self._lock:
            # Check global bypass first
            if self._global_bypass and self._global_bypass.is_active():
                return self._global_bypass
            
            # Check thread-specific bypass
            thread_id = threading.get_ident()
            if thread_id in self._bypasses:
                bypass = self._bypasses[thread_id]
                if bypass.is_active():
                    return bypass
            
            return None
    
    def clear_bypass(self, thread_id: Optional[int] = None, clear_global: bool = False):
        """Clear bypass for thread or globally."""
        with self._lock:
            if clear_global:
                self._global_bypass = None
                logger.info("Global validation bypass cleared")
            elif thread_id:
                if thread_id in self._bypasses:
                    del self._bypasses[thread_id]
                    logger.info(f"Thread {thread_id} validation bypass cleared")
            else:
                # Clear current thread's bypass
                current_thread = threading.get_ident()
                if current_thread in self._bypasses:
                    del self._bypasses[current_thread]
                    logger.info(f"Current thread validation bypass cleared")
    
    def get_all_bypasses(self) -> Dict[str, Any]:
        """Get all active bypasses for monitoring."""
        with self._lock:
            result = {
                "global": self._global_bypass.to_dict() if self._global_bypass and self._global_bypass.is_active() else None,
                "threads": {}
            }
            
            # Clean up expired bypasses
            expired_threads = []
            for thread_id, bypass in self._bypasses.items():
                if bypass.is_active():
                    result["threads"][thread_id] = bypass.to_dict()
                else:
                    expired_threads.append(thread_id)
            
            for thread_id in expired_threads:
                del self._bypasses[thread_id]
            
            return result


# Global bypass manager instance
_bypass_manager = BypassManager()


@contextlib.contextmanager
def bypass_validation(reason: str, duration_seconds: int = 300, user: Optional[str] = None, global_bypass: bool = False):
    """
    Context manager for temporarily bypassing validation.
    
    Usage:
        with bypass_validation("Emergency fix for prod issue #123", user="admin"):
            # Validation is relaxed here
            result = process_untrusted_data(data)
    
    Args:
        reason: Reason for bypass (required)
        duration_seconds: How long bypass is valid
        user: User requesting bypass
        global_bypass: If True, affects all threads
    """
    if not reason or not reason.strip():
        raise ValueError("Bypass reason is required for audit trail")
    
    if duration_seconds > 3600:  # 1 hour max
        raise ValueError("Bypass duration cannot exceed 1 hour")
    
    # Create bypass
    bypass = _bypass_manager.create_bypass(reason, duration_seconds, user, global_bypass)
    
    try:
        yield bypass
    finally:
        # Clear bypass when context exits
        if global_bypass:
            _bypass_manager.clear_bypass(clear_global=True)
        else:
            _bypass_manager.clear_bypass()
        
        logger.info(f"Validation bypass ended: {bypass.bypass_id}")


def is_bypass_active() -> bool:
    """Check if validation bypass is active for current thread."""
    return _bypass_manager.is_bypass_active()


def get_active_bypass() -> Optional[Dict[str, Any]]:
    """Get active bypass information if any."""
    bypass = _bypass_manager.get_active_bypass()
    return bypass.to_dict() if bypass else None


def get_all_bypasses() -> Dict[str, Any]:
    """Get all active bypasses (for monitoring/admin)."""
    return _bypass_manager.get_all_bypasses()


def clear_all_bypasses():
    """Clear all bypasses (emergency admin action)."""
    logger.critical("Clearing all validation bypasses")
    _bypass_manager._bypasses.clear()
    _bypass_manager._global_bypass = None