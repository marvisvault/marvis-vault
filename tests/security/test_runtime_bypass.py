"""
Test the runtime bypass API for emergency situations.

The bypass API allows temporary relaxation of validation rules
in emergency situations, with full audit logging.
"""

import pytest
import time
import threading
from vault.utils.security import (
    bypass_validation,
    is_bypass_active,
    get_validation_metrics,
    validate_agent_context,
    validate_role,
    SecurityValidationError,
)
from vault.utils.security.runtime_bypass import (
    get_active_bypass,
    get_all_bypasses,
    clear_all_bypasses,
)


class TestBypassAPI:
    """Test the bypass validation API."""
    
    def test_basic_bypass_context(self):
        """Basic bypass should work within context."""
        # Should fail without bypass
        with pytest.raises(SecurityValidationError):
            validate_role("admin'; DROP TABLE users;--")
        
        # Should work with bypass
        with bypass_validation("Testing bypass functionality"):
            assert is_bypass_active()
            # Dangerous input is allowed during bypass
            result = validate_role("admin'; DROP TABLE users;--")
            assert result == "admin'; DROP TABLE users;--"
        
        # Should fail again after bypass ends
        assert not is_bypass_active()
        with pytest.raises(SecurityValidationError):
            validate_role("admin'; DROP TABLE users;--")
    
    def test_bypass_requires_reason(self):
        """Bypass should require a reason for audit."""
        # Empty reason should fail
        with pytest.raises(ValueError, match="reason is required"):
            with bypass_validation(""):
                pass
        
        # Whitespace-only reason should fail
        with pytest.raises(ValueError, match="reason is required"):
            with bypass_validation("   "):
                pass
    
    def test_bypass_duration_limit(self):
        """Bypass duration should be limited."""
        # Over 1 hour should fail
        with pytest.raises(ValueError, match="cannot exceed 1 hour"):
            with bypass_validation("Test", duration_seconds=3601):
                pass
        
        # 1 hour or less should work
        with bypass_validation("Test", duration_seconds=3600):
            assert is_bypass_active()
    
    def test_bypass_auto_expires(self):
        """Bypass should automatically expire."""
        # Create short-duration bypass
        with bypass_validation("Quick test", duration_seconds=1):
            assert is_bypass_active()
            time.sleep(1.1)  # Wait for expiration
            assert not is_bypass_active()
    
    def test_bypass_info_available(self):
        """Bypass information should be retrievable."""
        with bypass_validation("Test bypass", user="admin"):
            info = get_active_bypass()
            assert info is not None
            assert info["reason"] == "Test bypass"
            assert info["user"] == "admin"
            assert info["is_active"] is True
            assert "bypass_id" in info
            assert "remaining_seconds" in info
    
    def test_thread_specific_bypass(self):
        """Bypass should be thread-specific by default."""
        results = {"thread1": None, "thread2": None}
        
        def thread1_func():
            with bypass_validation("Thread 1 bypass"):
                results["thread1"] = is_bypass_active()
        
        def thread2_func():
            # Should not see thread 1's bypass
            results["thread2"] = is_bypass_active()
        
        t1 = threading.Thread(target=thread1_func)
        t2 = threading.Thread(target=thread2_func)
        
        t1.start()
        time.sleep(0.1)  # Let t1 establish bypass
        t2.start()
        
        t1.join()
        t2.join()
        
        assert results["thread1"] is True
        assert results["thread2"] is False
    
    def test_global_bypass(self):
        """Global bypass should affect all threads."""
        results = {"thread1": None, "thread2": None}
        
        def check_bypass(key):
            results[key] = is_bypass_active()
        
        with bypass_validation("Global bypass", global_bypass=True):
            t1 = threading.Thread(target=lambda: check_bypass("thread1"))
            t2 = threading.Thread(target=lambda: check_bypass("thread2"))
            
            t1.start()
            t2.start()
            t1.join()
            t2.join()
            
            assert results["thread1"] is True
            assert results["thread2"] is True
    
    def test_bypass_validation_behavior(self):
        """Test what happens during bypass."""
        with bypass_validation("Test validation behavior"):
            # Invalid role - normally rejected
            result = validate_role(None)
            assert result == "anonymous"  # Default during bypass
            
            # Invalid trustScore - normally rejected
            from vault.utils.security import validate_trust_score
            result = validate_trust_score("not a number", required=True)
            assert result == 0.0  # Default during bypass
            
            # Invalid context
            result = validate_agent_context("not a dict")
            assert result == {"role": "anonymous", "trustScore": 0.0}
    
    def test_bypass_monitoring(self):
        """Bypass usage should be tracked."""
        # Get initial metrics
        metrics_before = get_validation_metrics()
        initial_bypass_count = metrics_before.get("bypass_count", 0)
        
        # Use bypass
        with bypass_validation("Monitoring test", user="tester"):
            # Do something that would normally fail
            validate_role("<script>alert(1)</script>")
        
        # Check metrics updated
        metrics_after = get_validation_metrics()
        assert metrics_after["bypass_count"] > initial_bypass_count
        
        # Recent bypasses should be recorded
        recent = metrics_after.get("recent_bypasses", [])
        assert len(recent) > 0
        assert any(b["reason"] == "Monitoring test" for b in recent)


class TestBypassSecurity:
    """Test security aspects of bypass system."""
    
    def test_bypass_logged(self):
        """All bypasses should be logged."""
        all_bypasses = get_all_bypasses()
        initial_count = len(all_bypasses.get("threads", {}))
        
        with bypass_validation("Security test"):
            # Check bypass is recorded
            all_bypasses = get_all_bypasses()
            assert len(all_bypasses["threads"]) > initial_count
    
    def test_clear_all_bypasses(self):
        """Admin should be able to clear all bypasses."""
        # Create some bypasses
        with bypass_validation("Test 1"):
            with bypass_validation("Test 2", global_bypass=True):
                # Both should be active
                assert is_bypass_active()
                
                # Clear all
                clear_all_bypasses()
                
                # Should no longer be active
                assert not is_bypass_active()
    
    def test_bypass_doesnt_break_validation(self):
        """Bypass should not break the validation system."""
        # Validate something normally
        result1 = validate_agent_context({
            "role": "user",
            "trustScore": 80
        })
        
        # Use bypass
        with bypass_validation("Test"):
            result2 = validate_agent_context({
                "role": "user", 
                "trustScore": 80
            })
        
        # Results should be the same
        assert result1 == result2
    
    def test_nested_bypass_not_allowed(self):
        """Nested bypasses in same thread should reuse existing."""
        with bypass_validation("Outer bypass"):
            info1 = get_active_bypass()
            
            with bypass_validation("Inner bypass"):
                info2 = get_active_bypass()
                
                # Should be the same bypass (not nested)
                assert info1["bypass_id"] == info2["bypass_id"]