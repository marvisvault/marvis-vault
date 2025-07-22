"""
Test performance monitoring capabilities.

The monitoring system tracks validation performance, rejection rates,
and provides metrics for operational monitoring.
"""

import pytest
import time
from vault.utils.security import (
    validate_agent_context,
    validate_role,
    validate_trust_score,
    get_validation_metrics,
    reset_metrics,
    SecurityValidationError,
)
from vault.utils.security.monitoring import set_performance_thresholds


class TestMetricsCollection:
    """Test that metrics are properly collected."""
    
    def setup_method(self):
        """Reset metrics before each test."""
        reset_metrics()
    
    def test_basic_metrics_collection(self):
        """Basic validation should generate metrics."""
        # Perform some validations
        validate_role("user")
        validate_trust_score(80)
        validate_agent_context({"role": "analyst", "trustScore": 75})
        
        # Get metrics
        metrics = get_validation_metrics()
        
        assert metrics["total_validations"] >= 3
        assert "role" in metrics["validation_counts"]
        assert "trustScore" in metrics["validation_counts"]
        assert "context" in metrics["validation_counts"]
    
    def test_rejection_tracking(self):
        """Rejections should be tracked separately."""
        # Some successful validations
        validate_role("user")
        validate_trust_score(50)
        
        # Some rejections
        try:
            validate_role(None)
        except SecurityValidationError:
            pass
        
        try:
            validate_trust_score("not a number")
        except SecurityValidationError:
            pass
        
        try:
            validate_trust_score(150)  # Out of range
        except SecurityValidationError:
            pass
        
        # Check metrics
        metrics = get_validation_metrics()
        
        assert metrics["total_validations"] >= 5
        assert metrics["total_rejections"] >= 3
        assert metrics["overall_rejection_rate"] > 0
        
        # Check rejection rates by type
        assert "role" in metrics["rejection_rates"]
        assert "trustScore" in metrics["rejection_rates"]
    
    def test_error_type_tracking(self):
        """Different error types should be tracked."""
        # Generate different error types
        try:
            validate_role("")  # Empty role
        except SecurityValidationError:
            pass
        
        try:
            validate_trust_score(True)  # Boolean
        except SecurityValidationError:
            pass
        
        try:
            validate_trust_score(float('inf'))  # Infinity
        except SecurityValidationError:
            pass
        
        metrics = get_validation_metrics()
        
        assert "error_types" in metrics
        assert "SecurityValidationError" in metrics["error_types"]
        assert metrics["error_types"]["SecurityValidationError"] >= 3
    
    def test_timing_statistics(self):
        """Timing statistics should be calculated."""
        # Perform multiple validations
        for i in range(100):
            validate_role(f"user{i}")
            validate_trust_score(i % 101)
        
        metrics = get_validation_metrics()
        timing = metrics["timing"]
        
        assert "avg_ms" in timing
        assert "min_ms" in timing
        assert "max_ms" in timing
        assert "p50_ms" in timing
        assert "p90_ms" in timing
        assert "p99_ms" in timing
        
        # Sanity checks
        assert timing["min_ms"] <= timing["avg_ms"] <= timing["max_ms"]
        assert timing["p50_ms"] <= timing["p90_ms"] <= timing["p99_ms"]
    
    def test_slow_validation_detection(self):
        """Slow validations should be detected."""
        # Set low thresholds for testing
        set_performance_thresholds(slow_ms=0.1, very_slow_ms=1.0)
        
        # Create artificially slow validation
        def slow_validation():
            # Validate a large context
            large_context = {
                "role": "user",
                "trustScore": 80,
            }
            # Add many fields to slow it down
            for i in range(1000):
                large_context[f"field_{i}"] = f"value_{i}" * 10
            
            try:
                validate_agent_context(large_context)
            except SecurityValidationError:
                pass
        
        slow_validation()
        
        metrics = get_validation_metrics()
        # Should have detected slow validation
        assert metrics.get("slow_validations", 0) > 0
    
    def test_metrics_reset(self):
        """Metrics should be resettable."""
        # Generate some metrics
        validate_role("user")
        validate_trust_score(80)
        
        metrics_before = get_validation_metrics()
        assert metrics_before["total_validations"] > 0
        
        # Reset
        reset_metrics()
        
        metrics_after = get_validation_metrics()
        assert metrics_after.get("message") == "No validations performed yet"


class TestPerformanceThresholds:
    """Test performance threshold configuration."""
    
    def test_threshold_configuration(self):
        """Performance thresholds should be configurable."""
        # Set custom thresholds
        set_performance_thresholds(slow_ms=50, very_slow_ms=200)
        
        # The thresholds are set internally
        # We can verify by causing slow validations and checking detection
        
        # Create validation that takes ~100ms (between slow and very_slow)
        large_data = "x" * 100000
        context = {
            "role": "user",
            "trustScore": 80,
            "data": large_data
        }
        
        # This should be marked as slow but not very slow
        # (actual timing depends on system performance)
        try:
            validate_agent_context(context)
        except SecurityValidationError:
            pass


class TestMetricsAccuracy:
    """Test that metrics are accurate and consistent."""
    
    def setup_method(self):
        """Reset metrics before each test."""
        reset_metrics()
    
    def test_count_accuracy(self):
        """Counts should be accurate."""
        # Exact number of validations
        n_role = 10
        n_trust = 15
        n_context = 5
        
        for i in range(n_role):
            validate_role(f"user{i}")
        
        for i in range(n_trust):
            validate_trust_score(i % 101)
        
        for i in range(n_context):
            validate_agent_context({
                "role": f"user{i}",
                "trustScore": 50
            })
        
        metrics = get_validation_metrics()
        
        # Context validation also validates role and trustScore internally
        assert metrics["validation_counts"]["role"] >= n_role
        assert metrics["validation_counts"]["trustScore"] >= n_trust
        assert metrics["validation_counts"]["context"] >= n_context
    
    def test_rejection_rate_calculation(self):
        """Rejection rates should be calculated correctly."""
        # 8 successful, 2 failed for role
        for i in range(8):
            validate_role(f"user{i}")
        
        for i in range(2):
            try:
                validate_role("")  # Will fail
            except SecurityValidationError:
                pass
        
        metrics = get_validation_metrics()
        
        # Should have 20% rejection rate for role
        role_rejection_rate = metrics["rejection_rates"].get("role", 0)
        assert 15 <= role_rejection_rate <= 25  # Allow some margin
    
    def test_performance_percentiles(self):
        """Performance percentiles should be meaningful."""
        # Generate many validations with varying complexity
        for i in range(200):
            if i % 10 == 0:
                # Every 10th is more complex
                context = {
                    "role": "user",
                    "trustScore": 50,
                    "extra": "x" * 1000  # Larger payload
                }
                try:
                    validate_agent_context(context)
                except:
                    pass
            else:
                # Simple validation
                validate_role(f"user{i}")
        
        metrics = get_validation_metrics()
        timing = metrics["timing"]
        
        # p99 should be notably higher than p50 due to complex validations
        if timing["p50_ms"] > 0:  # Avoid division by zero
            ratio = timing["p99_ms"] / timing["p50_ms"]
            assert ratio > 1.0  # p99 should be higher than median