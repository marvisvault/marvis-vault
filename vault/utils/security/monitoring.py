"""
Performance monitoring for security validation.

Tracks validation performance, rejection rates, and provides
metrics for operational monitoring.
"""

import time
import functools
from typing import Dict, Any, List, Callable, Optional
from collections import defaultdict, deque
from datetime import datetime
import threading
import logging

logger = logging.getLogger(__name__)


class ValidationMetrics:
    """Thread-safe metrics collection for validation."""
    
    def __init__(self, max_history: int = 10000):
        """
        Initialize metrics collector.
        
        Args:
            max_history: Maximum number of validation records to keep
        """
        self.max_history = max_history
        self._lock = threading.Lock()
        
        # Metrics storage
        self.validation_times: deque = deque(maxlen=max_history)
        self.validation_counts: Dict[str, int] = defaultdict(int)
        self.rejection_counts: Dict[str, int] = defaultdict(int)
        self.error_types: Dict[str, int] = defaultdict(int)
        self.bypass_uses: List[Dict[str, Any]] = []
        
        # Performance thresholds
        self.slow_threshold_ms = 100
        self.very_slow_threshold_ms = 500
    
    def record_validation(self, validation_type: str, duration_ms: float, 
                         success: bool, error_type: Optional[str] = None):
        """Record a validation attempt."""
        with self._lock:
            # Record timing
            self.validation_times.append({
                "type": validation_type,
                "duration_ms": duration_ms,
                "success": success,
                "timestamp": datetime.utcnow().isoformat()
            })
            
            # Update counts
            self.validation_counts[validation_type] += 1
            if not success:
                self.rejection_counts[validation_type] += 1
                if error_type:
                    self.error_types[error_type] += 1
            
            # Log slow validations
            if duration_ms > self.very_slow_threshold_ms:
                logger.error(f"Very slow validation: {validation_type} took {duration_ms:.2f}ms")
            elif duration_ms > self.slow_threshold_ms:
                logger.warning(f"Slow validation: {validation_type} took {duration_ms:.2f}ms")
    
    def record_bypass(self, bypass_info: Dict[str, Any]):
        """Record bypass usage."""
        with self._lock:
            self.bypass_uses.append({
                **bypass_info,
                "timestamp": datetime.utcnow().isoformat()
            })
    
    def get_summary(self) -> Dict[str, Any]:
        """Get metrics summary."""
        with self._lock:
            total_validations = sum(self.validation_counts.values())
            total_rejections = sum(self.rejection_counts.values())
            
            if total_validations == 0:
                return {"message": "No validations performed yet"}
            
            # Calculate timing statistics
            recent_times = [v["duration_ms"] for v in self.validation_times]
            if recent_times:
                avg_time = sum(recent_times) / len(recent_times)
                max_time = max(recent_times)
                min_time = min(recent_times)
                
                # Calculate percentiles
                sorted_times = sorted(recent_times)
                p50_idx = len(sorted_times) // 2
                p90_idx = int(len(sorted_times) * 0.9)
                p99_idx = int(len(sorted_times) * 0.99)
                
                timing_stats = {
                    "avg_ms": round(avg_time, 2),
                    "min_ms": round(min_time, 2),
                    "max_ms": round(max_time, 2),
                    "p50_ms": round(sorted_times[p50_idx], 2) if p50_idx < len(sorted_times) else 0,
                    "p90_ms": round(sorted_times[p90_idx], 2) if p90_idx < len(sorted_times) else 0,
                    "p99_ms": round(sorted_times[p99_idx], 2) if p99_idx < len(sorted_times) else 0,
                }
            else:
                timing_stats = {}
            
            # Calculate rejection rates
            rejection_rates = {}
            for val_type, count in self.validation_counts.items():
                rejections = self.rejection_counts.get(val_type, 0)
                rejection_rates[val_type] = round(rejections / count * 100, 2) if count > 0 else 0
            
            return {
                "total_validations": total_validations,
                "total_rejections": total_rejections,
                "overall_rejection_rate": round(total_rejections / total_validations * 100, 2),
                "validation_counts": dict(self.validation_counts),
                "rejection_rates": rejection_rates,
                "error_types": dict(self.error_types),
                "timing": timing_stats,
                "slow_validations": sum(1 for v in self.validation_times if v["duration_ms"] > self.slow_threshold_ms),
                "very_slow_validations": sum(1 for v in self.validation_times if v["duration_ms"] > self.very_slow_threshold_ms),
                "bypass_count": len(self.bypass_uses),
                "recent_bypasses": self.bypass_uses[-5:] if self.bypass_uses else []
            }
    
    def reset(self):
        """Reset all metrics."""
        with self._lock:
            self.validation_times.clear()
            self.validation_counts.clear()
            self.rejection_counts.clear()
            self.error_types.clear()
            self.bypass_uses.clear()
            logger.info("Validation metrics reset")


# Global metrics instance
_metrics = ValidationMetrics()


def monitor_validation(validation_type: str):
    """
    Decorator to monitor validation performance.
    
    Usage:
        @monitor_validation("role")
        def validate_role(role):
            # validation logic
            return normalized_role
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            success = True
            error_type = None
            
            try:
                result = func(*args, **kwargs)
                return result
            except Exception as e:
                success = False
                error_type = type(e).__name__
                raise
            finally:
                duration_ms = (time.time() - start_time) * 1000
                _metrics.record_validation(validation_type, duration_ms, success, error_type)
        
        return wrapper
    return decorator


def get_validation_metrics() -> Dict[str, Any]:
    """Get current validation metrics summary."""
    return _metrics.get_summary()


def reset_metrics():
    """Reset all validation metrics."""
    _metrics.reset()


def record_bypass_use(bypass_info: Dict[str, Any]):
    """Record that validation bypass was used."""
    _metrics.record_bypass(bypass_info)


def set_performance_thresholds(slow_ms: float = 100, very_slow_ms: float = 500):
    """
    Set performance thresholds for monitoring.
    
    Args:
        slow_ms: Threshold for slow validation warning
        very_slow_ms: Threshold for very slow validation error
    """
    _metrics.slow_threshold_ms = slow_ms
    _metrics.very_slow_threshold_ms = very_slow_ms
    logger.info(f"Performance thresholds set: slow={slow_ms}ms, very_slow={very_slow_ms}ms")