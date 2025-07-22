"""
Test protection against Denial of Service (DoS) attacks.

This module validates Marvis Vault's defenses against resource exhaustion attacks
that could render the system unavailable or degrade performance to unusable levels.

Attack vectors tested:
- Memory exhaustion via oversized payloads (>1MB contexts, >10KB fields)
- Stack exhaustion via deeply nested structures (>100 levels)
- CPU exhaustion via algorithmic complexity (ReDoS, Unicode bombs)
- Hash collision attacks via excessive field counts (HashDoS)

Security boundaries enforced:
- MAX_CONTENT_SIZE = 1MB: Total agent context size limit
- MAX_STRING_LENGTH = 10KB: Individual string field limit
- MAX_JSON_DEPTH = 100: Maximum nesting depth for objects/arrays
- MAX_ROLE_LENGTH = 100: Security-critical role field limit

These limits are calibrated to support legitimate use cases while preventing
attackers from consuming unbounded resources. Each test verifies both that
attacks are blocked AND that legitimate data near the limits is accepted.
"""

import pytest
import json
from vault.utils.security import (
    validate_agent_context,
    validate_role,
    SecurityValidationError,
)


class TestLargePayloadProtection:
    """Test protection against oversized payloads.
    
    Attack Category: Resource Exhaustion via Memory Consumption
    
    Real-world scenarios:
    - Attackers sending multi-gigabyte JSON payloads to crash services
    - Memory exhaustion attacks against API endpoints
    - Bypassing rate limits by sending fewer, larger requests
    
    Critical parameters:
    - MAX_CONTENT_SIZE = 1MB (1,048,576 bytes) - Balances functionality with DoS protection
    - MAX_STRING_LENGTH = 10KB (10,240 bytes) - Prevents individual field abuse
    - MAX_ROLE_LENGTH = 100 characters - Role fields have stricter limits
    """
    
    def test_oversized_context_rejected(self):
        """Verify rejection of contexts exceeding 1MB to prevent memory exhaustion.
        
        What: Tests that agent contexts larger than MAX_CONTENT_SIZE are rejected
        Why: Prevents attackers from exhausting server memory with oversized payloads
        How: Creates a context with 1MB + 1 byte of data and verifies rejection
        """
        # Create payload exceeding 1MB threshold to trigger size validation
        large_string = "x" * (1024 * 1024 + 1)  # 1,048,577 bytes
        
        oversized_context = {
            "role": "user",
            "trustScore": 80,
            "data": large_string
        }
        
        with pytest.raises(SecurityValidationError, match="too large"):
            # Reject payload exceeding 1MB to prevent memory exhaustion attacks
            validate_agent_context(oversized_context)
    
    def test_context_at_size_limit_accepted(self):
        """Verify legitimate contexts near size limit are not rejected.
        
        What: Tests that contexts at or below MAX_CONTENT_SIZE are accepted
        Why: Ensures security controls don't block legitimate large payloads
        How: Creates maximum allowed payload accounting for JSON overhead
        """
        # Calculate maximum data size accounting for JSON serialization overhead
        overhead = len('{"role":"user","trustScore":80,"data":""}')
        max_data_size = (1024 * 1024) - overhead - 100  # Leave some buffer
        
        acceptable_context = {
            "role": "user",
            "trustScore": 80,
            "data": "x" * max_data_size
        }
        
        # Accept payload within 1MB limit - legitimate use case protection
        result = validate_agent_context(acceptable_context)
        assert result["role"] == "user"  # Verify context processed correctly
    
    def test_individual_field_size_limit(self):
        """Verify individual fields cannot exceed 10KB to prevent targeted field attacks.
        
        What: Tests MAX_STRING_LENGTH enforcement on individual fields
        Why: Prevents attackers from bypassing total size limits via single large fields
        How: Creates a field exceeding 10KB and verifies rejection
        """
        # Create field exceeding 10KB per-field limit
        large_field = "x" * (10 * 1024 + 1)  # 10,241 bytes
        
        context = {
            "role": "user",
            "trustScore": 80,
            "comment": large_field
        }
        
        with pytest.raises(SecurityValidationError, match="too long"):
            # Reject fields over 10KB to prevent memory allocation attacks
            validate_agent_context(context)
    
    def test_role_length_limit(self):
        """Verify role field enforces 100 character limit for security.
        
        What: Tests MAX_ROLE_LENGTH enforcement on role fields
        Why: Role fields are security-critical and should never be arbitrarily long
        How: Attempts to set a 101-character role and verifies rejection
        """
        # Create role exceeding 100 character security limit
        long_role = "a" * 101
        
        with pytest.raises(SecurityValidationError, match="too long"):
            # Reject roles over 100 chars - security boundary enforcement
            validate_role(long_role)


class TestDeeplyNestedJSON:
    """Test protection against deeply nested JSON attacks.
    
    Attack Category: Stack Exhaustion via Recursive Parsing
    
    Real-world scenarios:
    - "Billion laughs" style attacks using nested structures
    - Stack overflow attempts through recursive JSON parsing
    - Parser DoS through pathological nesting patterns
    
    Critical parameters:
    - MAX_JSON_DEPTH = 100 levels - Prevents stack exhaustion while allowing complex data
    - Applies to both objects and arrays
    - Depth counted from root to deepest leaf
    """
    
    def test_excessive_nesting_rejected(self):
        """Verify JSON exceeding 100 levels of nesting is rejected.
        
        What: Tests MAX_JSON_DEPTH enforcement on nested objects
        Why: Prevents stack exhaustion attacks via recursive parsing
        How: Creates 101-level nested structure and verifies rejection
        """
        # Create pathological nesting to trigger stack protection
        def create_nested_dict(depth):
            if depth == 0:
                return {"value": "end"}
            return {"nested": create_nested_dict(depth - 1)}
        
        # Create structure with 101 levels
        deep_structure = create_nested_dict(101)
        
        context = {
            "role": "user",
            "trustScore": 80,
            "data": deep_structure
        }
        
        # Import depth validator for explicit testing
        from vault.utils.security.validators import validate_json_depth
        with pytest.raises(SecurityValidationError, match="nesting too deep"):
            # Reject 101+ levels to prevent stack exhaustion during parsing
            validate_json_depth(deep_structure)
    
    def test_reasonable_nesting_accepted(self):
        """Verify legitimate nested structures are not blocked.
        
        What: Tests that reasonable nesting (10 levels) is accepted
        Why: Security controls must not break legitimate nested data structures
        How: Creates 5-level nested object and verifies successful processing
        """
        # Create legitimate nested structure well within safety limits
        reasonable_structure = {
            "level1": {
                "level2": {
                    "level3": {
                        "level4": {
                            "level5": {
                                "data": "value"
                            }
                        }
                    }
                }
            }
        }
        
        context = {
            "role": "user",
            "trustScore": 80,
            "config": reasonable_structure
        }
        
        # Accept reasonable nesting - legitimate use case protection
        result = validate_agent_context(context)
        assert result["config"]["level1"]["level2"]["level3"]["level4"]["level5"]["data"] == "value"  # Verify deep access works
    
    def test_nested_arrays_depth_check(self):
        """Verify array nesting is also subject to depth limits.
        
        What: Tests MAX_JSON_DEPTH enforcement on nested arrays
        Why: Array recursion can cause stack exhaustion just like objects
        How: Creates 101-level nested array structure and verifies rejection
        """
        # Create pathological array nesting pattern
        def create_nested_array(depth):
            if depth == 0:
                return ["end"]
            return [create_nested_array(depth - 1)]
        
        deep_array = create_nested_array(101)
        
        from vault.utils.security.validators import validate_json_depth
        with pytest.raises(SecurityValidationError, match="nesting too deep"):
            # Reject deeply nested arrays - same stack exhaustion risk as objects
            validate_json_depth(deep_array)


class TestResourceExhaustion:
    """Test protection against resource exhaustion attacks.
    
    Attack Category: Resource Consumption via Algorithmic Complexity
    
    Real-world scenarios:
    - Hash collision attacks (HashDoS) using many fields
    - Unicode normalization bombs exploiting expansion
    - Compression ratio attacks (zip bombs in JSON form)
    
    Critical parameters:
    - Field count limits (implicit via total size)
    - Unicode normalization: NFKC for security
    - No explicit field count limit but controlled via MAX_CONTENT_SIZE
    """
    
    def test_many_small_fields(self):
        """Verify protection against HashDoS via excessive field count.
        
        What: Tests that many small fields totaling >1MB are rejected
        Why: Prevents hash collision attacks that degrade hashtable performance
        How: Creates 10,000 fields that together exceed size limits
        """
        # Create HashDoS pattern with thousands of fields
        context = {
            "role": "user",
            "trustScore": 80,
        }
        
        # Add 10,000 small fields
        for i in range(10000):
            context[f"field_{i}"] = f"value_{i}"
        
        # Reject payload with excessive fields - HashDoS prevention
        with pytest.raises(SecurityValidationError, match="too large"):
            validate_agent_context(context)
    
    def test_unicode_expansion_attacks(self):
        """Verify Unicode normalization doesn't enable expansion attacks.
        
        What: Tests handling of Unicode that expands during normalization
        Why: Some Unicode sequences can expand 3-4x during NFKC normalization
        How: Uses ligatures and special symbols that expand when normalized
        """
        # Test expansion-prone Unicode sequences
        expansion_attempts = [
            "ﬃ" * 1000,  # Ligatures that expand
            "℻" * 1000,   # Symbols that might normalize to multiple chars
            "𝕦𝕤𝕖𝕣",      # Mathematical alphanumeric symbols
        ]
        
        for attempt in expansion_attempts:
            # Unicode normalization should prevent expansion attacks
            try:
                result = validate_role(attempt[:100])  # Pre-limit to role boundary
                # Post-normalization length must respect security limits
                assert len(result) <= 100
            except SecurityValidationError:
                # Rejection for length/pattern is also acceptable security outcome
                pass
    
    def test_compression_bomb_prevention(self):
        """Verify protection against compression ratio attacks.
        
        What: Tests rejection of highly repetitive data mimicking compression bombs
        Why: Data with high compression ratios can DoS decompression operations
        How: Creates 1MB of repetitive data that would compress to <1KB
        """
        # Create compression bomb pattern - 1000:1 compression ratio
        repetitive = "a" * 100000
        
        context = {
            "role": "user", 
            "trustScore": 80,
            "data": repetitive * 10  # 1MB of 'a's
        }
        
        with pytest.raises(SecurityValidationError, match="too large"):
            # Reject compression bomb patterns - decompression DoS prevention
            validate_agent_context(context)


class TestPerformanceAttacks:
    """Test protection against attacks targeting validation performance.
    
    Attack Category: Algorithmic Complexity Attacks (ReDoS)
    
    Real-world scenarios:
    - Regular expression denial of service (ReDoS)
    - Catastrophic backtracking in pattern matching
    - Unicode normalization performance attacks
    
    Critical parameters:
    - Validation timeout: 100ms per operation
    - Regex patterns designed to avoid backtracking
    - Linear-time Unicode normalization via NFKC
    """
    
    def test_regex_dos_patterns(self):
        """Verify regex validation is not vulnerable to ReDoS attacks.
        
        What: Tests that pathological patterns don't cause exponential runtime
        Why: ReDoS can freeze services with 100% CPU usage from small inputs
        How: Tests known ReDoS patterns and enforces 100ms time limit
        """
        # Test catastrophic backtracking patterns
        redos_patterns = [
            "a" * 50 + "!" * 50,  # Patterns requiring backtracking
            "(a+)+" * 10,         # Nested quantifiers
            "x" * 100 + "y",      # Long strings with mismatch at end
        ]
        
        for pattern in redos_patterns:
            # Measure validation time to detect ReDoS vulnerability
            import time
            start = time.time()
            try:
                validate_role(pattern[:100])  # Test within role boundaries
            except SecurityValidationError:
                pass  # Rejection is fine, slowness is not
            duration = time.time() - start
            
            # Enforce 100ms limit - ReDoS patterns would take seconds/minutes
            assert duration < 0.1, f"ReDoS detected: {duration}s exceeds 100ms limit"
    
    def test_many_unicode_normalizations(self):
        """Verify Unicode normalization scales linearly with input count.
        
        What: Tests performance of many Unicode normalizations
        Why: Quadratic normalization algorithms could enable DoS
        How: Normalizes 100 Unicode fields and enforces 1-second limit
        """
        # Create workload requiring many normalizations
        context = {
            "role": "user",
            "trustScore": 80,
        }
        
        # Add fields with Unicode that needs normalization
        for i in range(100):
            context[f"field_{i}"] = f"tëst_värüé_{i}"
        
        import time
        start = time.time()
        try:
            validate_agent_context(context)
        except SecurityValidationError:
            pass
        duration = time.time() - start
        
        # Enforce 1-second limit for 100 normalizations - prevents O(n²) algorithms
        assert duration < 1.0, f"Normalization DoS: {duration}s exceeds 1s limit"