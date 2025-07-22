"""
Comprehensive CLI tests using realistic data with current parser format.
"""

import json
import os
import tempfile
from pathlib import Path
from typer.testing import CliRunner
import pytest

from vault.cli.main import app
from tests.fixtures.realistic_test_data import (
    ADMIN_AGENT,
    USER_LOW_TRUST,
    CONTRACTOR_MINIMAL,
    MISSING_TRUSTSCORE,
    HEALTHCARE_RECORDS,
    FINANCIAL_TRANSACTIONS,
    EMPLOYEE_RECORDS
)
from tests.fixtures.compatible_policies import (
    HEALTHCARE_COMPATIBLE,
    FINANCIAL_COMPATIBLE,
    HR_COMPATIBLE,
    TEST_POLICIES
)

runner = CliRunner()

class TestCLIWithRealisticData:
    """Test CLI commands with production-quality data."""
    
    def test_simulate_healthcare_admin(self, tmp_path):
        """Test healthcare simulation with admin access."""
        # Write files
        agent_file = tmp_path / "admin.json"
        policy_file = tmp_path / "healthcare.json"
        
        agent_file.write_text(json.dumps(ADMIN_AGENT))
        policy_file.write_text(json.dumps(HEALTHCARE_COMPATIBLE))
        
        result = runner.invoke(app, [
            "simulate",
            "-a", str(agent_file),
            "-p", str(policy_file)
        ])
        
        if result.exit_code != 0:
            print(f"CLI Error: {result.stdout}")
        assert result.exit_code == 0
        assert "admin" in result.stdout
        assert "Unmasked for role 'admin'" in result.stdout
    
    def test_redact_financial_low_trust(self, tmp_path):
        """Test financial data redaction with low trust user."""
        agent_file = tmp_path / "user.json"
        content_file = tmp_path / "financial.json"
        policy_file = tmp_path / "finance.json"
        output_file = tmp_path / "output.json"
        
        agent_file.write_text(json.dumps(USER_LOW_TRUST))
        content_file.write_text(json.dumps(FINANCIAL_TRANSACTIONS))
        policy_file.write_text(json.dumps(FINANCIAL_COMPATIBLE))
        
        result = runner.invoke(app, [
            "redact",
            "-g", str(agent_file),
            "-i", str(content_file),
            "-p", str(policy_file),
            "-o", str(output_file)
        ])
        
        if result.exit_code != 0:
            # Write to file to avoid Unicode issues
            error_file = tmp_path / "error.txt"
            error_file.write_text(result.stdout, encoding='utf-8')
            print(f"Exit code: {result.exit_code}")
            print(f"Error written to: {error_file}")
        
        assert result.exit_code == 0
        assert output_file.exists()
        
        # Check redacted content
        redacted = json.loads(output_file.read_text())
        
        # Financial data should be redacted for low trust
        assert "[REDACTED]" in json.dumps(redacted)
    
    def test_simulate_export_json(self, tmp_path):
        """Test export functionality with healthcare data."""
        agent_file = tmp_path / "admin.json" 
        policy_file = tmp_path / "healthcare.json"
        export_file = tmp_path / "export.json"
        
        agent_file.write_text(json.dumps(ADMIN_AGENT))
        policy_file.write_text(json.dumps(HEALTHCARE_COMPATIBLE))
        
        result = runner.invoke(app, [
            "simulate",
            "-a", str(agent_file),
            "-p", str(policy_file),
            "-e", str(export_file)
        ])
        
        assert result.exit_code == 0
        assert export_file.exists()
        
        # Verify export content
        export_data = json.loads(export_file.read_text())
        assert "context_summary" in export_data
        assert export_data["context_summary"]["role"] == "admin"
        assert export_data["context_summary"]["trustScore"] == 95
    
    def test_missing_trustscore_handling(self, tmp_path):
        """Test graceful handling of missing trustScore."""
        agent_file = tmp_path / "missing.json"
        policy_file = tmp_path / "policy.json"
        
        agent_file.write_text(json.dumps(MISSING_TRUSTSCORE))
        policy_file.write_text(json.dumps(TEST_POLICIES["minimal"]))
        
        result = runner.invoke(app, [
            "simulate",
            "-a", str(agent_file),
            "-p", str(policy_file)
        ])
        
        # Should not crash
        assert result.exit_code == 0
        # Should show restrictive access
        assert "REDACTED" in result.stdout or "condition" in result.stdout.lower()
    
    def test_contractor_hr_access(self, tmp_path):
        """Test contractor cannot access HR data."""
        agent_file = tmp_path / "contractor.json"
        content_file = tmp_path / "employees.json"
        policy_file = tmp_path / "hr.json"
        output_file = tmp_path / "contractor_view.json"
        
        agent_file.write_text(json.dumps(CONTRACTOR_MINIMAL))
        content_file.write_text(json.dumps(EMPLOYEE_RECORDS))
        policy_file.write_text(json.dumps(HR_COMPATIBLE))
        
        result = runner.invoke(app, [
            "redact",
            "-a", str(agent_file),
            "-d", str(content_file),
            "-p", str(policy_file),
            "-o", str(output_file),
            "--compact"
        ])
        
        assert result.exit_code == 0
        assert output_file.exists()
        
        # Verify sensitive data is redacted
        redacted = json.loads(output_file.read_text())
        content_str = json.dumps(redacted)
        
        # Count redactions
        redaction_count = content_str.count("[REDACTED]")
        assert redaction_count > 5  # Should have many redactions
    
    def test_output_directory_enforcement(self, tmp_path):
        """Ensure no files are created outside test directory."""
        # Save current directory
        original_cwd = os.getcwd()
        
        # Create test workspace
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        os.chdir(workspace)
        
        try:
            # Run a simulate command
            agent_file = workspace / "agent.json"
            policy_file = workspace / "policy.json"
            export_file = workspace / "export.json"
            
            agent_file.write_text(json.dumps({"role": "user", "trustScore": 50}))
            policy_file.write_text(json.dumps(TEST_POLICIES["minimal"]))
            
            result = runner.invoke(app, [
                "simulate",
                "-a", str(agent_file),
                "-p", str(policy_file),
                "-e", str(export_file)
            ])
            
            assert result.exit_code == 0
            
            # Check only expected files exist
            files = list(workspace.iterdir())
            expected = {"agent.json", "policy.json", "export.json"}
            actual = {f.name for f in files}
            
            assert actual == expected, f"Unexpected files: {actual - expected}"
            
        finally:
            os.chdir(original_cwd)


class TestCLIEdgeCases:
    """Test CLI edge cases and error handling."""
    
    def test_malformed_agent_rejection(self, tmp_path):
        """Test that malformed agents are properly rejected."""
        agent_file = tmp_path / "bad_agent.json"
        policy_file = tmp_path / "policy.json"
        
        # Agent with SQL injection attempt
        bad_agent = {
            "role": "admin' OR '1'='1",
            "trustScore": 100
        }
        
        agent_file.write_text(json.dumps(bad_agent))
        policy_file.write_text(json.dumps(TEST_POLICIES["minimal"]))
        
        result = runner.invoke(app, [
            "simulate",
            "-a", str(agent_file),
            "-p", str(policy_file)
        ])
        
        # Should be rejected
        assert result.exit_code != 0
        assert "error" in result.stdout.lower()
    
    def test_nested_field_redaction(self, tmp_path):
        """Test redaction of deeply nested fields."""
        agent_file = tmp_path / "doctor.json"
        content_file = tmp_path / "patients.json"
        policy_file = tmp_path / "nested.json"
        
        doctor_agent = {
            "role": "doctor",
            "trustScore": 88,
            "patient_assigned": True
        }
        
        # Create nested patient data
        nested_data = {
            "patient": {
                "demographics": {
                    "ssn": "123-45-6789",
                    "name": "John Doe"
                },
                "contact": {
                    "phone": "555-1234"
                },
                "medical": {
                    "diagnosis": "Hypertension"
                }
            }
        }
        
        agent_file.write_text(json.dumps(doctor_agent))
        content_file.write_text(json.dumps(nested_data))
        policy_file.write_text(json.dumps(TEST_POLICIES["nested_fields"]))
        
        result = runner.invoke(app, [
            "redact",
            "-a", str(agent_file),
            "-d", str(content_file),
            "-p", str(policy_file),
            "-f", "json"
        ])
        
        assert result.exit_code == 0
        
        # Parse output
        output = json.loads(result.stdout)
        
        # Doctor should see diagnosis but not SSN
        assert output["patient"]["medical"]["diagnosis"] != "[REDACTED]"
        assert output["patient"]["demographics"]["ssn"] == "[REDACTED]"
    
    def test_complex_condition_evaluation(self, tmp_path):
        """Test complex multi-part conditions."""
        agent_file = tmp_path / "manager.json"
        policy_file = tmp_path / "complex.json"
        
        manager_agent = {
            "role": "manager",
            "trustScore": 82,
            "direct_report": True,
            "review_period": True
        }
        
        agent_file.write_text(json.dumps(manager_agent))
        policy_file.write_text(json.dumps(TEST_POLICIES["complex_conditions"]))
        
        result = runner.invoke(app, [
            "simulate",
            "-a", str(agent_file),
            "-p", str(policy_file),
            "-v"  # Verbose
        ])
        
        assert result.exit_code == 0
        
        # Should show condition evaluation
        assert "manager" in result.stdout
        assert "82" in result.stdout  # trustScore


class TestCLIPerformance:
    """Test CLI performance with large datasets."""
    
    def test_large_healthcare_dataset(self, tmp_path):
        """Test performance with many patient records."""
        agent_file = tmp_path / "admin.json"
        content_file = tmp_path / "large_patients.json"
        policy_file = tmp_path / "healthcare.json"
        output_file = tmp_path / "large_output.json"
        
        # Create large dataset
        large_data = HEALTHCARE_RECORDS.copy()
        large_data["patients"] = large_data["patients"] * 50  # 150 patients
        
        agent_file.write_text(json.dumps(ADMIN_AGENT))
        content_file.write_text(json.dumps(large_data))
        policy_file.write_text(json.dumps(HEALTHCARE_COMPATIBLE))
        
        import time
        start = time.time()
        
        result = runner.invoke(app, [
            "redact",
            "-a", str(agent_file),
            "-d", str(content_file),
            "-p", str(policy_file),
            "-o", str(output_file),
            "--compact"
        ])
        
        elapsed = time.time() - start
        
        assert result.exit_code == 0
        assert output_file.exists()
        assert elapsed < 5  # Should complete in under 5 seconds
        
        # Verify output is valid
        redacted = json.loads(output_file.read_text())
        assert len(redacted["patients"]) == 150


if __name__ == "__main__":
    pytest.main([__file__, "-v"])