"""
Test suite for simulate command using realistic production data.
Tests real-world scenarios with comprehensive data structures.
"""

import json
import tempfile
from pathlib import Path
from typer.testing import CliRunner
import pytest

from vault.cli.main import app
from tests.fixtures.realistic_test_data import (
    TEST_SCENARIOS,
    create_temp_files,
    ADMIN_AGENT,
    ANALYST_MEDIUM_TRUST,
    CONTRACTOR_MINIMAL,
    MISSING_TRUSTSCORE,
    SQL_INJECTION_AGENT,
    HEALTHCARE_RECORDS,
    FINANCIAL_TRANSACTIONS,
    HEALTHCARE_HIPAA_POLICY,
    FINANCIAL_PCI_POLICY
)

runner = CliRunner()

class TestSimulateWithRealisticData:
    """Test simulate command with production-quality data."""
    
    def test_healthcare_admin_full_access(self, tmp_path):
        """Test healthcare admin can see all patient data including SSN."""
        scenario = TEST_SCENARIOS["healthcare_admin_access"]
        agent_file, _, policy_file = create_temp_files(tmp_path, scenario)
        
        result = runner.invoke(app, [
            "simulate", 
            "-a", str(agent_file), 
            "-p", str(policy_file)
        ])
        
        assert result.exit_code == 0
        output = result.stdout
        
        # Admin should have full access
        assert "Unmasked for role 'admin'" in output
        assert "CLEAR" in output
        
        # Verify comprehensive admin metadata is shown
        assert "admin_full_access" in open(agent_file).read()
        assert scenario["agent"]["clearanceLevel"] == "top-secret"
    
    def test_healthcare_nurse_limited_access(self, tmp_path):
        """Test nurse can see medical data but not financial/SSN."""
        scenario = TEST_SCENARIOS["healthcare_nurse_access"]
        agent_file, _, policy_file = create_temp_files(tmp_path, scenario)
        
        result = runner.invoke(app, [
            "simulate", 
            "-a", str(agent_file), 
            "-p", str(policy_file),
            "-v"  # Verbose to see field details
        ])
        
        assert result.exit_code == 0
        output = result.stdout
        
        # Should show mixed access
        assert "nurse" in output
        assert "trustScore" in output
        
    def test_financial_contractor_minimal_access(self, tmp_path):
        """Test contractor with low trust score gets minimal financial data access."""
        scenario = TEST_SCENARIOS["hr_contractor_access"]
        agent_file, _, policy_file = create_temp_files(tmp_path, scenario)
        
        result = runner.invoke(app, [
            "simulate", 
            "-a", str(agent_file), 
            "-p", str(policy_file)
        ])
        
        assert result.exit_code == 0
        output = result.stdout
        
        # Contractor should have very limited access
        assert "contractor" in output
        assert str(scenario["agent"]["trustScore"]) in output
        
    def test_missing_trustscore_safe_fallback(self, tmp_path):
        """Test that missing trustScore triggers safe fallback behavior."""
        scenario = TEST_SCENARIOS["missing_trustscore_fallback"]
        agent_file, _, policy_file = create_temp_files(tmp_path, scenario)
        
        result = runner.invoke(app, [
            "simulate", 
            "-a", str(agent_file), 
            "-p", str(policy_file),
            "-v"
        ])
        
        # Should not crash
        assert result.exit_code == 0
        output = result.stdout
        
        # Should show restrictive access due to missing trustScore
        assert "analyst" in output
        
    def test_sql_injection_rejection(self, tmp_path):
        """Test that SQL injection in agent fields is rejected."""
        # Create agent with SQL injection
        malicious_agent = SQL_INJECTION_AGENT.copy()
        agent_file = tmp_path / "malicious_agent.json"
        agent_file.write_text(json.dumps(malicious_agent))
        
        # Use a simple policy
        policy_file = tmp_path / "policy.json"
        policy_file.write_text(json.dumps({
            "fields": [{"field": "ssn", "conditions": ["role == 'admin'"]}]
        }))
        
        result = runner.invoke(app, [
            "simulate", 
            "-a", str(agent_file), 
            "-p", str(policy_file)
        ])
        
        # Should be rejected
        assert result.exit_code != 0
        assert "injection" in result.stdout.lower() or "error" in result.stdout.lower()
    
    def test_export_with_complex_data(self, tmp_path):
        """Test export functionality with nested healthcare data."""
        scenario = TEST_SCENARIOS["healthcare_admin_access"]
        agent_file, _, policy_file = create_temp_files(tmp_path, scenario)
        
        export_file = tmp_path / "export_output.json"
        
        result = runner.invoke(app, [
            "simulate", 
            "-a", str(agent_file), 
            "-p", str(policy_file),
            "-e", str(export_file)
        ])
        
        assert result.exit_code == 0
        assert export_file.exists()
        
        # Verify export contains comprehensive data
        export_data = json.loads(export_file.read_text())
        assert "context_summary" in export_data
        assert "fields_to_mask" in export_data
        assert export_data["context_summary"]["role"] == "admin"
        
        # Verify it includes admin metadata
        assert export_data["context_summary"]["trustScore"] == scenario["agent"]["trustScore"]
    
    def test_verbose_output_financial_data(self, tmp_path):
        """Test verbose output with complex financial transaction data."""
        # Use analyst with medium trust on financial data
        agent = ANALYST_MEDIUM_TRUST.copy()
        agent_file = tmp_path / "analyst.json"
        agent_file.write_text(json.dumps(agent))
        
        policy_file = tmp_path / "policy.json"
        policy_file.write_text(json.dumps(FINANCIAL_PCI_POLICY))
        
        result = runner.invoke(app, [
            "simulate", 
            "-a", str(agent_file), 
            "-p", str(policy_file),
            "-v"
        ])
        
        assert result.exit_code == 0
        output = result.stdout
        
        # Should show detailed field analysis
        assert "Field Breakdown" in output or "field" in output.lower()
        assert "analyst" in output
        assert str(agent["trustScore"]) in output


class TestSimulateEdgeCases:
    """Test edge cases and security scenarios."""
    
    def test_deeply_nested_policy_evaluation(self, tmp_path):
        """Test policy evaluation on deeply nested healthcare data."""
        # Create a policy targeting nested fields
        nested_policy = {
            "name": "Nested Field Policy",
            "fields": [
                {
                    "field": "patients[0].medicalHistory.currentMedications[0].name",
                    "conditions": ["role == 'pharmacist'"]
                },
                {
                    "field": "patients[0].contact.emergencyContact.phone",
                    "conditions": ["emergency == true"]
                }
            ]
        }
        
        agent = {"role": "pharmacist", "trustScore": 80}
        
        agent_file = tmp_path / "agent.json"
        policy_file = tmp_path / "policy.json"
        
        agent_file.write_text(json.dumps(agent))
        policy_file.write_text(json.dumps(nested_policy))
        
        result = runner.invoke(app, [
            "simulate", 
            "-a", str(agent_file), 
            "-p", str(policy_file)
        ])
        
        assert result.exit_code == 0
        assert "pharmacist" in result.stdout
    
    def test_multiple_condition_evaluation(self, tmp_path):
        """Test complex multi-condition policy evaluation."""
        # Use the comprehensive HR policy with multiple conditions
        agent = {
            "role": "hr_admin",
            "trustScore": 82,
            "purpose": "tax_reporting",
            "department": "Human Resources"
        }
        
        agent_file = tmp_path / "agent.json"
        policy_file = tmp_path / "policy.json"
        
        agent_file.write_text(json.dumps(agent))
        policy_file.write_text(json.dumps(HR_EMPLOYEE_POLICY))
        
        result = runner.invoke(app, [
            "simulate", 
            "-a", str(agent_file), 
            "-p", str(policy_file),
            "-v"
        ])
        
        assert result.exit_code == 0
        output = result.stdout
        
        # Should evaluate multiple conditions
        assert "hr_admin" in output
        assert "82" in str(output)  # trustScore
        
    def test_output_directory_isolation(self, tmp_path):
        """Ensure all outputs go to specified directory, not project root."""
        scenario = TEST_SCENARIOS["healthcare_admin_access"]
        agent_file, _, policy_file = create_temp_files(tmp_path, scenario)
        
        # Create a specific output directory
        output_dir = tmp_path / "test_outputs"
        output_dir.mkdir()
        export_file = output_dir / "test_export.json"
        
        # Get current directory contents before test
        import os
        root_files_before = set(os.listdir(os.getcwd()))
        
        result = runner.invoke(app, [
            "simulate", 
            "-a", str(agent_file), 
            "-p", str(policy_file),
            "-e", str(export_file)
        ])
        
        assert result.exit_code == 0
        assert export_file.exists()
        
        # Verify no new files in project root
        root_files_after = set(os.listdir(os.getcwd()))
        new_files = root_files_after - root_files_before
        
        # Filter out any pytest cache files
        new_files = {f for f in new_files if not f.startswith('.pytest')}
        
        assert len(new_files) == 0, f"Files created in root directory: {new_files}"
        
        # Verify export is in correct location
        assert export_file.parent == output_dir


if __name__ == "__main__":
    pytest.main([__file__, "-v"])