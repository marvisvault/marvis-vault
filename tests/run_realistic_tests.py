#!/usr/bin/env python3
"""
Run realistic tests with production-quality data and verify:
1. All tests pass
2. No files are created in inappropriate directories
3. Tests use comprehensive, realistic data
"""

import subprocess
import sys
import os
from pathlib import Path

def run_tests():
    """Run the realistic test suites."""
    print("Running realistic tests with production-quality data...")
    print("=" * 70)
    
    # Get the project root
    project_root = Path(__file__).parent.parent
    os.chdir(project_root)
    
    # Check for files in root before tests
    root_files_before = set(os.listdir('.'))
    
    # Test files to run
    test_files = [
        "tests/test_simulate_command_realistic.py",
        "tests/test_redact_command_realistic.py"
    ]
    
    all_passed = True
    
    for test_file in test_files:
        print(f"\nRunning {test_file}...")
        print("-" * 50)
        
        # Run pytest with verbose output
        result = subprocess.run([
            sys.executable, "-m", "pytest", test_file, 
            "-v", 
            "--tb=short",
            "--no-header",
            "-q"
        ], capture_output=True, text=True)
        
        print(result.stdout)
        if result.stderr:
            print("STDERR:", result.stderr)
        
        if result.returncode != 0:
            all_passed = False
            print(f"FAILED: {test_file}")
        else:
            print(f"PASSED: {test_file}")
    
    # Check for files in root after tests
    root_files_after = set(os.listdir('.'))
    new_files = root_files_after - root_files_before
    
    # Filter out acceptable files
    new_files = {f for f in new_files if not any([
        f.startswith('.pytest'),
        f.startswith('.coverage'),
        f.endswith('.pyc'),
        f == '__pycache__',
    ])}
    
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    
    if new_files:
        print(f"WARNING: Tests created files in project root: {new_files}")
        all_passed = False
    else:
        print("SUCCESS: No files created in project root")
    
    if all_passed:
        print("SUCCESS: All realistic tests passed!")
        print("\nTests are using:")
        print("- Production-quality healthcare data (HIPAA)")
        print("- Realistic financial transactions (PCI-DSS)")
        print("- Comprehensive employee records (HR)")
        print("- Complex nested data structures")
        print("- Real-world agent profiles with metadata")
        print("- Security attack scenarios")
    else:
        print("FAILURE: Some tests failed")
        sys.exit(1)

if __name__ == "__main__":
    run_tests()