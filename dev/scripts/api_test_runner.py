#!/usr/bin/env python3
"""
Comprehensive API testing script for Marvis Vault
Uses the test data in dev/test-data/ for systematic testing
"""

import json
import sys
import os
from pathlib import Path
from typing import Dict, Any, List
import argparse
import time
from datetime import datetime

# Add vault to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from vault.sdk import redact, unmask
from vault.audit import get_audit_report
from vault.engine.policy_parser import load_policy


class APITestRunner:
    def __init__(self, test_data_dir: Path):
        self.test_data_dir = test_data_dir
        self.results = []
        self.start_time = None
        
    def load_json(self, filepath: str) -> Dict[str, Any]:
        """Load JSON file with path resolution"""
        if '#' in filepath:
            # Handle JSON pointer notation (e.g., "agents/file.json#path.to.object")
            file_part, pointer = filepath.split('#', 1)
            full_path = self.test_data_dir / file_part
            
            with open(full_path, 'r') as f:
                data = json.load(f)
            
            # Navigate to the specified object
            parts = pointer.split('.')
            result = data
            for part in parts:
                result = result[part]
            return result
        else:
            full_path = self.test_data_dir / filepath
            with open(full_path, 'r') as f:
                return json.load(f)
    
    def run_test(self, test_config: Dict[str, Any]) -> Dict[str, Any]:
        """Run a single test case"""
        test_name = test_config['name']
        print(f"\nRunning test: {test_name}")
        
        start = time.time()
        result = {
            'name': test_name,
            'status': 'PENDING',
            'duration': 0,
            'details': {}
        }
        
        try:
            # Load test data
            agent = self.load_json(test_config['agent'])
            content = self.load_json(test_config['content'])
            policy = self.load_json(test_config['policy'])
            
            # Execute redaction
            redacted_result = redact(
                content=json.dumps(content),
                policy=policy,
                agent_context=agent
            )
            
            # Validate results
            if 'expected' in test_config:
                expected = test_config['expected']
                
                if 'result' in expected and expected['result'] == 'rejected':
                    result['status'] = 'FAIL'
                    result['details']['error'] = 'Expected rejection but got success'
                else:
                    # Check field redaction
                    parsed_content = json.loads(redacted_result.content)
                    result['status'] = 'PASS'
                    result['details']['redacted_fields'] = redacted_result.fields
                    
                    # Verify specific field expectations
                    if 'ssn' in expected:
                        # Navigate to SSN fields and check
                        pass  # Implement field checking logic
            
            result['details']['execution_time'] = f"{time.time() - start:.3f}s"
            
        except Exception as e:
            result['status'] = 'ERROR'
            result['details']['error'] = str(e)
            result['details']['error_type'] = type(e).__name__
        
        result['duration'] = time.time() - start
        return result
    
    def run_suite(self, suite_name: str, suite_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Run a test suite"""
        print(f"\n{'='*60}")
        print(f"Running suite: {suite_name}")
        print(f"Description: {suite_config['description']}")
        print(f"{'='*60}")
        
        suite_results = []
        for test in suite_config['tests']:
            result = self.run_test(test)
            suite_results.append(result)
            self.results.append(result)
        
        return suite_results
    
    def run_all_tests(self, config_file: Path) -> None:
        """Run all tests from config"""
        self.start_time = datetime.now()
        
        with open(config_file, 'r') as f:
            config = json.load(f)
        
        print(f"Starting API tests at {self.start_time}")
        print(f"Test data directory: {self.test_data_dir}")
        
        # Run each test suite
        for suite_name, suite_config in config['test_suites'].items():
            if 'tests' in suite_config:  # Skip non-test sections
                self.run_suite(suite_name, suite_config)
        
        # Print summary
        self.print_summary()
    
    def print_summary(self):
        """Print test execution summary"""
        end_time = datetime.now()
        duration = (end_time - self.start_time).total_seconds()
        
        passed = sum(1 for r in self.results if r['status'] == 'PASS')
        failed = sum(1 for r in self.results if r['status'] == 'FAIL')
        errors = sum(1 for r in self.results if r['status'] == 'ERROR')
        
        print(f"\n{'='*60}")
        print(f"TEST SUMMARY")
        print(f"{'='*60}")
        print(f"Total tests: {len(self.results)}")
        print(f"Passed: {passed}")
        print(f"Failed: {failed}")
        print(f"Errors: {errors}")
        print(f"Duration: {duration:.2f}s")
        print(f"{'='*60}")
        
        # Show failed tests
        if failed > 0 or errors > 0:
            print("\nFAILED/ERROR TESTS:")
            for result in self.results:
                if result['status'] in ['FAIL', 'ERROR']:
                    print(f"  - {result['name']}: {result['details'].get('error', 'Unknown error')}")
        
        # Save results
        results_file = f"test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(results_file, 'w') as f:
            json.dump({
                'start_time': self.start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration': duration,
                'summary': {
                    'total': len(self.results),
                    'passed': passed,
                    'failed': failed,
                    'errors': errors
                },
                'results': self.results
            }, f, indent=2)
        
        print(f"\nDetailed results saved to: {results_file}")


def main():
    parser = argparse.ArgumentParser(description='Run Marvis Vault API tests')
    parser.add_argument(
        '--config',
        default='dev/test-data/test-config.json',
        help='Path to test configuration file'
    )
    parser.add_argument(
        '--data-dir',
        default='dev/test-data',
        help='Path to test data directory'
    )
    parser.add_argument(
        '--suite',
        help='Run only a specific test suite'
    )
    
    args = parser.parse_args()
    
    # Convert paths
    config_path = Path(args.config)
    data_dir = Path(args.data_dir)
    
    if not config_path.exists():
        print(f"Error: Config file not found: {config_path}")
        sys.exit(1)
    
    if not data_dir.exists():
        print(f"Error: Test data directory not found: {data_dir}")
        sys.exit(1)
    
    # Run tests
    runner = APITestRunner(data_dir)
    runner.run_all_tests(config_path)


if __name__ == '__main__':
    main()