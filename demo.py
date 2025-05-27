#!/usr/bin/env python3
"""
Marvis Vault Demo Script
Shows off the core features and security improvements
"""

import json
import subprocess
import sys
import os
from pathlib import Path

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def print_header(text):
    print(f"\n{Colors.CYAN}{'='*60}{Colors.ENDC}")
    print(f"{Colors.CYAN}{text:^60}{Colors.ENDC}")
    print(f"{Colors.CYAN}{'='*60}{Colors.ENDC}\n")

def run_command(cmd, description):
    """Run a command and show the output"""
    print(f"{Colors.YELLOW}$ {cmd}{Colors.ENDC}")
    print(f"{Colors.BLUE}# {description}{Colors.ENDC}\n")
    
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(f"{Colors.RED}{result.stderr}{Colors.ENDC}")
    print()
    return result.returncode

def ensure_examples_exist():
    """Make sure we have the example files needed for the demo"""
    # Create a demo policy
    demo_policy = {
        "mask": ["ssn", "email", "phone", "credit_card"],
        "unmask_roles": ["admin", "security_officer"],
        "conditions": [
            "trustScore >= 90",
            "trustScore >= 70 && role == 'manager'",
            "role == 'auditor' && trustScore >= 60"
        ]
    }
    
    os.makedirs("demo", exist_ok=True)
    with open("demo/policy.json", "w") as f:
        json.dump(demo_policy, f, indent=2)
    
    # Create demo agents
    agents = {
        "demo/agent-admin.json": {"role": "admin", "trustScore": 95},
        "demo/agent-user.json": {"role": "user", "trustScore": 50},
        "demo/agent-manager.json": {"role": "manager", "trustScore": 75},
        "demo/agent-untrusted.json": {"role": "contractor", "trustScore": 30},
    }
    
    for path, data in agents.items():
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
    
    # Create demo data
    demo_data = {
        "customer": {
            "name": "John Smith",
            "email": "john.smith@example.com",
            "phone": "555-123-4567",
            "ssn": "123-45-6789",
            "credit_card": "4532-1234-5678-9012"
        },
        "notes": "VIP customer - handle with care",
        "internal_id": "CUST-12345"
    }
    
    with open("demo/customer_data.json", "w") as f:
        json.dump(demo_data, f, indent=2)

def main():
    print(f"{Colors.BOLD}{Colors.MAGENTA}")
    print(r"""
    __  __                  _      __      __         _ _   
   |  \/  |                (_)     \ \    / /        | | |  
   | \  / | __ _ _ ____   ___ ___   \ \  / /_ _ _   _| | |_ 
   | |\/| |/ _` | '__\ \ / / / __|   \ \/ / _` | | | | | __|
   | |  | | (_| | |   \ V /| \__ \    \  / (_| | |_| | | |_ 
   |_|  |_|\__,_|_|    \_/ |_|___/     \/ \__,_|\__,_|_|\__|
   
   Programmable Compliance Infrastructure for Agentic AI
    """)
    print(f"{Colors.ENDC}")
    
    ensure_examples_exist()
    
    # 1. Show what Marvis Vault does
    print_header("1. Core Feature: Policy-Based Redaction")
    
    print("Marvis Vault redacts sensitive data based on who's asking (role + trust score).\n")
    
    # Show the policy
    print(f"{Colors.BOLD}Demo Policy:{Colors.ENDC}")
    with open("demo/policy.json") as f:
        print(json.dumps(json.load(f), indent=2))
    
    input(f"\n{Colors.GREEN}Press Enter to see simulations...{Colors.ENDC}")
    
    # 2. Run simulations
    print_header("2. Simulations: Who Sees What?")
    
    scenarios = [
        ("Admin (Unmask Role)", "demo/agent-admin.json", "Admins see everything"),
        ("Manager (Meets Condition)", "demo/agent-manager.json", "trustScore >= 70 && role == 'manager'"),
        ("Regular User", "demo/agent-user.json", "Doesn't meet any conditions"),
        ("Untrusted Contractor", "demo/agent-untrusted.json", "Low trust score"),
    ]
    
    for title, agent_file, description in scenarios:
        print(f"\n{Colors.BOLD}{title}:{Colors.ENDC} {description}")
        run_command(
            f"vault simulate -a {agent_file} -p demo/policy.json",
            f"Simulating access for {title}"
        )
        input(f"{Colors.GREEN}Press Enter to continue...{Colors.ENDC}")
    
    # 3. Show actual redaction
    print_header("3. Actual Redaction in Action")
    
    print("Now let's see actual data redaction:\n")
    
    print(f"{Colors.BOLD}Original Data:{Colors.ENDC}")
    with open("demo/customer_data.json") as f:
        print(json.dumps(json.load(f), indent=2))
    
    input(f"\n{Colors.GREEN}Press Enter to see redacted versions...{Colors.ENDC}")
    
    for title, agent_file, _ in scenarios[2:3]:  # Just show user redaction
        print(f"\n{Colors.BOLD}Redacted for {title}:{Colors.ENDC}")
        run_command(
            f"vault redact demo/customer_data.json demo/policy.json -a {agent_file}",
            f"Redacting data for {title}"
        )
    
    # 4. Show security improvements
    print_header("4. Security Improvements Demo")
    
    print("Our security hardening prevents common attacks:\n")
    
    security_demos = [
        ("SQL Injection Protection", 
         {"role": "admin' OR '1'='1", "trustScore": 100},
         "sql_injection.json"),
        ("Type Confusion Prevention", 
         {"role": "admin", "trustScore": True},
         "bool_trust.json"),
        ("Special Values Protection", 
         {"role": "admin", "trustScore": "Infinity"},
         "infinity.json"),
    ]
    
    for attack_name, payload, filename in security_demos:
        print(f"{Colors.BOLD}{attack_name}:{Colors.ENDC}")
        
        with open(f"demo/{filename}", "w") as f:
            json.dump(payload, f)
        
        print(f"Attempting: {json.dumps(payload)}")
        result = run_command(
            f"vault simulate -a demo/{filename} -p demo/policy.json 2>&1",
            "This should be rejected"
        )
        
        if result != 0:
            print(f"{Colors.GREEN}Attack blocked!{Colors.ENDC}\n")
        else:
            print(f"{Colors.RED}Attack not blocked!{Colors.ENDC}\n")
    
    # 5. Performance note
    print_header("5. Performance & Scale")
    
    print(f"""{Colors.BOLD}Marvis Vault is built for production:{Colors.ENDC}
    
    - Validates inputs in <1ms for typical payloads
    - Protects against DoS with size/depth limits  
    - Thread-safe for concurrent operations
    - Comprehensive audit logging for compliance
    
    Perfect for LLM applications where you need to:
    - Protect sensitive data in prompts
    - Implement role-based access control
    - Maintain compliance (GDPR, HIPAA, etc.)
    - Audit all data access decisions
    """)
    
    # 6. Run comprehensive tests
    print_header("6. Comprehensive Security Test Suite")
    
    response = input(f"{Colors.YELLOW}Run full security test suite? (y/n): {Colors.ENDC}")
    if response.lower() == 'y':
        print("\nRunning security tests...\n")
        subprocess.run([sys.executable, "examples/test_security_comprehensive.py"])
    
    # Cleanup
    print_header("Demo Complete!")
    
    print(f"""{Colors.BOLD}Key Takeaways:{Colors.ENDC}
    
    1. {Colors.CYAN}Policy-based redaction{Colors.ENDC} - Define who sees what with simple rules
    2. {Colors.CYAN}Security-first design{Colors.ENDC} - Protected against common attacks
    3. {Colors.CYAN}Easy integration{Colors.ENDC} - Simple CLI and Python SDK
    4. {Colors.CYAN}Production ready{Colors.ENDC} - Fast, safe, and auditable
    
    {Colors.BOLD}Get Started:{Colors.ENDC}
    - Docs: ./docs/01_index.md
    - Templates: vault/templates/
    - Examples: examples/
    
    {Colors.GREEN}Thank you for trying Marvis Vault!{Colors.ENDC}
    """)
    
    # Cleanup demo files
    response = input(f"\n{Colors.YELLOW}Clean up demo files? (y/n): {Colors.ENDC}")
    if response.lower() == 'y':
        import shutil
        shutil.rmtree("demo")
        print("Demo files cleaned up.")

if __name__ == "__main__":
    main()