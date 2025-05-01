import os
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any

def get_log_path() -> Path:
    """Get the path to the audit log file."""
    return Path(os.getenv("VAULT_LOG_PATH", "vault.log"))

def validate_agent(agent: Dict[str, Any]) -> None:
    """Validate the agent dictionary has required keys."""
    required_keys = {"role", "trustScore"}
    missing_keys = required_keys - set(agent.keys())
    if missing_keys:
        raise ValueError(f"Agent missing required keys: {missing_keys}")

def format_timestamp() -> str:
    """Get current timestamp in ISO 8601 format."""
    return datetime.utcnow().isoformat() + "Z"

def log_event(action: str, field: str, agent: Dict[str, Any], result: str) -> None:
    """
    Log an audit event to the audit log file.
    
    Args:
        action: The action performed (e.g., "redact", "unmask", "simulate")
        field: The field affected (e.g., "email", "ssn")
        agent: Dictionary containing agent information (must include role and trustScore)
        result: The result of the action (e.g., "masked", "unmasked")
        
    Raises:
        ValueError: If agent is missing required keys
        IOError: If log file cannot be written
    """
    # Validate agent
    validate_agent(agent)
    
    # Create log entry
    log_entry = {
        "timestamp": format_timestamp(),
        "action": action,
        "field": field,
        "agent": agent,
        "result": result
    }
    
    # Get log path
    log_path = get_log_path()
    
    try:
        # Ensure parent directory exists
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Append log entry
        with log_path.open("a") as f:
            json.dump(log_entry, f)
            f.write("\n")
            
    except Exception as e:
        raise IOError(f"Failed to write to audit log: {str(e)}") 