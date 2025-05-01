import json
from collections import Counter
from pathlib import Path
from typing import Dict, Any, List, Tuple
import warnings

def get_default_log_path() -> Path:
    """Get the default path to the audit log file."""
    return Path("vault.log")

def validate_log_entry(entry: Dict[str, Any]) -> bool:
    """Validate a log entry has required fields."""
    required_fields = {"field", "agent", "result"}
    if not all(field in entry for field in required_fields):
        return False
    if "role" not in entry["agent"]:
        return False
    return True

def count_field_access(entries: List[Dict[str, Any]]) -> Dict[str, int]:
    """Count field access frequency."""
    fields = [entry["field"] for entry in entries]
    return dict(Counter(fields).most_common())

def count_role_frequency(entries: List[Dict[str, Any]]) -> Dict[str, int]:
    """Count role frequency."""
    roles = [entry["agent"]["role"] for entry in entries]
    return dict(Counter(roles).most_common())

def count_action_results(entries: List[Dict[str, Any]]) -> Tuple[int, int]:
    """Count masked and unmasked actions."""
    mask_count = sum(1 for entry in entries if entry["result"] == "masked")
    unmask_count = sum(1 for entry in entries if entry["result"] == "unmasked")
    return mask_count, unmask_count

def get_role_field_patterns(entries: List[Dict[str, Any]]) -> Dict[str, Dict[str, int]]:
    """Get role → field access patterns."""
    patterns = {}
    for entry in entries:
        role = entry["agent"]["role"]
        field = entry["field"]
        if role not in patterns:
            patterns[role] = {}
        patterns[role][field] = patterns[role].get(field, 0) + 1
    
    # Sort patterns by frequency
    for role in patterns:
        patterns[role] = dict(sorted(
            patterns[role].items(),
            key=lambda x: x[1],
            reverse=True
        ))
    
    return patterns

def generate_trust_report(log_path: str = None) -> Dict[str, Any]:
    """
    Generate a trust report from audit log entries.
    
    Args:
        log_path: Path to the log file (defaults to vault.log)
        
    Returns:
        Dictionary containing trust report statistics
        
    Raises:
        FileNotFoundError: If log file does not exist
    """
    # Get log path
    path = Path(log_path) if log_path else get_default_log_path()
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {path}")
    
    # Read and parse log entries
    entries = []
    with path.open() as f:
        for line in f:
            try:
                entry = json.loads(line)
                if validate_log_entry(entry):
                    entries.append(entry)
                else:
                    warnings.warn(f"Skipping entry missing required fields: {line.strip()}")
            except json.JSONDecodeError:
                warnings.warn(f"Skipping malformed JSON line: {line.strip()}")
    
    # Generate report
    report = {
        "most_accessed_fields": count_field_access(entries),
        "most_frequent_roles": count_role_frequency(entries),
        "role_field_patterns": get_role_field_patterns(entries)
    }
    
    # Add action counts
    mask_count, unmask_count = count_action_results(entries)
    report["mask_count"] = mask_count
    report["unmask_count"] = unmask_count
    
    return report 