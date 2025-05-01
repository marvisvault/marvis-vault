import json
import csv
from io import StringIO
from pathlib import Path
from typing import List, Dict, Any
import warnings

def get_default_log_path() -> Path:
    """Get the default path to the audit log file."""
    return Path("vault.log")

def validate_log_entry(entry: Dict[str, Any]) -> bool:
    """Validate a log entry has required fields."""
    required_fields = {"timestamp", "field", "agent", "result"}
    if not all(field in entry for field in required_fields):
        return False
    if "role" not in entry["agent"]:
        return False
    return True

def format_csv(entries: List[Dict[str, Any]]) -> str:
    """Format log entries as CSV."""
    output = StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(["timestamp", "field", "role", "result"])
    
    # Write entries
    for entry in entries:
        writer.writerow([
            entry["timestamp"],
            entry["field"],
            entry["agent"]["role"],
            entry["result"]
        ])
    
    return output.getvalue()

def format_json(entries: List[Dict[str, Any]]) -> str:
    """Format log entries as JSON array."""
    return json.dumps(entries, indent=2)

def export_log(log_path: str = None, output_format: str = "csv") -> str:
    """
    Export audit log entries to CSV or JSON format.
    
    Args:
        log_path: Path to the log file (defaults to vault.log)
        output_format: Output format ("csv" or "json")
        
    Returns:
        Formatted log entries as a string
        
    Raises:
        ValueError: If output_format is not supported
        FileNotFoundError: If log file does not exist
    """
    # Validate output format
    if output_format not in {"csv", "json"}:
        raise ValueError(f"Unsupported output format: {output_format}")
    
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
    
    # Format entries
    if output_format == "csv":
        return format_csv(entries)
    else:
        return format_json(entries) 