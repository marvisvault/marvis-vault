import re
import json
import unicodedata
from typing import Dict, Any, Optional, Union, List, Tuple, Set
from datetime import datetime, timezone
from vault.engine.policy_engine import evaluate

class RedactionError(Exception):
    """Custom exception for redaction failures."""
    def __init__(self, field: str, message: str):
        self.field = field
        self.message = message
        super().__init__(f"Redaction failed for field '{field}': {message}")

class RedactionResult:
    """Structured result of redaction operation."""
    def __init__(self, content: str, is_json: bool = False):
        self.content = content
        self.is_json = is_json
        self.audit_log = []
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.redacted_fields: Set[str] = set()
        self.line_mapping: Dict[int, List[Dict[str, Any]]] = {}

    def add_audit_entry(self, field: str, reason: str, value: Optional[str] = None, 
                       line_number: Optional[int] = None, context: Optional[Dict[str, Any]] = None):
        """Add an entry to the audit log with line number and context."""
        entry = {
            "timestamp": self.timestamp,
            "field": field,
            "reason": reason,
            "original_value": value,
            "line_number": line_number,
            "context": context
        }
        self.audit_log.append(entry)
        self.redacted_fields.add(field)
        
        if line_number is not None:
            if line_number not in self.line_mapping:
                self.line_mapping[line_number] = []
            self.line_mapping[line_number].append(entry)

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary format."""
        return {
            "content": self.content,
            "is_json": self.is_json,
            "audit_log": self.audit_log,
            "timestamp": self.timestamp,
            "redacted_fields": list(self.redacted_fields),
            "line_mapping": self.line_mapping
        }

def normalize_policy_keys(policy: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize policy keys to support both snake_case and camelCase."""
    key_map = {
        "unmask_roles": "unmaskRoles",
        "unmaskRoles": "unmaskRoles",
        "mask": "mask",
        "conditions": "conditions",
        "field_conditions": "fieldConditions",
        "field_aliases": "fieldAliases"
    }
    normalized = {}
    for key, value in policy.items():
        norm_key = key_map.get(key)
        if norm_key:
            normalized[norm_key] = value
    return normalized

def validate_policy(policy: Dict[str, Any]) -> bool:
    """Validate that the policy has required fields and correct types."""
    if not isinstance(policy, dict):
        return False

    policy = normalize_policy_keys(policy)

    required_fields = {"mask", "unmaskRoles", "conditions"}
    if not all(field in policy for field in required_fields):
        return False

    if not all(isinstance(policy[field], list) for field in required_fields):
        return False

    if not all(isinstance(policy[field], list) for field in required_fields):
        return False

    # Validate field conditions if present
    if "fieldConditions" in policy:
        if not isinstance(policy["fieldConditions"], dict):
            return False
        for field, condition in policy["fieldConditions"].items():
            if not isinstance(condition, (str, list)):
                return False

    # Validate field aliases if present
    if "fieldAliases" in policy:
        if not isinstance(policy["fieldAliases"], dict):
            return False
        for field, aliases in policy["fieldAliases"].items():
            if not isinstance(aliases, list):
                return False

    return True

def detect_format(content: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """Detect if content is JSON and parse if possible."""
    try:
        parsed = json.loads(content)
        return True, parsed
    except json.JSONDecodeError:
        return False, None

def create_field_patterns(fields: List[str], aliases: Optional[Dict[str, List[str]]] = None) -> Dict[str, re.Pattern]:
    """Create case-insensitive regex patterns for each field with proper escaping."""
    patterns = {}
    for field in fields:
        # Handle wildcard patterns
        if "*" in field:
            base = field.replace("*", ".*")
            pattern = rf"{base}\s*[:=]\s*([^\n,}}]+(?:\n[^\n,}}]+)*)"
        else:
            # Normalize field name to NFC form
            normalized_field = unicodedata.normalize('NFC', field)
            escaped_field = re.escape(normalized_field)
            pattern = rf"{escaped_field}\s*[:=]\s*([^\n,}}]+(?:\n[^\n,}}]+)*)"
        
        patterns[field] = re.compile(pattern, re.IGNORECASE | re.DOTALL)
        
        # Add patterns for aliases if they exist
        if aliases and field in aliases:
            for alias in aliases[field]:
                alias_pattern = rf"{re.escape(alias)}\s*[:=]\s*([^\n,}}]+(?:\n[^\n,}}]+)*)"
                patterns[f"{field}__{alias}"] = re.compile(alias_pattern, re.IGNORECASE | re.DOTALL)
    
    return patterns

def redact_json(data: Any, policy: Dict[str, Any], result: RedactionResult, path: str = "") -> Any:
    """Recursively redact sensitive fields in JSON data."""
    if isinstance(data, dict):
        redacted = {}
        for key, value in data.items():
            current_path = f"{path}.{key}" if path else key
            
            # Check if key matches any mask pattern
            should_mask = False
            matched_field = None
            
            for mask_pattern in policy["mask"]:
                if "*" in mask_pattern:
                    if re.match(mask_pattern.replace("*", ".*"), key):
                        should_mask = True
                        matched_field = mask_pattern
                        break
                elif key.lower() == mask_pattern.lower():
                    should_mask = True
                    matched_field = mask_pattern
                    break
                
                # Check aliases
                if "fieldAliases" in policy and mask_pattern in policy["fieldAliases"]:
                    for alias in policy["fieldAliases"][mask_pattern]:
                        if key.lower() == alias.lower():
                            should_mask = True
                            matched_field = mask_pattern
                            break

            if should_mask and matched_field:
                # Check field-specific conditions if they exist
                field_conditions = policy.get("fieldConditions", {}).get(matched_field)
                if field_conditions:
                    if not evaluate({"conditions": field_conditions}, data):
                        redacted[key] = value
                        continue

                redacted[key] = "[REDACTED]"
                result.add_audit_entry(
                    matched_field,
                    "Field masked by policy",
                    str(value),
                    context={"path": current_path}
                )
            else:
                redacted[key] = redact_json(value, policy, result, current_path)
        return redacted
    elif isinstance(data, list):
        return [redact_json(item, policy, result, f"{path}[{i}]") for i, item in enumerate(data)]
    else:
        return data

def redact_text(text: str, policy: Dict[str, Any], result: RedactionResult) -> str:
    """Redact sensitive fields in plain text with line-by-line tracking."""
    patterns = create_field_patterns(policy["mask"], policy.get("fieldAliases"))
    lines = text.splitlines()
    redacted_lines = []
    
    for line_num, line in enumerate(lines, 1):
        redacted_line = line
        line_modified = False
        
        for field, pattern in patterns.items():
            matches = pattern.findall(line)
            if matches:
                for match in matches:
                    # Extract the actual field name (without alias suffix)
                    base_field = field.split("__")[0]
                    result.add_audit_entry(
                        base_field,
                        "Field masked in text",
                        match,
                        line_num,
                        {"line": line.strip()}
                    )
                redacted_line = pattern.sub(f"{field.split('__')[0]}: [REDACTED]", redacted_line)
                line_modified = True
        
        redacted_lines.append(redacted_line)
    
    return "\n".join(redacted_lines)

def redact(content: str, policy: Dict[str, Any], context: Optional[Dict[str, Any]] = None, result: Optional[RedactionResult] = None) -> RedactionResult:
    """
    Redact sensitive fields from content based on policy rules.

    Args:
        content: The input content to redact (JSON or text)
        policy: The policy dictionary containing mask rules
        context: Optional context for policy evaluation
        result: Optional pre-constructed RedactionResult for external audit stream injection

    Returns:
        RedactionResult containing redacted content and audit log

    Raises:
        RedactionError: If redaction fails for any required field
    """
    if not validate_policy(policy):
        raise RedactionError("policy", "Invalid policy structure")

    # Use the passed-in result or create a new one
    if result is None:
        result = RedactionResult(content)
    else:
        # Reset relevant fields to ensure clean processing
        result.content = content
        result.is_json = False
        result.audit_log.clear()
        result.redacted_fields.clear()
        result.line_mapping.clear()
        result.timestamp = datetime.now(timezone.utc).isoformat()

    # Evaluate global conditions if context is provided
    if context is not None:
        eval_result = evaluate(policy, context)
        if not eval_result.get("status", False):
            return result  # Policy condition not met — no redaction

    # Detect format and apply appropriate redaction
    is_json, parsed_json = detect_format(content)
    result.is_json = is_json

    if is_json and parsed_json is not None:
        try:
            redacted_json = redact_json(parsed_json, policy, result)
            result.content = json.dumps(redacted_json)
        except Exception as e:
            result.content = redact_text(content, policy, result)
            result.add_audit_entry("system", f"JSON redaction failed, fell back to text: {str(e)}")
    else:
        result.content = redact_text(content, policy, result)
        result.add_audit_entry("system", "JSON redaction failed, fell back to text: malformed JSON input", content)

    return result

