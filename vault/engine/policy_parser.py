from pathlib import Path
from typing import List, Union, Dict, Any
import json
import yaml
from pydantic import BaseModel, Field, validator

class PolicyCondition(BaseModel):
    """Represents a single condition in a policy."""
    field: str
    operator: str
    value: Any

class Policy(BaseModel):
    """Represents a complete policy document."""
    mask: str = Field(..., description="The pattern to use for masking")
    unmask_roles: List[str] = Field(..., description="List of roles that can unmask data")
    conditions: List[PolicyCondition] = Field(..., description="List of conditions that must be met")

    @validator('unmask_roles')
    def validate_unmask_roles(cls, v):
        if not v:
            raise ValueError("unmask_roles cannot be empty")
        return v

    @validator('conditions')
    def validate_conditions(cls, v):
        if not v:
            raise ValueError("conditions cannot be empty")
        return v

def parse_policy(file_path: Union[str, Path]) -> Policy:
    """
    Parse a policy file (JSON or YAML) and return a validated Policy object.
    
    Args:
        file_path: Path to the policy file
        
    Returns:
        Policy: Validated policy object
        
    Raises:
        ValueError: If the file format is invalid or required fields are missing
        FileNotFoundError: If the file doesn't exist
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Policy file not found: {file_path}")
    
    try:
        content = path.read_text()
        if path.suffix.lower() in ['.json']:
            data = json.loads(content)
        elif path.suffix.lower() in ['.yaml', '.yml']:
            data = yaml.safe_load(content)
        else:
            raise ValueError(f"Unsupported file format: {path.suffix}")
        
        return Policy(**data)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON: {str(e)}")
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML: {str(e)}")
    except Exception as e:
        raise ValueError(f"Failed to parse policy: {str(e)}") 