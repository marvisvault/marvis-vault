"""
Policy parser for loading and validating policy files.
"""

from pathlib import Path
from typing import List, Union, Dict, Any, Set, Optional
import json
import yaml
from pydantic import BaseModel, Field

class Policy(BaseModel):
    """Represents a complete policy document."""
    mask: List[str] = Field(..., description="Fields to mask")
    unmask_roles: List[str] = Field(..., description="List of roles that can unmask data")
    conditions: List[str] = Field(..., description="List of conditions that must be met")
    name: Optional[str] = Field(None, description="Policy name")
    template_id: Optional[str] = Field(None, description="Template ID if policy is based on a template")

def load_policy(file_path: Union[str, Path]) -> Dict[str, Any]:
    """
    Load and validate a policy file.
    
    Args:
        file_path: Path to the policy file
        
    Returns:
        Dict containing the parsed policy
        
    Raises:
        FileNotFoundError: If the file doesn't exist
        ValueError: If the file format is invalid or policy validation fails
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
        
        # Validate using Pydantic model
        policy = Policy(**data)
        return policy.model_dump()
        
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON: {str(e)}")
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML: {str(e)}")
    except Exception as e:
        raise ValueError(f"Failed to parse policy: {str(e)}")

def parse_policy(file_path: Union[str, Path]) -> Policy:
    """
    Parse a policy file and return a Policy object.
    
    This is a wrapper around load_policy that returns the Pydantic model
    instead of a dict.
    """
    data = load_policy(file_path)
    return Policy(**data) 