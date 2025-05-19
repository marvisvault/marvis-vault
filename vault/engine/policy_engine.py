"""
Policy engine for evaluating conditions against context.
"""

from typing import Any, Dict, List, Optional, Tuple, Union

from pydantic import BaseModel

from .condition_evaluator import evaluate_condition, InvalidConditionError
from .policy_parser import parse_policy

class EvaluationResult(BaseModel):
    """Result of policy evaluation."""
    success: bool
    reason: str
    fields: List[str] = []
    skipped_conditions: List[str] = []

def evaluate(context: Dict[str, Any], policy_path: str) -> EvaluationResult:
    """
    Evaluate a policy against a context.
    
    Args:
        context: Dictionary containing role, trustScore, etc.
        policy_path: Path to policy file
        
    Returns:
        EvaluationResult with success/failure and reason
    """
    # Parse policy
    policy = parse_policy(policy_path)
    
    # Check role
    if context.get("role") not in policy.unmask_roles:
        return EvaluationResult(
            success=False,
            reason=f"Role {context.get('role')} not in allowed roles: {policy.unmask_roles}",
            fields=policy.mask
        )
    
    # Track skipped conditions
    skipped_conditions = []
    
    # Evaluate conditions
    for condition in policy.conditions:
        try:
            success, explanation = evaluate_condition(condition, context)
            if not success:
                return EvaluationResult(
                    success=False,
                    reason=f"Condition failed: {explanation}",
                    fields=policy.mask,
                    skipped_conditions=skipped_conditions
                )
        except InvalidConditionError as e:
            # Log warning and skip invalid condition
            skipped_conditions.append(f"Skipped invalid condition '{condition}': {str(e)}")
            continue
        except Exception as e:
            return EvaluationResult(
                success=False,
                reason=f"Error evaluating condition '{condition}': {str(e)}",
                fields=policy.mask,
                skipped_conditions=skipped_conditions
            )
            
    return EvaluationResult(
        success=True,
        reason="All conditions passed",
        fields=[],  # No fields to mask when successful
        skipped_conditions=skipped_conditions
    ) 