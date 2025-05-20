"""
Policy engine for evaluating conditions against context.
"""

from typing import Any, Dict, List, Optional, Tuple, Union, NamedTuple

from pydantic import BaseModel

from .condition_evaluator import evaluate_condition, InvalidConditionError
from .policy_parser import parse_policy

class ConditionResult(NamedTuple):
    """Result of a single condition evaluation."""
    condition: str
    success: bool
    explanation: str

class EvaluationResult(BaseModel):
    """Result of policy evaluation."""
    success: bool
    reason: str
    fields: List[str] = []
    skipped_conditions: List[str] = []
    condition_results: List[ConditionResult] = []
    passed_conditions: List[str] = []
    failed_conditions: List[str] = []

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
    
    # Check role - if in unmask_roles, skip condition evaluation entirely
    if context.get("role") in policy.unmask_roles:
        return EvaluationResult(
            success=True,
            reason=f"Role {context.get('role')} is in unmask_roles - skipping condition evaluation",
            fields=[],
            condition_results=[],
            passed_conditions=[],
            failed_conditions=[]
        )
    
    # Track results
    skipped_conditions = []
    condition_results = []
    passed_conditions = []
    failed_conditions = []
    
    # Evaluate all conditions
    for condition in policy.conditions:
        try:
            success, explanation = evaluate_condition(condition, context)
            result = ConditionResult(condition, success, explanation)
            condition_results.append(result)
            
            if success:
                passed_conditions.append(condition)
            else:
                failed_conditions.append(condition)
                
        except InvalidConditionError as e:
            # Log warning and skip invalid condition
            skipped_conditions.append(f"Skipped invalid condition '{condition}': {str(e)}")
            continue
        except Exception as e:
            return EvaluationResult(
                success=False,
                reason=f"Error evaluating condition '{condition}': {str(e)}",
                fields=policy.mask,
                skipped_conditions=skipped_conditions,
                condition_results=condition_results,
                passed_conditions=passed_conditions,
                failed_conditions=failed_conditions
            )
    
    # Fields should only be masked if ALL conditions fail
    should_mask = len(passed_conditions) == 0 and len(policy.conditions) > 0
    
    # Build result message
    if len(passed_conditions) > 0:
        reason = f"{len(passed_conditions)} of {len(policy.conditions)} conditions passed"
    elif len(policy.conditions) == 0:
        reason = "No conditions to evaluate"
    else:
        reason = "All conditions failed"
    
    return EvaluationResult(
        success=not should_mask,
        reason=reason,
        fields=policy.mask if should_mask else [],
        skipped_conditions=skipped_conditions,
        condition_results=condition_results,
        passed_conditions=passed_conditions,
        failed_conditions=failed_conditions
    ) 