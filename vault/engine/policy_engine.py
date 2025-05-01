from typing import Dict, List, Optional
from dataclasses import dataclass
from pathlib import Path
from .policy_parser import parse_policy, Policy
from .condition_evaluator import evaluate_condition

@dataclass
class EvaluationResult:
    """Result of a policy evaluation."""
    status: bool
    reason: str
    fields_to_mask: List[str]
    policy: Optional[Policy] = None

def evaluate(context: Dict[str, Any], policy_path: str) -> EvaluationResult:
    """
    Evaluate a policy against a context.
    
    Args:
        context: Dictionary containing context values (e.g. trustScore, role)
        policy_path: Path to the policy file (JSON or YAML)
        
    Returns:
        EvaluationResult: Result of the policy evaluation
        
    Raises:
        ValueError: If the policy is invalid or cannot be parsed
        FileNotFoundError: If the policy file doesn't exist
    """
    try:
        # Parse the policy
        policy = parse_policy(policy_path)
        
        # Evaluate each condition
        all_conditions_met = True
        reasons = []
        
        for condition in policy.conditions:
            # Convert condition object to string format
            condition_str = f"{condition.field} {condition.operator} {repr(condition.value)}"
            
            # Evaluate the condition
            result, explanation = evaluate_condition(condition_str, context)
            
            if not result:
                all_conditions_met = False
                reasons.append(f"Condition failed: {explanation}")
            else:
                reasons.append(f"Condition passed: {explanation}")
        
        # Determine which fields to mask
        fields_to_mask = []
        if not all_conditions_met:
            fields_to_mask = [field for field in context.keys()]
        
        # Build the final reason
        final_reason = "\n".join(reasons)
        if all_conditions_met:
            final_reason = f"All conditions passed:\n{final_reason}"
        else:
            final_reason = f"Some conditions failed:\n{final_reason}"
        
        return EvaluationResult(
            status=all_conditions_met,
            reason=final_reason,
            fields_to_mask=fields_to_mask,
            policy=policy
        )
        
    except Exception as e:
        return EvaluationResult(
            status=False,
            reason=f"Policy evaluation failed: {str(e)}",
            fields_to_mask=list(context.keys()),
            policy=None
        ) 