"""
Condition evaluator for policy engine.
"""

from typing import Dict, Tuple, Any, List, Optional, Union, Set
import re
from enum import Enum, auto

class ConditionValidationError(ValueError):
    """Custom exception for condition validation errors."""
    pass

class InvalidConditionError(ValueError):
    """Custom exception for invalid or missing conditions."""
    pass

class CircularReferenceError(ValueError):
    """Custom exception for circular references in conditions."""
    def __init__(self, field: str, chain: List[str]):
        self.field = field
        self.chain = chain
        super().__init__(f"Circular reference detected: {' -> '.join(chain + [field])}")

class Operator(Enum):
    """Supported operators for condition evaluation."""
    AND = auto()
    OR = auto()
    EQUALS = auto()
    NOT_EQUALS = auto()
    GREATER_THAN = auto()
    LESS_THAN = auto()

class TokenType(Enum):
    """Types of tokens in the condition string."""
    OPERATOR = auto()
    VALUE = auto()
    LITERAL = auto()
    PAREN = auto()

class Token:
    """Represents a token in the condition string."""
    def __init__(self, type: TokenType, value: Any):
        self.type = type
        self.value = value

def _validate_numeric(value: Any, field_name: str) -> float:
    """
    Validate that a value is numeric and within bounds.
    
    Args:
        value: The value to validate
        field_name: Name of the field being validated
        
    Returns:
        float: The validated numeric value
        
    Raises:
        ConditionValidationError: If value is invalid or out of bounds
    """
    if value is None:
        raise ConditionValidationError(f"Field '{field_name}' cannot be null")
        
    # Only accept actual numbers, not strings that can be coerced
    if not isinstance(value, (int, float)):
        raise ConditionValidationError(
            f"Field '{field_name}' must be numeric, got {type(value)}"
        )
        
    # Convert to float for consistent comparison
    num_value = float(value)
    
    # Add bounds check for trustScore
    if field_name == "trustScore" and not (0 <= num_value <= 100):
        raise ConditionValidationError(
            f"Field '{field_name}' must be between 0 and 100 inclusive"
        )
        
    return num_value

def _tokenize(condition: str) -> list[Token]:
    """
    Convert condition string into a list of tokens.
    
    Args:
        condition: The condition string to tokenize
        
    Returns:
        list[Token]: List of parsed tokens
        
    Raises:
        ConditionValidationError: If token limit exceeded or invalid tokens found
    """
    MAX_TOKENS = 100
    tokens = []
    i = 0
    
    while i < len(condition):
        if len(tokens) >= MAX_TOKENS:
            raise ConditionValidationError(
                f"Condition exceeds maximum token limit of {MAX_TOKENS}"
            )
            
        char = condition[i]
        
        # Skip whitespace
        if char.isspace():
            i += 1
            continue
            
        # Handle operators
        if char in ['&', '|', '=', '!', '>', '<']:
            # Check for invalid operator sequences
            if i + 1 < len(condition):
                next_char = condition[i + 1]
                if char in ['>', '<'] and next_char in ['>', '<']:
                    raise ConditionValidationError(
                        f"Invalid operator sequence '{char}{next_char}' at position {i}"
                    )
                    
            if i + 1 < len(condition) and condition[i:i+2] == '&&':
                tokens.append(Token(TokenType.OPERATOR, Operator.AND))
                i += 2
            elif i + 1 < len(condition) and condition[i:i+2] == '||':
                tokens.append(Token(TokenType.OPERATOR, Operator.OR))
                i += 2
            elif i + 1 < len(condition) and condition[i:i+2] == '==':
                tokens.append(Token(TokenType.OPERATOR, Operator.EQUALS))
                i += 2
            elif i + 1 < len(condition) and condition[i:i+2] == '!=':
                tokens.append(Token(TokenType.OPERATOR, Operator.NOT_EQUALS))
                i += 2
            elif char == '>':
                tokens.append(Token(TokenType.OPERATOR, Operator.GREATER_THAN))
                i += 1
            elif char == '<':
                tokens.append(Token(TokenType.OPERATOR, Operator.LESS_THAN))
                i += 1
            else:
                raise ConditionValidationError(f"Invalid operator at position {i}")
                
        # Handle parentheses
        elif char in ['(', ')']:
            tokens.append(Token(TokenType.PAREN, char))
            i += 1
            
        # Handle values (identifiers, numbers, strings)
        else:
            # Match identifiers, numbers, or strings
            if char.isalpha():
                # Match identifier - must be full match
                match = re.match(r'[a-zA-Z_][a-zA-Z0-9_]*', condition[i:])
                if not match:
                    raise ConditionValidationError(f"Invalid identifier at position {i}")
                tokens.append(Token(TokenType.VALUE, match.group()))
                i += len(match.group())
            elif char.isdigit() or char == '-':
                # Match number - must be full match
                match = re.match(r'-?\d+(\.\d+)?', condition[i:])
                if not match:
                    raise ConditionValidationError(f"Invalid number at position {i}")
                tokens.append(Token(TokenType.VALUE, float(match.group())))
                i += len(match.group())
            elif char == "'" or char == '"':
                # Match string literal
                quote = char
                i += 1
                start = i
                while i < len(condition) and condition[i] != quote:
                    i += 1
                if i >= len(condition):
                    raise ConditionValidationError(f"Unclosed string at position {start-1}")
                tokens.append(Token(TokenType.LITERAL, condition[start:i]))
                i += 1
            else:
                raise ConditionValidationError(f"Unexpected character at position {i}")
                
    return tokens

def _find_matching_paren(tokens: List[Token], start: int) -> int:
    """Find the matching closing parenthesis."""
    count = 1
    i = start + 1
    while i < len(tokens):
        if tokens[i].type == TokenType.PAREN:
            if tokens[i].value == '(':
                count += 1
            elif tokens[i].value == ')':
                count -= 1
                if count == 0:
                    return i
        i += 1
    raise ValueError("Unmatched parenthesis")

def _evaluate_expression(
    tokens: List[Token], 
    context: Dict[str, Any],
    visited_fields: Optional[Set[str]] = None,
    depth: int = 0
) -> Tuple[bool, str]:
    """
    Evaluate a list of tokens using the provided context.
    
    Args:
        tokens: List of tokens to evaluate
        context: Dictionary containing context values
        visited_fields: Set of fields already visited in this evaluation chain
        depth: Current recursion depth
        
    Returns:
        Tuple[bool, str]: (result, explanation)
        
    Raises:
        CircularReferenceError: If a circular reference is detected
        ValueError: If the condition is invalid or context keys are missing
    """
    MAX_RECURSION_DEPTH = 20
    
    if depth > MAX_RECURSION_DEPTH:
        raise ValueError(f"Maximum recursion depth of {MAX_RECURSION_DEPTH} exceeded")
        
    if visited_fields is None:
        visited_fields = set()
        
    if not tokens:
        return True, "Empty condition"
        
    # Handle parentheses
    if tokens[0].type == TokenType.PAREN and tokens[0].value == '(':
        end = _find_matching_paren(tokens, 0)
        if end == len(tokens) - 1:
            return _evaluate_expression(tokens[1:end], context, visited_fields, depth + 1)
            
    # Handle single value
    if len(tokens) == 1:
        if tokens[0].type not in [TokenType.VALUE, TokenType.LITERAL]:
            raise ValueError("Invalid expression")
        value = tokens[0].value
        if tokens[0].type == TokenType.VALUE and isinstance(value, str):
            if value in visited_fields:
                raise CircularReferenceError(value, list(visited_fields))
            if value in context:
                visited_fields.add(value)
                return bool(context[value]), f"Context value '{value}' is {bool(context[value])}"
            raise ValueError(f"Context key '{value}' not found")
        return bool(value), f"Value {value} is {bool(value)}"
        
    # Handle comparison
    if len(tokens) == 3 and tokens[1].type == TokenType.OPERATOR:
        left = tokens[0].value
        op = tokens[1].value
        right = tokens[2].value
        
        # Get left value from context if it's a context variable
        if tokens[0].type == TokenType.VALUE and isinstance(left, str):
            if left in visited_fields:
                raise CircularReferenceError(left, list(visited_fields))
            if left in context:
                visited_fields.add(left)
                left = context[left]
            else:
                raise ValueError(f"Context key '{left}' not found")
            
        # Get right value from context if it's a context variable
        if tokens[2].type == TokenType.VALUE and isinstance(right, str):
            if right in visited_fields:
                raise CircularReferenceError(right, list(visited_fields))
            if right in context:
                visited_fields.add(right)
                right = context[right]
            
        # Validate numeric comparisons
        if op in [Operator.GREATER_THAN, Operator.LESS_THAN]:
            try:
                left = _validate_numeric(left, tokens[0].value)
                right = _validate_numeric(right, tokens[2].value)
            except ValueError as e:
                raise ValueError(f"Invalid comparison: {str(e)}")
            
        # Perform comparison
        if op == Operator.EQUALS:
            result = left == right
            return result, f"{left} == {right} is {result}"
        elif op == Operator.NOT_EQUALS:
            result = left != right
            return result, f"{left} != {right} is {result}"
        elif op == Operator.GREATER_THAN:
            result = left > right
            return result, f"{left} > {right} is {result}"
        elif op == Operator.LESS_THAN:
            result = left < right
            return result, f"{left} < {right} is {result}"
            
    # Handle AND/OR operations
    for i in range(len(tokens)):
        if tokens[i].type == TokenType.OPERATOR and tokens[i].value in [Operator.AND, Operator.OR]:
            left_result, left_explanation = _evaluate_expression(
                tokens[:i], context, visited_fields.copy(), depth + 1
            )
            right_result, right_explanation = _evaluate_expression(
                tokens[i+1:], context, visited_fields.copy(), depth + 1
            )
            
            if tokens[i].value == Operator.AND:
                result = left_result and right_result
                return result, f"({left_explanation}) AND ({right_explanation}) is {result}"
            else:  # OR
                result = left_result or right_result
                return result, f"({left_explanation}) OR ({right_explanation}) is {result}"
                
    raise ValueError("Invalid expression structure")

# JS-compatible condition fix: Add normalization function
def normalize_condition(condition: str) -> str:
    """
    Normalize JavaScript-style condition syntax to Python-style.
    
    Args:
        condition: The condition string to normalize
        
    Returns:
        str: The normalized condition string
        
    Example:
        "trustScore > 85 && role !== 'auditor'"
        -> "trustScore > 85 and role != 'auditor'"
    """
    if not condition or not isinstance(condition, str):
        return condition
        
    # Save string literals to prevent modifying their contents
    literals = {}
    def save_literal(match):
        key = f"__STR_LIT_{len(literals)}__"
        literals[key] = match.group(0)
        return key
    
    # Save string literals
    condition = re.sub(r"'[^']*'|\"[^\"]*\"", save_literal, condition)
    
    # Normalize operators
    condition = re.sub(r'(?<!!)===', '==', condition)  # === to ==
    condition = re.sub(r'!==', '!=', condition)        # !== to !=
    condition = re.sub(r'(?<![=!<>])\|\|(?![=|])', ' or ', condition)  # || to or
    condition = re.sub(r'(?<![=!<>])&&(?![&])', ' and ', condition)    # && to and
    condition = re.sub(r'(?<![\w!])!(?![=\w])', 'not ', condition)     # ! to not, except !=
    
    # Restore string literals
    for key, value in literals.items():
        condition = condition.replace(key, value)
        
    return condition

def evaluate_condition(
    condition: str, 
    context: Dict[str, Any],
    visited_fields: Optional[Set[str]] = None
) -> Tuple[bool, str]:
    """
    Evaluate a condition string using the provided context.
    
    Args:
        condition: String containing the condition to evaluate
        context: Dictionary containing context values
        visited_fields: Set of fields already visited in this evaluation chain
        
    Returns:
        Tuple[bool, str]: (result, explanation)
        
    Raises:
        CircularReferenceError: If a circular reference is detected
        InvalidConditionError: If the condition is missing, empty or invalid
        ValueError: If the condition is invalid or context keys are missing
    """
    # Validate condition
    if not condition:
        raise InvalidConditionError("Condition cannot be empty or None")
    if not isinstance(condition, str):
        raise InvalidConditionError(f"Condition must be a string, got {type(condition)}")
    if condition.isspace():
        raise InvalidConditionError("Condition cannot be whitespace only")
        
    # JS-compatible condition fix: Normalize condition before evaluation
    original_condition = condition
    try:
        condition = normalize_condition(condition)
        tokens = _tokenize(condition)
        if not tokens:
            raise InvalidConditionError("Condition produced no valid tokens")
        return _evaluate_expression(tokens, context, visited_fields)
    except CircularReferenceError:
        raise
    except InvalidConditionError:
        raise
    except Exception as e:
        # Include original condition in error message
        raise ValueError(f"Failed to evaluate condition '{original_condition}': {str(e)}") 