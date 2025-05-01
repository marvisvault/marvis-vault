from typing import Dict, Tuple, Any
import re
from enum import Enum, auto

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
    PAREN = auto()

class Token:
    """Represents a token in the condition string."""
    def __init__(self, type: TokenType, value: Any):
        self.type = type
        self.value = value

def _tokenize(condition: str) -> list[Token]:
    """Convert condition string into a list of tokens."""
    tokens = []
    i = 0
    while i < len(condition):
        char = condition[i]
        
        # Skip whitespace
        if char.isspace():
            i += 1
            continue
            
        # Handle operators
        if char in ['&', '|', '=', '!', '>', '<']:
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
                raise ValueError(f"Invalid operator at position {i}")
                
        # Handle parentheses
        elif char in ['(', ')']:
            tokens.append(Token(TokenType.PAREN, char))
            i += 1
            
        # Handle values (identifiers, numbers, strings)
        else:
            # Match identifiers, numbers, or strings
            if char.isalpha():
                # Match identifier
                match = re.match(r'[a-zA-Z_][a-zA-Z0-9_]*', condition[i:])
                if not match:
                    raise ValueError(f"Invalid identifier at position {i}")
                tokens.append(Token(TokenType.VALUE, match.group()))
                i += len(match.group())
            elif char.isdigit() or char == '-':
                # Match number
                match = re.match(r'-?\d+(\.\d+)?', condition[i:])
                if not match:
                    raise ValueError(f"Invalid number at position {i}")
                tokens.append(Token(TokenType.VALUE, float(match.group())))
                i += len(match.group())
            elif char == "'" or char == '"':
                # Match string
                quote = char
                i += 1
                start = i
                while i < len(condition) and condition[i] != quote:
                    i += 1
                if i >= len(condition):
                    raise ValueError(f"Unclosed string at position {start-1}")
                tokens.append(Token(TokenType.VALUE, condition[start:i]))
                i += 1
            else:
                raise ValueError(f"Unexpected character at position {i}")
                
    return tokens

def _evaluate_expression(tokens: list[Token], context: Dict[str, Any]) -> Tuple[bool, str]:
    """Evaluate a list of tokens using the provided context."""
    if not tokens:
        return True, "Empty condition"
        
    # Handle single value
    if len(tokens) == 1:
        if tokens[0].type != TokenType.VALUE:
            raise ValueError("Invalid expression")
        value = tokens[0].value
        if isinstance(value, str) and value in context:
            return bool(context[value]), f"Context value '{value}' is {bool(context[value])}"
        return bool(value), f"Value {value} is {bool(value)}"
        
    # Handle comparison
    if len(tokens) == 3 and tokens[1].type == TokenType.OPERATOR:
        left = tokens[0].value
        op = tokens[1].value
        right = tokens[2].value
        
        # Get left value from context if it's a string
        if isinstance(left, str) and left in context:
            left = context[left]
        elif isinstance(left, str):
            raise ValueError(f"Context key '{left}' not found")
            
        # Get right value from context if it's a string
        if isinstance(right, str) and right in context:
            right = context[right]
        elif isinstance(right, str):
            raise ValueError(f"Context key '{right}' not found")
            
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
    if len(tokens) >= 3 and tokens[1].type == TokenType.OPERATOR and tokens[1].value in [Operator.AND, Operator.OR]:
        left_result, left_explanation = _evaluate_expression([tokens[0]], context)
        right_result, right_explanation = _evaluate_expression(tokens[2:], context)
        
        if tokens[1].value == Operator.AND:
            result = left_result and right_result
            return result, f"({left_explanation}) AND ({right_explanation}) is {result}"
        else:  # OR
            result = left_result or right_result
            return result, f"({left_explanation}) OR ({right_explanation}) is {result}"
            
    raise ValueError("Invalid expression structure")

def evaluate_condition(condition: str, context: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Evaluate a condition string using the provided context.
    
    Args:
        condition: String containing the condition to evaluate
        context: Dictionary containing context values
        
    Returns:
        Tuple[bool, str]: (result, explanation)
        
    Raises:
        ValueError: If the condition is invalid or context keys are missing
    """
    try:
        tokens = _tokenize(condition)
        return _evaluate_expression(tokens, context)
    except Exception as e:
        raise ValueError(f"Failed to evaluate condition: {str(e)}") 