"""
Marvis Vault OSS - Programmable compliance SDK for redaction, audit, and policy-based masking
in agentic AI workflows.
"""

__version__ = "0.1.0"
__author__ = "Marvis Vault"
__license__ = "MIT"

# Optional: Expose commonly used functions at package level
from vault.sdk.redact import redact
from vault.sdk.unmask import unmask
from vault.sdk.audit import audit

__all__ = ["redact", "unmask", "audit"] 