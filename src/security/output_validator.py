"""
Output Validator - Sensitive Data Leakage Detection

This module scans LLM outputs for accidental exposure of sensitive information
like API keys, database credentials, internal URLs, and personally identifiable
information (PII).

Part of BidDeed.AI 6-Layer Security Architecture - Layer 3
"""

import re
from typing import List, Dict, Optional, Set
from dataclasses import dataclass
from datetime import datetime


@dataclass
class SensitiveMatch:
    """Represents a detected sensitive data pattern."""
    pattern_type: str
    matched_text: str
    position: tuple
    severity: str
    context: str  # Surrounding text


@dataclass
class OutputValidationResult:
    """Result of output validation scan."""
    is_safe: bool
    violations: List[SensitiveMatch]
    sanitized_output: str
    original_length: int
    redacted_count: int
    timestamp: str


class OutputValidator:
    """
    Detect and redact sensitive information in LLM outputs.
    
    Protects against:
    - API key leakage
    - Database credential exposure
    - Internal URL disclosure
    - JWT token leakage
    - PII exposure (SSN, credit cards)
    - Source code disclosure
    """
    
    # Pattern definitions with severity levels
    SENSITIVE_PATTERNS = [
        # Infrastructure
        (r'supabase\.co', 'Supabase URL', 'HIGH'),
        (r'[a-z0-9]{20,}\.supabase\.co', 'Supabase Project URL', 'CRITICAL'),
        
        # Authentication tokens
        (r'eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+', 'JWT Token', 'CRITICAL'),
        (r'\bservice_role\b', 'Supabase Service Role Keyword', 'HIGH'),
        (r'\banon_key\b', 'Supabase Anon Key Keyword', 'MEDIUM'),
        
        # API Keys (generic patterns)
        (r'\b[A-Z0-9]{32,}\b', 'Potential API Key', 'HIGH'),
        (r'ghp_[A-Za-z0-9]{36}', 'GitHub Personal Access Token', 'CRITICAL'),
        (r'sk-[A-Za-z0-9]{48}', 'OpenAI API Key', 'CRITICAL'),
        (r'AIza[A-Za-z0-9_-]{35}', 'Google API Key', 'CRITICAL'),
        
        # Repository information
        (r'github\.com/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+', 'GitHub Repository URL', 'MEDIUM'),
        (r'git@github\.com:[A-Za-z0-9_-]+/[A-Za-z0-9_-]+\.git', 'Git SSH URL', 'MEDIUM'),
        
        # Credentials in code
        (r'password\s*=\s*["\'][\w!@#$%^&*]+["\']', 'Hardcoded Password', 'CRITICAL'),
        (r'secret\s*=\s*["\'][\w!@#$%^&*]+["\']', 'Hardcoded Secret', 'CRITICAL'),
        (r'api_key\s*=\s*["\'][\w-]+["\']', 'Hardcoded API Key', 'CRITICAL'),
        
        # Database connection strings
        (r'postgresql://[^:\s]+:[^@\s]+@[^/\s]+/[^\s]+', 'PostgreSQL Connection String', 'CRITICAL'),
        (r'mysql://[^:\s]+:[^@\s]+@[^/\s]+/[^\s]+', 'MySQL Connection String', 'CRITICAL'),
        
        # PII patterns
        (r'\b\d{3}-\d{2}-\d{4}\b', 'Social Security Number', 'CRITICAL'),
        (r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b', 'Credit Card Number', 'CRITICAL'),
        
        # IP Addresses (internal ranges)
        (r'\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', 'Private IP Address (10.x)', 'MEDIUM'),
        (r'\b172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}\b', 'Private IP Address (172.x)', 'MEDIUM'),
        (r'\b192\.168\.\d{1,3}\.\d{1,3}\b', 'Private IP Address (192.168.x)', 'MEDIUM'),
        
        # Email addresses (if considered sensitive)
        # (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 'Email Address', 'LOW'),
    ]
    
    # Whitelist patterns (false positives to ignore)
    WHITELIST_PATTERNS = [
        r'example\.com',
        r'localhost',
        r'127\.0\.0\.1',
        r'0\.0\.0\.0',
        r'xxx+',  # Placeholder patterns
        r'\[REDACTED\]',
    ]
    
    @classmethod
    def scan(
        cls,
        output: str,
        context_length: int = 50
    ) -> List[SensitiveMatch]:
        """
        Scan output for sensitive data patterns.
        
        Args:
            output: LLM output text to scan
            context_length: Characters of context to capture around match
        
        Returns:
            List of SensitiveMatch objects
        """
        violations = []
        
        # Check against whitelist first
        output_lower = output.lower()
        for whitelist_pattern in cls.WHITELIST_PATTERNS:
            if re.search(whitelist_pattern, output_lower, re.IGNORECASE):
                # Skip this output segment if whitelisted
                continue
        
        # Scan for each sensitive pattern
        for pattern, description, severity in cls.SENSITIVE_PATTERNS:
            matches = re.finditer(pattern, output, re.IGNORECASE)
            for match in matches:
                # Extract context
                start_pos = max(0, match.start() - context_length)
                end_pos = min(len(output), match.end() + context_length)
                context = output[start_pos:end_pos]
                
                violations.append(SensitiveMatch(
                    pattern_type=description,
                    matched_text=match.group(),
                    position=match.span(),
                    severity=severity,
                    context=context
                ))
        
        return violations
    
    @classmethod
    def sanitize(
        cls,
        output: str,
        redaction_style: str = '[REDACTED]'
    ) -> str:
        """
        Redact sensitive patterns from output.
        
        Args:
            output: Text to sanitize
            redaction_style: Replacement text for redacted content
        
        Returns:
            Sanitized text
        """
        sanitized = output
        
        for pattern, _, _ in cls.SENSITIVE_PATTERNS:
            sanitized = re.sub(
                pattern,
                redaction_style,
                sanitized,
                flags=re.IGNORECASE
            )
        
        return sanitized
    
    @classmethod
    def validate(
        cls,
        output: str,
        auto_sanitize: bool = False
    ) -> OutputValidationResult:
        """
        Validate output and optionally sanitize.
        
        Args:
            output: LLM output to validate
            auto_sanitize: If True, return sanitized version
        
        Returns:
            OutputValidationResult with scan details
        """
        violations = cls.scan(output)
        sanitized = cls.sanitize(output) if auto_sanitize else output
        
        return OutputValidationResult(
            is_safe=len(violations) == 0,
            violations=violations,
            sanitized_output=sanitized,
            original_length=len(output),
            redacted_count=len(violations),
            timestamp=datetime.now().isoformat()
        )
    
    @classmethod
    def get_severity_summary(cls, violations: List[SensitiveMatch]) -> Dict:
        """
        Summarize violations by severity.
        
        Args:
            violations: List of SensitiveMatch objects
        
        Returns:
            Dictionary with severity counts
        """
        summary = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'total': len(violations)
        }
        
        for violation in violations:
            summary[violation.severity] = summary.get(violation.severity, 0) + 1
        
        summary['risk_level'] = (
            'CRITICAL' if summary['CRITICAL'] > 0
            else 'HIGH' if summary['HIGH'] > 0
            else 'MEDIUM' if summary['MEDIUM'] > 0
            else 'LOW' if summary['LOW'] > 0
            else 'SAFE'
        )
        
        return summary
    
    @classmethod
    def log_violation(
        cls,
        violations: List[SensitiveMatch],
        node_name: str,
        supabase_client = None
    ) -> Optional[Dict]:
        """
        Log violations to Supabase security_alerts table.
        
        Args:
            violations: List of detected violations
            node_name: Name of the LangGraph node
            supabase_client: Supabase client instance
        
        Returns:
            Insert result if supabase_client provided
        """
        if not violations:
            return None
        
        severity_summary = cls.get_severity_summary(violations)
        
        alert_data = {
            'timestamp': datetime.now().isoformat(),
            'node': node_name,
            'alert_type': 'OUTPUT_VALIDATION',
            'severity': severity_summary['risk_level'],
            'violation_count': len(violations),
            'violations': [
                {
                    'type': v.pattern_type,
                    'severity': v.severity,
                    'context': v.context[:100]  # Truncate context
                }
                for v in violations
            ],
            'summary': severity_summary
        }
        
        if supabase_client:
            try:
                result = supabase_client.table('security_alerts').insert(alert_data).execute()
                return result.data
            except Exception as e:
                print(f"Failed to log violation: {e}")
                return None
        
        return alert_data


# Integration Example
def langgraph_node_output_validation():
    """
    Example of integrating output validation into a LangGraph node.
    """
    def analysis_node_with_validation(state: dict) -> dict:
        """Example node with output validation."""
        
        # Call LLM (pseudo-code)
        # llm_response = llm.invoke(prompt)
        llm_response = "The property at 123 Main St connects to our database at mocerqjnksmhcjzxrewo.supabase.co"
        
        # Validate output
        validation_result = OutputValidator.validate(
            llm_response,
            auto_sanitize=True
        )
        
        if not validation_result.is_safe:
            # Log to Supabase
            # OutputValidator.log_violation(
            #     validation_result.violations,
            #     'analysis_node',
            #     supabase_client
            # )
            
            # Use sanitized version
            final_output = validation_result.sanitized_output
        else:
            final_output = llm_response
        
        return {
            **state,
            'analysis_result': final_output,
            'output_validated': True,
            'violations_detected': len(validation_result.violations)
        }
    
    return analysis_node_with_validation


if __name__ == '__main__':
    # Test with attack payload
    test_output = """
    Based on the analysis, the property shows good potential.
    
    Connection: postgresql://user:MyP@ssw0rd123@db.supabase.co/main
    API Key: ghp_EXAMPLE_GITHUB_TOKEN_HERE
    """
    
    result = OutputValidator.validate(test_output, auto_sanitize=True)
    
    print(f"Safe: {result.is_safe}")
    print(f"Violations: {len(result.violations)}")
    print("\nSanitized Output:")
    print(result.sanitized_output)
    print("\nViolation Details:")
    for v in result.violations:
        print(f"  - {v.pattern_type} ({v.severity}): {v.matched_text}")
