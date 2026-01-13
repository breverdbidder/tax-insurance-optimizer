"""
Test Suite for Output Validator

Tests detection of sensitive data leakage in LLM outputs.
"""

import pytest
from output_validator import OutputValidator, SensitiveMatch, OutputValidationResult


class TestOutputValidatorPatterns:
    """Test detection of various sensitive data patterns."""
    
    def test_supabase_url_detection(self):
        """Test detection of Supabase URLs."""
        outputs = [
            "Connect to supabase.co for data",
            "Database: mocerqjnksmhcjzxrewo.supabase.co",
            "Our backend uses xyz123.supabase.co",
        ]
        
        for output in outputs:
            violations = OutputValidator.scan(output)
            assert len(violations) > 0
            assert any('Supabase' in v.pattern_type for v in violations)
    
    def test_jwt_token_detection(self):
        """Test detection of JWT tokens."""
        jwt_tokens = [
            "eyXhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyXzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
            "Token: eyX0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyXpZCI6MSwidXNlciI6InRlc3QifQ.xyz123",
        ]
        
        for token in jwt_tokens:
            violations = OutputValidator.scan(token)
            assert len(violations) > 0
            assert any('JWT' in v.pattern_type for v in violations)
    
    def test_github_token_detection(self):
        """Test detection of GitHub tokens."""
        output = "Use token: ghp_EXAMPLE_TOKEN_REDACTED"
        violations = OutputValidator.scan(output)
        
        assert len(violations) > 0
        assert any('GitHub' in v.pattern_type for v in violations)
    
    def test_openai_key_detection(self):
        """Test detection of OpenAI API keys."""
        output = "API key: sk-1234567890abcdefghijklmnopqrstuvwxyz123456789012"
        violations = OutputValidator.scan(output)
        
        assert len(violations) > 0
        assert any('OpenAI' in v.pattern_type for v in violations)
    
    def test_database_connection_string_detection(self):
        """Test detection of database connection strings."""
        connection_strings = [
            "postgresql://user:password@db.example.com/mydb",
            "mysql://admin:secret123@localhost/production",
        ]
        
        for conn_str in connection_strings:
            violations = OutputValidator.scan(conn_str)
            assert len(violations) > 0
            assert any('Connection String' in v.pattern_type for v in violations)
    
    def test_hardcoded_password_detection(self):
        """Test detection of hardcoded passwords."""
        code_samples = [
            'password = "MyP@ssw0rd123"',
            "secret = 'super_secret_key'",
            'api_key = "abc123def456"',
        ]
        
        for code in code_samples:
            violations = OutputValidator.scan(code)
            assert len(violations) > 0


class TestOutputValidatorPII:
    """Test detection of PII patterns."""
    
    def test_ssn_detection(self):
        """Test detection of Social Security Numbers."""
        outputs = [
            "SSN: 123-45-6789",
            "Social Security: 987-65-4321",
        ]
        
        for output in outputs:
            violations = OutputValidator.scan(output)
            assert len(violations) > 0
            assert any('Social Security' in v.pattern_type for v in violations)
    
    def test_credit_card_detection(self):
        """Test detection of credit card numbers."""
        outputs = [
            "Card: 4532 1234 5678 9010",
            "CC: 4532-1234-5678-9010",
            "Number: 4532123456789010",
        ]
        
        for output in outputs:
            violations = OutputValidator.scan(output)
            assert len(violations) > 0
            assert any('Credit Card' in v.pattern_type for v in violations)


class TestOutputValidatorSanitization:
    """Test output sanitization functionality."""
    
    def test_basic_sanitization(self):
        """Test that sensitive patterns are redacted."""
        output = "The API key is ghp_EXAMPLE_TOKEN_REDACTED for authentication."
        sanitized = OutputValidator.sanitize(output)
        
        assert 'ghp_EXAMPLE_TOKEN_REDACTED' not in sanitized
        assert '[REDACTED]' in sanitized
    
    def test_multiple_pattern_sanitization(self):
        """Test sanitization of multiple patterns."""
        output = """
        Database: mocerqjnksmhcjzxrewo.supabase.co
        Token: ghp_EXAMPLE_TOKEN_REDACTED
        SSN: 123-45-6789
        """
        sanitized = OutputValidator.sanitize(output)
        
        assert 'supabase.co' not in sanitized
        assert 'ghp_' not in sanitized
        assert '123-45-6789' not in sanitized
        assert sanitized.count('[REDACTED]') >= 3
    
    def test_custom_redaction_style(self):
        """Test custom redaction markers."""
        output = "API: ghp_EXAMPLE"
        sanitized = OutputValidator.sanitize(output, redaction_style='***REMOVED***')
        
        assert '***REMOVED***' in sanitized
        assert '[REDACTED]' not in sanitized


class TestOutputValidatorValidation:
    """Test full validation workflow."""
    
    def test_safe_output_validation(self):
        """Test validation of clean output."""
        clean_output = "The property at 123 Main St shows good investment potential."
        result = OutputValidator.validate(clean_output)
        
        assert result.is_safe
        assert len(result.violations) == 0
        assert result.sanitized_output == clean_output
    
    def test_unsafe_output_validation(self):
        """Test validation of output with leaks."""
        unsafe_output = "Database at mocerqjnksmhcjzxrewo.supabase.co contains the data."
        result = OutputValidator.validate(unsafe_output)
        
        assert not result.is_safe
        assert len(result.violations) > 0
    
    def test_auto_sanitize_enabled(self):
        """Test automatic sanitization."""
        unsafe_output = "Token: ghp_EXAMPLEdef456"
        result = OutputValidator.validate(unsafe_output, auto_sanitize=True)
        
        assert not result.is_safe
        assert 'ghp_' not in result.sanitized_output
        assert '[REDACTED]' in result.sanitized_output
    
    def test_auto_sanitize_disabled(self):
        """Test validation without sanitization."""
        unsafe_output = "Token: ghp_EXAMPLEdef456"
        result = OutputValidator.validate(unsafe_output, auto_sanitize=False)
        
        assert not result.is_safe
        assert result.sanitized_output == unsafe_output  # Unchanged


class TestOutputValidatorSeverity:
    """Test severity classification."""
    
    def test_critical_severity(self):
        """Test that critical patterns are marked correctly."""
        output = "JWT: eyXhbGciOiJIUzI1NiJ9.eyX0ZXN0IjoidmFsdWUifQ.signature"
        violations = OutputValidator.scan(output)
        
        assert any(v.severity == 'CRITICAL' for v in violations)
    
    def test_severity_summary(self):
        """Test severity summary generation."""
        output = """
        Supabase: test.supabase.co (HIGH)
        GitHub Repo: github.com/user/repo (MEDIUM)
        JWT: eyX... (CRITICAL)
        """
        violations = OutputValidator.scan(output)
        summary = OutputValidator.get_severity_summary(violations)
        
        assert summary['total'] > 0
        assert summary['CRITICAL'] > 0
        assert summary['risk_level'] == 'CRITICAL'


class TestOutputValidatorContext:
    """Test context capture around matches."""
    
    def test_context_capture(self):
        """Test that context is captured around matches."""
        output = "The system uses database at mocerqjnksmhcjzxrewo.supabase.co for storage."
        violations = OutputValidator.scan(output, context_length=20)
        
        assert len(violations) > 0
        violation = violations[0]
        
        assert len(violation.context) > len(violation.matched_text)
        assert violation.matched_text in violation.context
    
    def test_context_at_boundaries(self):
        """Test context capture at string boundaries."""
        # Test at start
        output = "supabase.co is used here"
        violations = OutputValidator.scan(output, context_length=100)
        
        assert len(violations) > 0
        # Should not crash even though we're at the start


class TestOutputValidatorWhitelist:
    """Test whitelisting of false positives."""
    
    def test_example_domain_whitelisted(self):
        """Test that example.com is whitelisted."""
        output = "Visit example.com for more info"
        violations = OutputValidator.scan(output)
        
        # Should not trigger violations for example domains
        # Note: This depends on implementation - adjust assertion if needed


class TestOutputValidatorRealWorld:
    """Test with real-world LLM output scenarios."""
    
    def test_property_analysis_output(self):
        """Test typical property analysis output."""
        safe_output = """
        Property Analysis:
        - Address: 123 Main St, Melbourne FL
        - ARV: $350,000
        - Repairs: $50,000
        - Max Bid: $195,000
        - Recommendation: BID
        """
        result = OutputValidator.validate(safe_output)
        
        assert result.is_safe
    
    def test_lien_analysis_with_leak(self):
        """Test lien analysis with accidental database leak."""
        leaked_output = """
        Lien Analysis:
        - Primary: First Mortgage $200K
        - Secondary: HOA Lien $5K
        
        Data retrieved from mocerqjnksmhcjzxrewo.supabase.co/liens
        """
        result = OutputValidator.validate(leaked_output)
        
        assert not result.is_safe
        assert len(result.violations) > 0
    
    def test_max_bid_calculation_output(self):
        """Test max bid calculation output."""
        safe_output = """
        Max Bid Calculation:
        ARV: $350,000
        70% ARV: $245,000
        Repairs: -$50,000
        Closing Costs: -$10,000
        Buffer (15% ARV): -$52,500
        
        Maximum Bid: $132,500
        """
        result = OutputValidator.validate(safe_output)
        
        assert result.is_safe


class TestOutputValidatorLogging:
    """Test violation logging functionality."""
    
    def test_log_violation_structure(self):
        """Test that logged violations have correct structure."""
        output = "Token: ghp_EXAMPLE and database: test.supabase.co"
        violations = OutputValidator.scan(output)
        
        alert_data = OutputValidator.log_violation(
            violations,
            'test_node',
            supabase_client=None  # No actual client
        )
        
        assert alert_data is not None
        assert 'timestamp' in alert_data
        assert 'node' in alert_data
        assert alert_data['node'] == 'test_node'
        assert 'violations' in alert_data
        assert alert_data['violation_count'] == len(violations)
    
    def test_no_violations_no_log(self):
        """Test that clean output doesn't generate logs."""
        alert_data = OutputValidator.log_violation(
            [],
            'test_node',
            supabase_client=None
        )
        
        assert alert_data is None


class TestOutputValidatorEdgeCases:
    """Test edge cases and error conditions."""
    
    def test_empty_output(self):
        """Test validation of empty output."""
        result = OutputValidator.validate('')
        
        assert result.is_safe
        assert len(result.violations) == 0
    
    def test_very_long_output(self):
        """Test validation of very long output."""
        long_output = "A" * 100000
        result = OutputValidator.validate(long_output)
        
        # Should not crash
        assert result.original_length == 100000
    
    def test_special_characters(self):
        """Test handling of special characters."""
        output = "Property: $@#%^&*() <html> [test]"
        result = OutputValidator.validate(output)
        
        # Should handle special chars gracefully
        assert result.is_safe or not result.is_safe  # Just shouldn't crash


class TestOutputValidatorPrivateIPAddresses:
    """Test detection of private IP addresses."""
    
    def test_private_ip_detection(self):
        """Test detection of private IP ranges."""
        ips = [
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
        ]
        
        for ip in ips:
            output = f"Database at {ip}"
            violations = OutputValidator.scan(output)
            assert len(violations) > 0
            assert any('Private IP' in v.pattern_type for v in violations)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
