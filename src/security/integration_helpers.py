"""
Security Integration Helpers

Quick integration functions for adding Phase 2 security to existing code.

Usage:
    from src.security.integration_helpers import secure_llm_call, secure_data_fetch

    # Wrap LLM calls
    @secure_llm_call(node="my_node")
    async def my_llm_function():
        return await llm.invoke(prompt)
    
    # Validate input data
    clean_data = validate_input(user_data, max_length=1000)
"""

import asyncio
from typing import Any, Callable, Dict, Optional
from functools import wraps

# Import security components
try:
    from src.security.input_validator import InputValidator
    from src.security.rse_wrapper import RSEWrapper
    from src.security.output_validator import OutputValidator
    from src.security.anomaly_detector import get_detector
except ImportError:
    print("⚠️ Security modules not found. Install with: pip install -r requirements.txt")


def secure_llm_call(node: str, use_rse: bool = True):
    """
    Decorator to secure LLM calls with monitoring and validation.
    
    Args:
        node: Node name for monitoring
        use_rse: Whether to use RSE wrapper for prompt boundaries
    
    Example:
        @secure_llm_call(node="analysis")
        async def analyze_property(data):
            return await llm.invoke(prompt)
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            detector = get_detector()
            breaker = detector.get_circuit_breaker(node)
            
            # Check circuit breaker
            if breaker.state == "OPEN":
                raise Exception(f"Circuit breaker OPEN for {node}")
            
            try:
                # Execute function
                result = await func(*args, **kwargs)
                
                # Monitor output
                if isinstance(result, dict) and 'content' in result:
                    output = result['content']
                    token_count = result.get('token_count')
                    
                    # Detect anomalies
                    anomalies = detector.monitor_llm_call(
                        node=node,
                        output=output,
                        token_count=token_count,
                        success=True
                    )
                    
                    # Validate output
                    validation = OutputValidator.validate(output)
                    if not validation.is_safe:
                        print(f"⚠️ Output validation failed: {validation.violations}")
                        result['content'] = validation.sanitized_output
                    
                    # Log anomalies
                    for anomaly in anomalies:
                        print(f"⚠️ ANOMALY: {anomaly.severity} - {anomaly.description}")
                
                # Update circuit breaker
                if breaker.state == "HALF_OPEN":
                    breaker.half_open_success_count += 1
                    if breaker.half_open_success_count >= breaker.half_open_attempts:
                        breaker.state = "CLOSED"
                        breaker.failure_count = 0
                
                return result
                
            except Exception as e:
                # Record failure
                detector.record_failure(node)
                anomalies = detector.monitor_llm_call(node=node, output="", success=False)
                raise e
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            return asyncio.run(async_wrapper(*args, **kwargs))
        
        # Return appropriate wrapper based on function type
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


def validate_input(
    data: str,
    max_length: int = 10000,
    allow_sql: bool = False,
    allow_code: bool = False
) -> str:
    """
    Validate and sanitize input data.
    
    Args:
        data: Input string to validate
        max_length: Maximum allowed length
        allow_sql: Whether to allow SQL-like patterns
        allow_code: Whether to allow code injection patterns
    
    Returns:
        Sanitized input string
    
    Raises:
        ValueError: If validation fails
    """
    validation = InputValidator.validate(
        data,
        field_name="input",
        max_length=max_length
    )
    
    if not validation.is_valid:
        raise ValueError(f"Input validation failed: {validation.violations}")
    
    return validation.sanitized_text


def validate_output(
    data: str,
    auto_sanitize: bool = True
) -> str:
    """
    Validate and sanitize output data.
    
    Args:
        data: Output string to validate
        auto_sanitize: Whether to automatically sanitize sensitive data
    
    Returns:
        Sanitized output string
    
    Raises:
        ValueError: If validation fails and auto_sanitize=False
    """
    validation = OutputValidator.validate(data, auto_sanitize=auto_sanitize)
    
    if not validation.is_safe and not auto_sanitize:
        raise ValueError(f"Output contains sensitive data: {validation.violations}")
    
    return validation.sanitized_output


def wrap_prompt(
    user_input: str,
    instructions: str,
    context: Optional[str] = None
) -> tuple[str, Dict]:
    """
    Wrap prompt with RSE (Random Sequence Enclosure) boundaries.
    
    Args:
        user_input: User-provided input
        instructions: System instructions
        context: Optional context data
    
    Returns:
        Tuple of (wrapped_prompt, envelope)
    """
    prompt, envelope = RSEWrapper.wrap_user_input(user_input, instructions, context)
    return prompt, envelope


def secure_database_query(agent_type: str = 'scraper'):
    """
    Get secure Supabase client for specific agent.
    
    Args:
        agent_type: Type of agent ('scraper', 'analysis', 'report', 'qa', 'admin')
    
    Returns:
        Supabase client with appropriate permissions
    
    Example:
        db = secure_database_query('scraper')
        data = db.table('historical_auctions').select('*').execute()
    """
    from src.utils.supabase_client import SupabaseClientV14
    return SupabaseClientV14.get_client(agent_type)


def log_security_event(
    event_type: str,
    severity: str,
    description: str,
    metadata: Optional[Dict] = None
):
    """
    Log security event to database.
    
    Args:
        event_type: Type of event (e.g., 'anomaly', 'violation', 'alert')
        severity: Severity level ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
        description: Event description
        metadata: Optional metadata dict
    """
    try:
        from src.utils.supabase_client import get_admin_client
        
        client = get_admin_client()
        client.table('security_alerts').insert({
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'severity': severity,
            'description': description,
            'metadata': metadata or {}
        }).execute()
    except Exception as e:
        print(f"Failed to log security event: {e}")


# Quick integration examples
INTEGRATION_EXAMPLES = """
# Example 1: Secure LLM Call with Monitoring
from src.security.integration_helpers import secure_llm_call

@secure_llm_call(node="property_analysis")
async def analyze_property(property_data):
    prompt = f"Analyze this property: {property_data}"
    response = await llm.invoke(prompt)
    return response

# Example 2: Input Validation
from src.security.integration_helpers import validate_input

def process_user_input(user_data):
    clean_data = validate_input(user_data, max_length=1000)
    # Process clean_data safely...

# Example 3: Output Sanitization
from src.security.integration_helpers import validate_output

def generate_report(data):
    report = create_report(data)
    safe_report = validate_output(report, auto_sanitize=True)
    return safe_report

# Example 4: Secure Database Access
from src.security.integration_helpers import secure_database_query

def fetch_auctions():
    db = secure_database_query('scraper')
    auctions = db.table('historical_auctions').select('*').execute()
    return auctions.data

# Example 5: RSE Prompt Wrapping
from src.security.integration_helpers import wrap_prompt

def call_llm_with_user_input(user_input, instructions):
    prompt, envelope = wrap_prompt(user_input, instructions)
    response = llm.invoke(prompt)
    return RSEWrapper.extract_response(response, envelope)
"""


if __name__ == '__main__':
    print("=" * 70)
    print("SECURITY INTEGRATION HELPERS")
    print("=" * 70)
    print()
    print(INTEGRATION_EXAMPLES)
