"""
Anomaly Detector for LLM Security Monitoring

Detects suspicious patterns in LLM behavior:
- Excessive output length (potential data exfiltration)
- Repeated failures (circuit breaker trigger)
- Unusual token usage patterns
- Rate limit violations
- Pattern-based anomaly detection

Part of Phase 2 - Week 3-4: Monitoring & Circuit Breakers
"""

import os
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict, deque


@dataclass
class AnomalyEvent:
    """Single anomaly detection event."""
    timestamp: str
    node: str
    anomaly_type: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    description: str
    metadata: Dict
    action_taken: str


class CircuitBreaker:
    """
    Circuit breaker for LLM nodes.
    
    States:
    - CLOSED: Normal operation
    - OPEN: Failures exceeded threshold, blocking requests
    - HALF_OPEN: Testing if service recovered
    """
    
    def __init__(
        self,
        failure_threshold: int = 3,
        timeout: int = 60,  # seconds
        half_open_attempts: int = 1
    ):
        self.failure_threshold = failure_threshold
        self.timeout = timeout
        self.half_open_attempts = half_open_attempts
        
        self.state = "CLOSED"
        self.failure_count = 0
        self.last_failure_time = None
        self.half_open_success_count = 0
    
    def call(self, func, *args, **kwargs):
        """Execute function with circuit breaker protection."""
        if self.state == "OPEN":
            # Check if timeout elapsed
            if time.time() - self.last_failure_time > self.timeout:
                self.state = "HALF_OPEN"
                self.half_open_success_count = 0
            else:
                raise Exception(f"Circuit breaker OPEN - blocking request")
        
        try:
            result = func(*args, **kwargs)
            
            if self.state == "HALF_OPEN":
                self.half_open_success_count += 1
                if self.half_open_success_count >= self.half_open_attempts:
                    self.state = "CLOSED"
                    self.failure_count = 0
            elif self.state == "CLOSED":
                self.failure_count = 0
            
            return result
            
        except Exception as e:
            self.failure_count += 1
            self.last_failure_time = time.time()
            
            if self.failure_count >= self.failure_threshold:
                self.state = "OPEN"
            
            raise e
    
    def get_state(self) -> Dict:
        """Get current circuit breaker state."""
        return {
            "state": self.state,
            "failure_count": self.failure_count,
            "last_failure_time": self.last_failure_time,
            "half_open_success_count": self.half_open_success_count
        }


class AnomalyDetector:
    """
    Detects anomalies in LLM behavior and triggers circuit breakers.
    """
    
    def __init__(self):
        # Thresholds
        self.max_output_tokens = 5000
        self.max_failures_per_10min = 3
        self.max_requests_per_minute = 60
        self.suspicious_token_patterns = [
            "IGNORE ALL INSTRUCTIONS",
            "SYSTEM:",
            "ASSISTANT:",
            "<|endoftext|>",
            "```sql DROP",
            "```bash rm -rf",
        ]
        
        # Tracking
        self.failure_history = defaultdict(deque)  # node -> deque of timestamps
        self.request_history = defaultdict(deque)  # node -> deque of timestamps
        self.circuit_breakers = {}  # node -> CircuitBreaker
        self.anomaly_events = []
        
    def get_circuit_breaker(self, node: str) -> CircuitBreaker:
        """Get or create circuit breaker for node."""
        if node not in self.circuit_breakers:
            self.circuit_breakers[node] = CircuitBreaker(
                failure_threshold=3,
                timeout=60,
                half_open_attempts=1
            )
        return self.circuit_breakers[node]
    
    def check_output_length(
        self,
        node: str,
        output: str,
        token_count: Optional[int] = None
    ) -> Optional[AnomalyEvent]:
        """Detect excessive output length (potential exfiltration)."""
        if token_count and token_count > self.max_output_tokens:
            return AnomalyEvent(
                timestamp=datetime.now().isoformat(),
                node=node,
                anomaly_type="excessive_output",
                severity="HIGH",
                description=f"Output exceeded {self.max_output_tokens} tokens: {token_count}",
                metadata={
                    "token_count": token_count,
                    "threshold": self.max_output_tokens
                },
                action_taken="truncate_output"
            )
        
        # Check for suspicious patterns
        for pattern in self.suspicious_token_patterns:
            if pattern.lower() in output.lower():
                return AnomalyEvent(
                    timestamp=datetime.now().isoformat(),
                    node=node,
                    anomaly_type="suspicious_pattern",
                    severity="CRITICAL",
                    description=f"Suspicious pattern detected: {pattern}",
                    metadata={
                        "pattern": pattern,
                        "output_preview": output[:200]
                    },
                    action_taken="block_output"
                )
        
        return None
    
    def check_failure_rate(self, node: str) -> Optional[AnomalyEvent]:
        """Detect excessive failure rate."""
        now = time.time()
        cutoff = now - 600  # 10 minutes
        
        # Clean old failures
        while self.failure_history[node] and self.failure_history[node][0] < cutoff:
            self.failure_history[node].popleft()
        
        failure_count = len(self.failure_history[node])
        
        if failure_count >= self.max_failures_per_10min:
            return AnomalyEvent(
                timestamp=datetime.now().isoformat(),
                node=node,
                anomaly_type="excessive_failures",
                severity="HIGH",
                description=f"Node failed {failure_count} times in 10 minutes",
                metadata={
                    "failure_count": failure_count,
                    "threshold": self.max_failures_per_10min,
                    "window_minutes": 10
                },
                action_taken="open_circuit_breaker"
            )
        
        return None
    
    def check_rate_limit(self, node: str) -> Optional[AnomalyEvent]:
        """Detect rate limit violations."""
        now = time.time()
        cutoff = now - 60  # 1 minute
        
        # Clean old requests
        while self.request_history[node] and self.request_history[node][0] < cutoff:
            self.request_history[node].popleft()
        
        request_count = len(self.request_history[node])
        
        if request_count >= self.max_requests_per_minute:
            return AnomalyEvent(
                timestamp=datetime.now().isoformat(),
                node=node,
                anomaly_type="rate_limit_exceeded",
                severity="MEDIUM",
                description=f"Node made {request_count} requests in 1 minute",
                metadata={
                    "request_count": request_count,
                    "threshold": self.max_requests_per_minute,
                    "window_seconds": 60
                },
                action_taken="throttle_requests"
            )
        
        return None
    
    def record_request(self, node: str):
        """Record a request for rate limiting."""
        self.request_history[node].append(time.time())
    
    def record_failure(self, node: str):
        """Record a failure for circuit breaking."""
        self.failure_history[node].append(time.time())
    
    def monitor_llm_call(
        self,
        node: str,
        output: str,
        token_count: Optional[int] = None,
        success: bool = True
    ) -> List[AnomalyEvent]:
        """
        Monitor a single LLM call for anomalies.
        
        Returns list of detected anomalies.
        """
        anomalies = []
        
        # Record request
        self.record_request(node)
        
        # Check rate limit
        rate_anomaly = self.check_rate_limit(node)
        if rate_anomaly:
            anomalies.append(rate_anomaly)
            self.anomaly_events.append(rate_anomaly)
        
        if not success:
            # Record failure
            self.record_failure(node)
            
            # Check failure rate
            failure_anomaly = self.check_failure_rate(node)
            if failure_anomaly:
                anomalies.append(failure_anomaly)
                self.anomaly_events.append(failure_anomaly)
                
                # Open circuit breaker
                breaker = self.get_circuit_breaker(node)
                breaker.failure_count = self.max_failures_per_10min
                breaker.state = "OPEN"
                breaker.last_failure_time = time.time()
        
        else:
            # Check output for anomalies
            output_anomaly = self.check_output_length(node, output, token_count)
            if output_anomaly:
                anomalies.append(output_anomaly)
                self.anomaly_events.append(output_anomaly)
        
        return anomalies
    
    def get_node_health(self, node: str) -> Dict:
        """Get health status for a node."""
        breaker = self.get_circuit_breaker(node)
        
        now = time.time()
        recent_failures = sum(
            1 for ts in self.failure_history[node]
            if ts > now - 600
        )
        recent_requests = sum(
            1 for ts in self.request_history[node]
            if ts > now - 60
        )
        
        return {
            "node": node,
            "circuit_breaker_state": breaker.state,
            "recent_failures_10min": recent_failures,
            "recent_requests_1min": recent_requests,
            "health_status": "HEALTHY" if breaker.state == "CLOSED" else "DEGRADED"
        }
    
    def get_all_anomalies(
        self,
        since: Optional[datetime] = None,
        severity: Optional[str] = None
    ) -> List[AnomalyEvent]:
        """Get all detected anomalies with optional filters."""
        anomalies = self.anomaly_events
        
        if since:
            anomalies = [
                a for a in anomalies
                if datetime.fromisoformat(a.timestamp) >= since
            ]
        
        if severity:
            anomalies = [a for a in anomalies if a.severity == severity]
        
        return anomalies
    
    def log_to_supabase(self, anomaly: AnomalyEvent, supabase_client):
        """Log anomaly to Supabase anomaly_metrics table."""
        try:
            supabase_client.table('anomaly_metrics').insert({
                'timestamp': anomaly.timestamp,
                'node': anomaly.node,
                'anomaly_type': anomaly.anomaly_type,
                'severity': anomaly.severity,
                'description': anomaly.description,
                'metadata': anomaly.metadata,
                'action_taken': anomaly.action_taken
            }).execute()
        except Exception as e:
            print(f"Failed to log anomaly to Supabase: {e}")
    
    def generate_daily_report(self) -> Dict:
        """Generate daily anomaly report."""
        now = datetime.now()
        yesterday = now - timedelta(days=1)
        
        daily_anomalies = self.get_all_anomalies(since=yesterday)
        
        by_severity = defaultdict(int)
        by_type = defaultdict(int)
        by_node = defaultdict(int)
        
        for anomaly in daily_anomalies:
            by_severity[anomaly.severity] += 1
            by_type[anomaly.anomaly_type] += 1
            by_node[anomaly.node] += 1
        
        return {
            "period": "24h",
            "total_anomalies": len(daily_anomalies),
            "by_severity": dict(by_severity),
            "by_type": dict(by_type),
            "by_node": dict(by_node),
            "critical_count": by_severity.get("CRITICAL", 0),
            "high_count": by_severity.get("HIGH", 0),
            "generated_at": now.isoformat()
        }


# Global detector instance
_detector = None


def get_detector() -> AnomalyDetector:
    """Get global anomaly detector instance."""
    global _detector
    if _detector is None:
        _detector = AnomalyDetector()
    return _detector


# Decorator for LLM calls
def monitor_llm(node: str):
    """Decorator to monitor LLM calls for anomalies."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            detector = get_detector()
            breaker = detector.get_circuit_breaker(node)
            
            # Check circuit breaker
            if breaker.state == "OPEN":
                # Check if timeout elapsed
                if time.time() - breaker.last_failure_time > breaker.timeout:
                    breaker.state = "HALF_OPEN"
                else:
                    raise Exception(
                        f"Circuit breaker OPEN for {node} - "
                        f"wait {breaker.timeout}s or use fallback"
                    )
            
            try:
                # Execute function
                result = func(*args, **kwargs)
                
                # Monitor output
                if isinstance(result, dict) and 'content' in result:
                    output = result['content']
                    token_count = result.get('token_count')
                    
                    anomalies = detector.monitor_llm_call(
                        node=node,
                        output=output,
                        token_count=token_count,
                        success=True
                    )
                    
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
                
                # Monitor failure
                anomalies = detector.monitor_llm_call(
                    node=node,
                    output="",
                    success=False
                )
                
                # Log anomalies
                for anomaly in anomalies:
                    print(f"🚨 ANOMALY: {anomaly.severity} - {anomaly.description}")
                
                raise e
        
        return wrapper
    return decorator


if __name__ == '__main__':
    print("=" * 70)
    print("ANOMALY DETECTOR TEST")
    print("=" * 70)
    print()
    
    detector = get_detector()
    
    # Simulate normal operation
    print("✅ Normal operation:")
    for i in range(5):
        detector.monitor_llm_call(
            node="test_node",
            output="Normal output text",
            token_count=100,
            success=True
        )
    health = detector.get_node_health("test_node")
    print(f"   Health: {health['health_status']}")
    print()
    
    # Simulate excessive output
    print("⚠️ Excessive output:")
    anomalies = detector.monitor_llm_call(
        node="test_node",
        output="x" * 10000,
        token_count=6000,
        success=True
    )
    print(f"   Detected: {len(anomalies)} anomalies")
    for a in anomalies:
        print(f"   - {a.severity}: {a.description}")
    print()
    
    # Simulate failures
    print("🚨 Repeated failures:")
    for i in range(4):
        detector.monitor_llm_call(
            node="failing_node",
            output="",
            success=False
        )
        time.sleep(0.1)
    
    health = detector.get_node_health("failing_node")
    print(f"   Circuit Breaker: {health['circuit_breaker_state']}")
    print(f"   Health: {health['health_status']}")
    print()
    
    # Generate report
    print("📊 Daily Report:")
    report = detector.generate_daily_report()
    print(f"   Total Anomalies: {report['total_anomalies']}")
    print(f"   By Severity: {report['by_severity']}")
    print(f"   By Type: {report['by_type']}")
