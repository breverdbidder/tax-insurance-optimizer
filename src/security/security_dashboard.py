"""
Security Dashboard for LLM Monitoring

Real-time monitoring of:
- Anomaly detection events
- Circuit breaker states
- Security violations
- System health

Part of Phase 2 - Week 3-4: Monitoring & Circuit Breakers
"""

import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from collections import defaultdict


class SecurityDashboard:
    """
    Real-time security monitoring dashboard.
    
    Aggregates data from:
    - Anomaly detector
    - Security alerts table
    - Input/output validators
    - Circuit breakers
    """
    
    def __init__(self, supabase_client):
        self.supabase = supabase_client
    
    def get_recent_anomalies(
        self,
        hours: int = 24,
        severity: Optional[str] = None
    ) -> List[Dict]:
        """Get recent anomaly events."""
        cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
        
        query = self.supabase.table('anomaly_metrics').select('*').gte(
            'timestamp', cutoff
        ).order('timestamp', desc=True)
        
        if severity:
            query = query.eq('severity', severity)
        
        response = query.execute()
        return response.data if response.data else []
    
    def get_security_alerts(
        self,
        hours: int = 24,
        severity: Optional[str] = None
    ) -> List[Dict]:
        """Get recent security alerts."""
        cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
        
        query = self.supabase.table('security_alerts').select('*').gte(
            'timestamp', cutoff
        ).order('timestamp', desc=True)
        
        if severity:
            query = query.eq('severity', severity)
        
        response = query.execute()
        return response.data if response.data else []
    
    def get_node_health_summary(self) -> Dict:
        """Get health summary for all nodes."""
        # Get recent anomalies per node
        anomalies = self.get_recent_anomalies(hours=1)
        
        node_stats = defaultdict(lambda: {
            'total_anomalies': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'last_anomaly': None
        })
        
        for anomaly in anomalies:
            node = anomaly.get('node', 'unknown')
            node_stats[node]['total_anomalies'] += 1
            
            severity = anomaly.get('severity', 'LOW').lower()
            if severity in node_stats[node]:
                node_stats[node][severity] += 1
            
            # Track most recent
            if not node_stats[node]['last_anomaly']:
                node_stats[node]['last_anomaly'] = anomaly.get('timestamp')
        
        # Determine health status
        for node, stats in node_stats.items():
            if stats['critical'] > 0:
                stats['health'] = 'CRITICAL'
            elif stats['high'] > 3:
                stats['health'] = 'DEGRADED'
            elif stats['total_anomalies'] > 10:
                stats['health'] = 'STRESSED'
            else:
                stats['health'] = 'HEALTHY'
        
        return dict(node_stats)
    
    def get_security_score(self) -> Dict:
        """
        Calculate overall security score (0-100).
        
        Factors:
        - Recent anomalies (weight: 40%)
        - Security violations (weight: 40%)
        - Circuit breaker trips (weight: 20%)
        """
        score = 100.0
        
        # Factor 1: Anomalies (last 24h)
        anomalies = self.get_recent_anomalies(hours=24)
        anomaly_penalty = 0
        for anomaly in anomalies:
            severity = anomaly.get('severity', 'LOW')
            if severity == 'CRITICAL':
                anomaly_penalty += 10
            elif severity == 'HIGH':
                anomaly_penalty += 5
            elif severity == 'MEDIUM':
                anomaly_penalty += 2
            else:
                anomaly_penalty += 0.5
        
        score -= min(anomaly_penalty * 0.4, 40)  # Max 40 points
        
        # Factor 2: Security violations (last 24h)
        alerts = self.get_security_alerts(hours=24)
        alert_penalty = 0
        for alert in alerts:
            severity = alert.get('severity', 'LOW')
            if severity == 'CRITICAL':
                alert_penalty += 10
            elif severity == 'HIGH':
                alert_penalty += 5
            else:
                alert_penalty += 1
        
        score -= min(alert_penalty * 0.4, 40)  # Max 40 points
        
        # Factor 3: Circuit breaker trips
        breaker_trips = sum(
            1 for a in anomalies
            if a.get('anomaly_type') == 'excessive_failures'
        )
        score -= min(breaker_trips * 4, 20)  # Max 20 points
        
        score = max(0, score)
        
        return {
            'score': round(score, 1),
            'grade': self._score_to_grade(score),
            'anomaly_count': len(anomalies),
            'alert_count': len(alerts),
            'breaker_trips': breaker_trips,
            'status': self._score_to_status(score)
        }
    
    def _score_to_grade(self, score: float) -> str:
        """Convert score to letter grade."""
        if score >= 95:
            return 'A+'
        elif score >= 90:
            return 'A'
        elif score >= 85:
            return 'B+'
        elif score >= 80:
            return 'B'
        elif score >= 75:
            return 'C+'
        elif score >= 70:
            return 'C'
        elif score >= 60:
            return 'D'
        else:
            return 'F'
    
    def _score_to_status(self, score: float) -> str:
        """Convert score to status."""
        if score >= 90:
            return 'EXCELLENT'
        elif score >= 75:
            return 'GOOD'
        elif score >= 60:
            return 'FAIR'
        elif score >= 40:
            return 'POOR'
        else:
            return 'CRITICAL'
    
    def get_weekly_summary(self) -> Dict:
        """Get weekly security summary."""
        anomalies = self.get_recent_anomalies(hours=24*7)
        alerts = self.get_security_alerts(hours=24*7)
        
        # Group by day
        daily_stats = defaultdict(lambda: {
            'anomalies': 0,
            'alerts': 0,
            'critical_events': 0
        })
        
        for anomaly in anomalies:
            day = anomaly['timestamp'][:10]  # YYYY-MM-DD
            daily_stats[day]['anomalies'] += 1
            if anomaly.get('severity') == 'CRITICAL':
                daily_stats[day]['critical_events'] += 1
        
        for alert in alerts:
            day = alert['timestamp'][:10]
            daily_stats[day]['alerts'] += 1
            if alert.get('severity') == 'CRITICAL':
                daily_stats[day]['critical_events'] += 1
        
        # Top anomaly types
        anomaly_types = defaultdict(int)
        for anomaly in anomalies:
            anomaly_types[anomaly.get('anomaly_type', 'unknown')] += 1
        
        top_anomalies = sorted(
            anomaly_types.items(),
            key=lambda x: x[1],
            reverse=True
        )[:5]
        
        # Top affected nodes
        node_counts = defaultdict(int)
        for anomaly in anomalies:
            node_counts[anomaly.get('node', 'unknown')] += 1
        
        top_nodes = sorted(
            node_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )[:5]
        
        return {
            'period': '7 days',
            'total_anomalies': len(anomalies),
            'total_alerts': len(alerts),
            'daily_breakdown': dict(daily_stats),
            'top_anomaly_types': top_anomalies,
            'top_affected_nodes': top_nodes,
            'critical_events': sum(
                stats['critical_events']
                for stats in daily_stats.values()
            )
        }
    
    def generate_html_dashboard(self) -> str:
        """Generate HTML dashboard for web viewing."""
        security_score = self.get_security_score()
        node_health = self.get_node_health_summary()
        weekly_summary = self.get_weekly_summary()
        recent_anomalies = self.get_recent_anomalies(hours=24)
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Security Dashboard</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            margin: 0;
            padding: 20px;
            background: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            background: #1a1a1a;
            color: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
        }}
        .score-card {{
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
            margin-bottom: 20px;
        }}
        .score {{
            font-size: 72px;
            font-weight: bold;
            color: {self._score_color(security_score['score'])};
        }}
        .grade {{
            font-size: 36px;
            color: #666;
        }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }}
        .card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .card h3 {{
            margin-top: 0;
            color: #333;
        }}
        .health-status {{
            padding: 5px 10px;
            border-radius: 4px;
            font-weight: bold;
            display: inline-block;
        }}
        .health-HEALTHY {{ background: #d4edda; color: #155724; }}
        .health-STRESSED {{ background: #fff3cd; color: #856404; }}
        .health-DEGRADED {{ background: #f8d7da; color: #721c24; }}
        .health-CRITICAL {{ background: #f8d7da; color: #721c24; }}
        .anomaly {{
            padding: 10px;
            margin-bottom: 10px;
            border-left: 4px solid;
            background: #f8f9fa;
        }}
        .anomaly-CRITICAL {{ border-color: #dc3545; }}
        .anomaly-HIGH {{ border-color: #fd7e14; }}
        .anomaly-MEDIUM {{ border-color: #ffc107; }}
        .anomaly-LOW {{ border-color: #28a745; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Security Dashboard</h1>
            <p>Real-time monitoring of LLM security posture</p>
            <p><small>Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</small></p>
        </div>
        
        <div class="score-card">
            <div class="score">{security_score['score']}</div>
            <div class="grade">Grade: {security_score['grade']}</div>
            <p style="color: #666;">Security Status: {security_score['status']}</p>
        </div>
        
        <div class="grid">
            <div class="card">
                <h3>📊 24-Hour Summary</h3>
                <p>Anomalies: <strong>{security_score['anomaly_count']}</strong></p>
                <p>Alerts: <strong>{security_score['alert_count']}</strong></p>
                <p>Circuit Breaker Trips: <strong>{security_score['breaker_trips']}</strong></p>
            </div>
            
            <div class="card">
                <h3>📅 Weekly Summary</h3>
                <p>Total Anomalies: <strong>{weekly_summary['total_anomalies']}</strong></p>
                <p>Total Alerts: <strong>{weekly_summary['total_alerts']}</strong></p>
                <p>Critical Events: <strong>{weekly_summary['critical_events']}</strong></p>
            </div>
        </div>
        
        <div class="card">
            <h3>🏥 Node Health</h3>
            {self._render_node_health(node_health)}
        </div>
        
        <div class="card">
            <h3>🚨 Recent Anomalies (24h)</h3>
            {self._render_recent_anomalies(recent_anomalies[:10])}
        </div>
        
        <div class="card">
            <h3>📈 Top Anomaly Types (7d)</h3>
            <ol>
            {''.join(f"<li>{atype}: {count} occurrences</li>" for atype, count in weekly_summary['top_anomaly_types'])}
            </ol>
        </div>
    </div>
</body>
</html>
"""
        return html
    
    def _score_color(self, score: float) -> str:
        """Get color for score."""
        if score >= 90:
            return '#28a745'
        elif score >= 75:
            return '#5cb85c'
        elif score >= 60:
            return '#ffc107'
        elif score >= 40:
            return '#fd7e14'
        else:
            return '#dc3545'
    
    def _render_node_health(self, node_health: Dict) -> str:
        """Render node health HTML."""
        if not node_health:
            return "<p>No nodes monitored yet</p>"
        
        html = "<table style='width: 100%;'>"
        html += "<tr><th>Node</th><th>Status</th><th>Anomalies (1h)</th><th>Last Event</th></tr>"
        
        for node, stats in node_health.items():
            health = stats['health']
            html += f"""
            <tr>
                <td>{node}</td>
                <td><span class="health-status health-{health}">{health}</span></td>
                <td>{stats['total_anomalies']}</td>
                <td>{stats['last_anomaly'][:19] if stats['last_anomaly'] else 'N/A'}</td>
            </tr>
            """
        
        html += "</table>"
        return html
    
    def _render_recent_anomalies(self, anomalies: List[Dict]) -> str:
        """Render recent anomalies HTML."""
        if not anomalies:
            return "<p>✅ No anomalies detected in the last 24 hours</p>"
        
        html = ""
        for anomaly in anomalies:
            severity = anomaly.get('severity', 'LOW')
            html += f"""
            <div class="anomaly anomaly-{severity}">
                <strong>{severity}</strong> - {anomaly.get('description', 'Unknown')}
                <br><small>{anomaly.get('node', 'unknown')} | {anomaly.get('timestamp', '')[:19]}</small>
            </div>
            """
        
        return html


if __name__ == '__main__':
    print("=" * 70)
    print("SECURITY DASHBOARD TEST")
    print("=" * 70)
    print()
    
    print("To use dashboard:")
    print("1. Initialize with Supabase client:")
    print("   from src.utils.supabase_client import get_admin_client")
    print("   dashboard = SecurityDashboard(get_admin_client())")
    print()
    print("2. Get security score:")
    print("   score = dashboard.get_security_score()")
    print()
    print("3. Generate HTML dashboard:")
    print("   html = dashboard.generate_html_dashboard()")
    print("   with open('dashboard.html', 'w') as f:")
    print("       f.write(html)")
