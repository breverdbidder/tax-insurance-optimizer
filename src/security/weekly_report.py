"""
Weekly Security Report Generator

Automatically generates comprehensive security reports including:
- Security score trends
- Top anomalies and alerts
- Node health summary
- Compliance status
- Recommendations

Part of Phase 2 - Week 3-4: Monitoring & Reporting
"""

import os
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional


class WeeklySecurityReport:
    """
    Generates weekly security reports for management review.
    """
    
    def __init__(self, supabase_client):
        self.supabase = supabase_client
    
    def get_weekly_anomalies(self) -> List[Dict]:
        """Get all anomalies from the last 7 days."""
        cutoff = (datetime.now() - timedelta(days=7)).isoformat()
        
        response = self.supabase.table('anomaly_metrics').select('*').gte(
            'timestamp', cutoff
        ).order('timestamp', desc=True).execute()
        
        return response.data if response.data else []
    
    def get_weekly_alerts(self) -> List[Dict]:
        """Get all security alerts from the last 7 days."""
        cutoff = (datetime.now() - timedelta(days=7)).isoformat()
        
        response = self.supabase.table('security_alerts').select('*').gte(
            'timestamp', cutoff
        ).order('timestamp', desc=True).execute()
        
        return response.data if response.data else []
    
    def calculate_weekly_score(self) -> Dict:
        """Calculate average security score for the week."""
        anomalies = self.get_weekly_anomalies()
        alerts = self.get_weekly_alerts()
        
        # Score calculation (same as dashboard)
        daily_scores = []
        
        for day_offset in range(7):
            day = datetime.now() - timedelta(days=day_offset)
            day_str = day.strftime('%Y-%m-%d')
            
            day_anomalies = [a for a in anomalies if a['timestamp'].startswith(day_str)]
            day_alerts = [a for a in alerts if a['timestamp'].startswith(day_str)]
            
            score = 100.0
            
            # Anomaly penalty
            for anomaly in day_anomalies:
                severity = anomaly.get('severity', 'LOW')
                if severity == 'CRITICAL':
                    score -= 10
                elif severity == 'HIGH':
                    score -= 5
                elif severity == 'MEDIUM':
                    score -= 2
                else:
                    score -= 0.5
            
            # Alert penalty
            for alert in day_alerts:
                severity = alert.get('severity', 'LOW')
                if severity == 'CRITICAL':
                    score -= 10
                elif severity == 'HIGH':
                    score -= 5
                else:
                    score -= 1
            
            daily_scores.append(max(0, score))
        
        avg_score = sum(daily_scores) / len(daily_scores) if daily_scores else 0
        
        return {
            'average_score': round(avg_score, 1),
            'daily_scores': daily_scores,
            'trend': self._calculate_trend(daily_scores)
        }
    
    def _calculate_trend(self, scores: List[float]) -> str:
        """Calculate trend direction."""
        if len(scores) < 2:
            return 'STABLE'
        
        recent = sum(scores[:3]) / 3
        older = sum(scores[3:]) / max(1, len(scores[3:]))
        
        if recent > older + 5:
            return 'IMPROVING'
        elif recent < older - 5:
            return 'DECLINING'
        else:
            return 'STABLE'
    
    def get_top_anomalies(self, limit: int = 10) -> List[Dict]:
        """Get top anomalies by severity."""
        anomalies = self.get_weekly_anomalies()
        
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        
        sorted_anomalies = sorted(
            anomalies,
            key=lambda x: severity_order.get(x.get('severity', 'LOW'), 4)
        )
        
        return sorted_anomalies[:limit]
    
    def get_node_performance(self) -> Dict:
        """Get performance metrics per node."""
        anomalies = self.get_weekly_anomalies()
        
        node_stats = {}
        
        for anomaly in anomalies:
            node = anomaly.get('node', 'unknown')
            
            if node not in node_stats:
                node_stats[node] = {
                    'total_anomalies': 0,
                    'critical': 0,
                    'high': 0,
                    'medium': 0,
                    'low': 0,
                    'types': {}
                }
            
            node_stats[node]['total_anomalies'] += 1
            
            severity = anomaly.get('severity', 'LOW').lower()
            if severity in node_stats[node]:
                node_stats[node][severity] += 1
            
            anomaly_type = anomaly.get('anomaly_type', 'unknown')
            node_stats[node]['types'][anomaly_type] = node_stats[node]['types'].get(anomaly_type, 0) + 1
        
        return node_stats
    
    def generate_recommendations(self) -> List[str]:
        """Generate security recommendations based on weekly data."""
        recommendations = []
        
        anomalies = self.get_weekly_anomalies()
        alerts = self.get_weekly_alerts()
        score_data = self.calculate_weekly_score()
        
        # Check critical anomalies
        critical_count = sum(1 for a in anomalies if a.get('severity') == 'CRITICAL')
        if critical_count > 0:
            recommendations.append(
                f"⚠️ {critical_count} CRITICAL anomalies detected this week. "
                "Review circuit breaker configurations and failure thresholds."
            )
        
        # Check score trend
        if score_data['trend'] == 'DECLINING':
            recommendations.append(
                "📉 Security score declining. Investigate recent changes "
                "and review anomaly patterns."
            )
        
        # Check excessive failures
        excessive_failures = sum(
            1 for a in anomalies 
            if a.get('anomaly_type') == 'excessive_failures'
        )
        if excessive_failures > 5:
            recommendations.append(
                f"🔄 {excessive_failures} circuit breaker trips this week. "
                "Review node reliability and error handling."
            )
        
        # Check rate limiting
        rate_limit_violations = sum(
            1 for a in anomalies
            if a.get('anomaly_type') == 'rate_limit_exceeded'
        )
        if rate_limit_violations > 10:
            recommendations.append(
                f"⏱️ {rate_limit_violations} rate limit violations. "
                "Consider increasing thresholds or optimizing request patterns."
            )
        
        # Check output anomalies
        output_anomalies = sum(
            1 for a in anomalies
            if a.get('anomaly_type') in ['excessive_output', 'suspicious_pattern']
        )
        if output_anomalies > 0:
            recommendations.append(
                f"📤 {output_anomalies} output anomalies detected. "
                "Review LLM prompts and output validation rules."
            )
        
        if not recommendations:
            recommendations.append("✅ No critical issues detected. Security posture is healthy.")
        
        return recommendations
    
    def generate_report(self) -> Dict:
        """Generate complete weekly security report."""
        return {
            'report_date': datetime.now().isoformat(),
            'period': '7 days',
            'security_score': self.calculate_weekly_score(),
            'anomaly_summary': {
                'total': len(self.get_weekly_anomalies()),
                'by_severity': self._count_by_severity(self.get_weekly_anomalies()),
                'top_10': self.get_top_anomalies(10)
            },
            'alert_summary': {
                'total': len(self.get_weekly_alerts()),
                'by_severity': self._count_by_severity(self.get_weekly_alerts())
            },
            'node_performance': self.get_node_performance(),
            'recommendations': self.generate_recommendations()
        }
    
    def _count_by_severity(self, items: List[Dict]) -> Dict:
        """Count items by severity."""
        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        
        for item in items:
            severity = item.get('severity', 'LOW')
            if severity in counts:
                counts[severity] += 1
        
        return counts
    
    def generate_markdown_report(self) -> str:
        """Generate markdown-formatted report."""
        report = self.generate_report()
        
        md = f"""# Weekly Security Report

**Report Date**: {report['report_date'][:10]}
**Period**: {report['period']}

---

## Executive Summary

### Security Score
- **Average**: {report['security_score']['average_score']}/100
- **Trend**: {report['security_score']['trend']}

### Key Metrics
- **Total Anomalies**: {report['anomaly_summary']['total']}
- **Total Alerts**: {report['alert_summary']['total']}
- **Critical Events**: {report['anomaly_summary']['by_severity']['CRITICAL'] + report['alert_summary']['by_severity']['CRITICAL']}

---

## Anomalies by Severity

| Severity | Count |
|----------|-------|
| CRITICAL | {report['anomaly_summary']['by_severity']['CRITICAL']} |
| HIGH | {report['anomaly_summary']['by_severity']['HIGH']} |
| MEDIUM | {report['anomaly_summary']['by_severity']['MEDIUM']} |
| LOW | {report['anomaly_summary']['by_severity']['LOW']} |

---

## Top 10 Anomalies

"""
        for i, anomaly in enumerate(report['anomaly_summary']['top_10'], 1):
            md += f"{i}. **{anomaly.get('severity')}** - {anomaly.get('description', 'N/A')}\n"
            md += f"   - Node: {anomaly.get('node', 'unknown')}\n"
            md += f"   - Time: {anomaly.get('timestamp', '')[:19]}\n\n"
        
        md += """---

## Node Performance

"""
        for node, stats in report['node_performance'].items():
            md += f"### {node}\n"
            md += f"- Total Anomalies: {stats['total_anomalies']}\n"
            md += f"- Critical: {stats['critical']} | High: {stats['high']} | Medium: {stats['medium']} | Low: {stats['low']}\n\n"
        
        md += """---

## Recommendations

"""
        for rec in report['recommendations']:
            md += f"- {rec}\n"
        
        md += f"\n---\n\n*Generated: {datetime.now().isoformat()}*\n"
        
        return md
    
    def save_report(self, output_path: str = 'weekly_security_report.md'):
        """Generate and save report to file."""
        report_md = self.generate_markdown_report()
        
        with open(output_path, 'w') as f:
            f.write(report_md)
        
        print(f"✅ Report saved to {output_path}")
        return output_path


if __name__ == '__main__':
    print("=" * 70)
    print("WEEKLY SECURITY REPORT GENERATOR")
    print("=" * 70)
    print()
    print("Usage:")
    print()
    print("from src.security.weekly_report import WeeklySecurityReport")
    print("from src.utils.supabase_client import get_admin_client")
    print()
    print("reporter = WeeklySecurityReport(get_admin_client())")
    print("report = reporter.generate_report()")
    print()
    print("# Save to file")
    print("reporter.save_report('weekly_security_report.md')")
