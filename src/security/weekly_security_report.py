"""
Weekly Security Report Generator

Generates comprehensive weekly security reports including:
- Anomaly summary
- Security alerts
- Circuit breaker trips
- Security score trends
- Top affected nodes
- Recommendations

Can send via Email or Slack webhook.

Usage:
    python src/security/weekly_security_report.py
    python src/security/weekly_security_report.py --slack-webhook <url>
"""

import os
import json
import argparse
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import requests


def generate_weekly_report(supabase_client) -> Dict:
    """Generate comprehensive weekly security report."""
    now = datetime.now()
    week_ago = now - timedelta(days=7)
    
    # Get anomalies
    anomalies_response = supabase_client.table('anomaly_metrics').select('*').gte(
        'timestamp', week_ago.isoformat()
    ).execute()
    anomalies = anomalies_response.data if anomalies_response.data else []
    
    # Get security alerts
    alerts_response = supabase_client.table('security_alerts').select('*').gte(
        'timestamp', week_ago.isoformat()
    ).execute()
    alerts = alerts_response.data if alerts_response.data else []
    
    # Aggregate statistics
    total_anomalies = len(anomalies)
    total_alerts = len(alerts)
    
    # By severity
    anomalies_by_severity = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for anomaly in anomalies:
        severity = anomaly.get('severity', 'LOW')
        anomalies_by_severity[severity] = anomalies_by_severity.get(severity, 0) + 1
    
    alerts_by_severity = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for alert in alerts:
        severity = alert.get('severity', 'LOW')
        alerts_by_severity[severity] = alerts_by_severity.get(severity, 0) + 1
    
    # By type
    anomalies_by_type = {}
    for anomaly in anomalies:
        atype = anomaly.get('anomaly_type', 'unknown')
        anomalies_by_type[atype] = anomalies_by_type.get(atype, 0) + 1
    
    # Top affected nodes
    nodes_affected = {}
    for anomaly in anomalies:
        node = anomaly.get('node', 'unknown')
        nodes_affected[node] = nodes_affected.get(node, 0) + 1
    
    top_nodes = sorted(nodes_affected.items(), key=lambda x: x[1], reverse=True)[:5]
    
    # Circuit breaker trips
    breaker_trips = sum(1 for a in anomalies if a.get('anomaly_type') == 'excessive_failures')
    
    # Security score calculation
    score = 100.0
    score -= min(anomalies_by_severity['CRITICAL'] * 10, 40)
    score -= min(anomalies_by_severity['HIGH'] * 5, 30)
    score -= min(alerts_by_severity['CRITICAL'] * 10, 20)
    score -= min(breaker_trips * 4, 10)
    score = max(0, score)
    
    # Recommendations
    recommendations = []
    if anomalies_by_severity['CRITICAL'] > 0:
        recommendations.append("🚨 CRITICAL anomalies detected - immediate investigation required")
    if breaker_trips > 3:
        recommendations.append("⚠️ Multiple circuit breaker trips - check node health")
    if anomalies_by_severity['HIGH'] > 10:
        recommendations.append("📊 High anomaly count - review security thresholds")
    if score < 70:
        recommendations.append("🔧 Security score below 70 - implement remediation plan")
    
    if not recommendations:
        recommendations.append("✅ Security posture is healthy - maintain current practices")
    
    # Daily breakdown
    daily_breakdown = {}
    for i in range(7):
        day = (week_ago + timedelta(days=i)).strftime('%Y-%m-%d')
        daily_breakdown[day] = {
            'anomalies': sum(1 for a in anomalies if a['timestamp'][:10] == day),
            'alerts': sum(1 for a in alerts if a['timestamp'][:10] == day)
        }
    
    return {
        'period': f"{week_ago.strftime('%Y-%m-%d')} to {now.strftime('%Y-%m-%d')}",
        'generated_at': now.isoformat(),
        'summary': {
            'total_anomalies': total_anomalies,
            'total_alerts': total_alerts,
            'circuit_breaker_trips': breaker_trips,
            'security_score': round(score, 1)
        },
        'anomalies_by_severity': anomalies_by_severity,
        'alerts_by_severity': alerts_by_severity,
        'anomalies_by_type': dict(sorted(anomalies_by_type.items(), key=lambda x: x[1], reverse=True)[:5]),
        'top_affected_nodes': [{'node': node, 'count': count} for node, count in top_nodes],
        'daily_breakdown': daily_breakdown,
        'recommendations': recommendations,
        'score_grade': _score_to_grade(score)
    }


def _score_to_grade(score: float) -> str:
    """Convert score to grade."""
    if score >= 95: return 'A+'
    elif score >= 90: return 'A'
    elif score >= 85: return 'B+'
    elif score >= 80: return 'B'
    elif score >= 75: return 'C+'
    elif score >= 70: return 'C'
    elif score >= 60: return 'D'
    else: return 'F'


def format_markdown_report(report: Dict) -> str:
    """Format report as Markdown."""
    md = f"""# 🛡️ Weekly Security Report

**Period**: {report['period']}
**Generated**: {report['generated_at'][:19]}

---

## 📊 Summary

- **Security Score**: {report['summary']['security_score']} ({report['score_grade']})
- **Total Anomalies**: {report['summary']['total_anomalies']}
- **Total Alerts**: {report['summary']['total_alerts']}
- **Circuit Breaker Trips**: {report['summary']['circuit_breaker_trips']}

---

## 🚨 Anomalies by Severity

| Severity | Count |
|----------|-------|
| CRITICAL | {report['anomalies_by_severity']['CRITICAL']} |
| HIGH | {report['anomalies_by_severity']['HIGH']} |
| MEDIUM | {report['anomalies_by_severity']['MEDIUM']} |
| LOW | {report['anomalies_by_severity']['LOW']} |

---

## 🔴 Security Alerts by Severity

| Severity | Count |
|----------|-------|
| CRITICAL | {report['alerts_by_severity']['CRITICAL']} |
| HIGH | {report['alerts_by_severity']['HIGH']} |
| MEDIUM | {report['alerts_by_severity']['MEDIUM']} |
| LOW | {report['alerts_by_severity']['LOW']} |

---

## 📈 Top Anomaly Types

"""
    for atype, count in report['anomalies_by_type'].items():
        md += f"- **{atype}**: {count}\n"
    
    md += "\n---\n\n## 🎯 Top Affected Nodes\n\n"
    for node_data in report['top_affected_nodes']:
        md += f"- **{node_data['node']}**: {node_data['count']} anomalies\n"
    
    md += "\n---\n\n## 📅 Daily Breakdown\n\n"
    for day, counts in report['daily_breakdown'].items():
        md += f"- **{day}**: {counts['anomalies']} anomalies, {counts['alerts']} alerts\n"
    
    md += "\n---\n\n## 💡 Recommendations\n\n"
    for rec in report['recommendations']:
        md += f"- {rec}\n"
    
    return md


def send_to_slack(report: Dict, webhook_url: str):
    """Send report to Slack via webhook."""
    score = report['summary']['security_score']
    
    # Choose emoji based on score
    if score >= 90:
        emoji = "✅"
    elif score >= 75:
        emoji = "⚠️"
    else:
        emoji = "🚨"
    
    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{emoji} Weekly Security Report"
            }
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Period*\n{report['period']}"},
                {"type": "mrkdwn", "text": f"*Security Score*\n{score} ({report['score_grade']})"}
            ]
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Anomalies*\n{report['summary']['total_anomalies']}"},
                {"type": "mrkdwn", "text": f"*Circuit Breakers*\n{report['summary']['circuit_breaker_trips']}"}
            ]
        },
        {
            "type": "divider"
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*🚨 Critical Events*\n" + 
                        f"• Critical Anomalies: {report['anomalies_by_severity']['CRITICAL']}\n" +
                        f"• Critical Alerts: {report['alerts_by_severity']['CRITICAL']}"
            }
        }
    ]
    
    # Add recommendations
    if report['recommendations']:
        recs_text = "*💡 Recommendations*\n"
        for rec in report['recommendations'][:3]:  # Top 3
            recs_text += f"• {rec}\n"
        
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": recs_text}
        })
    
    payload = {
        "blocks": blocks
    }
    
    response = requests.post(webhook_url, json=payload)
    
    if response.status_code == 200:
        print("✅ Report sent to Slack")
    else:
        print(f"❌ Failed to send to Slack: {response.status_code}")


def main():
    parser = argparse.ArgumentParser(description='Generate weekly security report')
    parser.add_argument('--slack-webhook', help='Slack webhook URL for notifications')
    parser.add_argument('--output', default='weekly_security_report.md', help='Output file path')
    args = parser.parse_args()
    
    print("=" * 70)
    print("WEEKLY SECURITY REPORT GENERATOR")
    print("=" * 70)
    print()
    
    # Import supabase client
    try:
        from src.utils.supabase_client import get_admin_client
        client = get_admin_client()
    except Exception as e:
        print(f"❌ Failed to initialize Supabase client: {e}")
        return
    
    # Generate report
    print("📊 Generating report...")
    report = generate_weekly_report(client)
    
    # Format as Markdown
    md_report = format_markdown_report(report)
    
    # Save to file
    with open(args.output, 'w') as f:
        f.write(md_report)
    
    print(f"✅ Report saved to {args.output}")
    
    # Print summary
    print()
    print("Summary:")
    print(f"  Security Score: {report['summary']['security_score']} ({report['score_grade']})")
    print(f"  Total Anomalies: {report['summary']['total_anomalies']}")
    print(f"  Circuit Breaker Trips: {report['summary']['circuit_breaker_trips']}")
    
    # Send to Slack if webhook provided
    if args.slack_webhook:
        print()
        print("📤 Sending to Slack...")
        send_to_slack(report, args.slack_webhook)
    
    print()
    print("=" * 70)


if __name__ == '__main__':
    main()
