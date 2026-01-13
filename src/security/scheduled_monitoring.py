"""
Scheduled Security Monitoring

Runs daily security checks and generates reports.
Can be run as cron job or GitHub Actions scheduled workflow.

Schedule:
- Daily at midnight: Security score calculation
- Weekly on Monday: Comprehensive security report
- Hourly: Anomaly detection and alerting
"""

import os
import sys
from datetime import datetime
from pathlib import Path


def run_daily_security_check():
    """Run daily security monitoring tasks."""
    print("=" * 70)
    print("DAILY SECURITY CHECK")
    print("=" * 70)
    print(f"Timestamp: {datetime.now().isoformat()}")
    print()
    
    # Import security components
    from src.security.security_dashboard import SecurityDashboard
    from src.security.anomaly_detector import get_detector
    from src.utils.supabase_client import get_admin_client
    
    client = get_admin_client()
    dashboard = SecurityDashboard(client)
    detector = get_detector()
    
    # 1. Calculate security score
    print("1. Calculating security score...")
    score_data = dashboard.get_security_score()
    print(f"   Security Score: {score_data['score']}/100 ({score_data['grade']})")
    print(f"   Status: {score_data['status']}")
    print()
    
    # 2. Check node health
    print("2. Checking node health...")
    node_health = dashboard.get_node_health_summary()
    
    if not node_health:
        print("   No nodes monitored yet")
    else:
        for node, stats in node_health.items():
            print(f"   {node}: {stats['health']} ({stats['total_anomalies']} anomalies)")
    print()
    
    # 3. Get recent anomalies
    print("3. Recent anomalies (24h)...")
    recent_anomalies = dashboard.get_recent_anomalies(hours=24)
    
    critical = sum(1 for a in recent_anomalies if a.get('severity') == 'CRITICAL')
    high = sum(1 for a in recent_anomalies if a.get('severity') == 'HIGH')
    
    print(f"   Total: {len(recent_anomalies)}")
    print(f"   Critical: {critical}")
    print(f"   High: {high}")
    print()
    
    # 4. Alert on critical issues
    if critical > 0:
        print(f"⚠️ WARNING: {critical} CRITICAL anomalies detected!")
        for anomaly in recent_anomalies:
            if anomaly.get('severity') == 'CRITICAL':
                print(f"   - {anomaly.get('description')}")
        print()
    
    # 5. Generate HTML dashboard
    print("4. Generating HTML dashboard...")
    html = dashboard.generate_html_dashboard()
    
    output_dir = Path('reports')
    output_dir.mkdir(exist_ok=True)
    
    output_path = output_dir / f"security_dashboard_{datetime.now().strftime('%Y%m%d')}.html"
    with open(output_path, 'w') as f:
        f.write(html)
    
    print(f"   Dashboard saved: {output_path}")
    print()
    
    # 6. Summary
    print("=" * 70)
    print("DAILY CHECK COMPLETE")
    print("=" * 70)
    print(f"Score: {score_data['score']}/100 | Status: {score_data['status']}")
    print(f"Anomalies: {len(recent_anomalies)} | Critical: {critical}")
    print()
    
    return score_data['score']


def run_weekly_security_report():
    """Generate comprehensive weekly security report."""
    print("=" * 70)
    print("WEEKLY SECURITY REPORT")
    print("=" * 70)
    print(f"Timestamp: {datetime.now().isoformat()}")
    print()
    
    from src.security.weekly_report import WeeklySecurityReport
    from src.utils.supabase_client import get_admin_client
    
    client = get_admin_client()
    reporter = WeeklySecurityReport(client)
    
    # Generate report
    print("Generating weekly report...")
    report = reporter.generate_report()
    
    print(f"Security Score: {report['security_score']['average_score']}/100")
    print(f"Trend: {report['security_score']['trend']}")
    print(f"Total Anomalies: {report['anomaly_summary']['total']}")
    print(f"Total Alerts: {report['alert_summary']['total']}")
    print()
    
    # Save markdown report
    output_dir = Path('reports')
    output_dir.mkdir(exist_ok=True)
    
    output_path = output_dir / f"weekly_security_report_{datetime.now().strftime('%Y%m%d')}.md"
    reporter.save_report(str(output_path))
    
    print(f"Report saved: {output_path}")
    print()
    
    # Show recommendations
    print("Recommendations:")
    for rec in report['recommendations']:
        print(f"  {rec}")
    print()
    
    return report


def run_hourly_anomaly_check():
    """Run hourly anomaly detection."""
    print("=" * 70)
    print("HOURLY ANOMALY CHECK")
    print("=" * 70)
    print(f"Timestamp: {datetime.now().isoformat()}")
    print()
    
    from src.security.security_dashboard import SecurityDashboard
    from src.utils.supabase_client import get_admin_client
    
    client = get_admin_client()
    dashboard = SecurityDashboard(client)
    
    # Get recent anomalies (last hour)
    recent_anomalies = dashboard.get_recent_anomalies(hours=1)
    
    critical = [a for a in recent_anomalies if a.get('severity') == 'CRITICAL']
    high = [a for a in recent_anomalies if a.get('severity') == 'HIGH']
    
    print(f"Anomalies (last hour): {len(recent_anomalies)}")
    print(f"Critical: {len(critical)}")
    print(f"High: {len(high)}")
    print()
    
    # Alert on critical
    if critical:
        print("🚨 CRITICAL ANOMALIES:")
        for anomaly in critical:
            print(f"  - {anomaly.get('node')}: {anomaly.get('description')}")
        print()
    
    # Alert on high
    if high:
        print("⚠️ HIGH ANOMALIES:")
        for anomaly in high[:5]:  # Top 5
            print(f"  - {anomaly.get('node')}: {anomaly.get('description')}")
        print()
    
    return len(critical), len(high)


def main():
    """Main entry point for scheduled monitoring."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Run scheduled security monitoring')
    parser.add_argument(
        'frequency',
        choices=['hourly', 'daily', 'weekly'],
        help='Monitoring frequency'
    )
    
    args = parser.parse_args()
    
    try:
        if args.frequency == 'hourly':
            run_hourly_anomaly_check()
        elif args.frequency == 'daily':
            run_daily_security_check()
        elif args.frequency == 'weekly':
            run_weekly_security_report()
        
        sys.exit(0)
    
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    # If run without arguments, do daily check
    if len(sys.argv) == 1:
        run_daily_security_check()
    else:
        main()
