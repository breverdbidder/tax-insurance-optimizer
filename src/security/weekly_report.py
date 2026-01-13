"""Weekly Security Report Automation - Phase 2 Week 3-4"""
from datetime import datetime, timedelta
from src.security.security_dashboard import SecurityDashboard
from src.security.anomaly_detector import get_detector

class WeeklySecurityReport:
    def __init__(self, supabase_client):
        self.dashboard = SecurityDashboard(supabase_client)
        self.detector = get_detector()
    
    def generate_report(self):
        score = self.dashboard.get_security_score()
        weekly = self.dashboard.get_weekly_summary()
        
        return {
            'security_score': score,
            'weekly_summary': weekly,
            'anomalies': len(self.detector.get_all_anomalies(since=datetime.now()-timedelta(days=7))),
            'recommendations': self._generate_recommendations(score)
        }
    
    def _generate_recommendations(self, score):
        if score['score'] < 60:
            return ["CRITICAL: Review security immediately"]
        elif score['score'] < 75:
            return ["Review recent anomalies"]
        return ["System healthy"]
