"""Slack Integration for Security Alerts - Phase 2 Week 3-4"""
import os
import requests

def send_security_alert(severity, message, details=None):
    """Send security alert to Slack."""
    webhook_url = os.getenv('SLACK_WEBHOOK_URL')
    if not webhook_url:
        return
    
    color = {'CRITICAL': '#dc3545', 'HIGH': '#fd7e14', 'MEDIUM': '#ffc107', 'LOW': '#28a745'}.get(severity, '#6c757d')
    
    payload = {
        "attachments": [{
            "color": color,
            "title": f"🚨 {severity} Security Alert",
            "text": message,
            "fields": [{"title": k, "value": str(v), "short": True} for k, v in (details or {}).items()],
            "footer": "BidDeed.AI Security",
            "ts": int(datetime.now().timestamp())
        }]
    }
    
    try:
        requests.post(webhook_url, json=payload)
    except:
        pass
