#!/usr/bin/env python3
"""
Alert Triage Helper
Analyse une alerte et recommande True/False Positive avec scoring
"""

import json
import sys
import os
import requests
from dotenv import load_dotenv
from datetime import datetime

# Charge variables d'environnement
load_dotenv()

def check_ip_reputation(ip_address):
    """
    Check IP reputation via AbuseIPDB
    """
    api_key = os.getenv('ABUSEIPDB_API_KEY')
    
    if not api_key:
        print("[!] Warning: ABUSEIPDB_API_KEY not found, using simulated data")
        # Simulation pour test
        return {'abuseConfidenceScore': 0, 'totalReports': 0}
    
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {'Key': api_key, 'Accept': 'application/json'}
    params = {'ipAddress': ip_address, 'maxAgeInDays': 90}
    
    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            return response.json()['data']
        return None
    except Exception as e:
        print(f"[!] Error checking IP: {e}")
        return None


def analyze_alert(alert_data):
    """
    Analyse l'alerte et calcule risk score
    """
    risk_score = 0
    risk_factors = []
    
    # 1. Check IP reputation
    src_ip = alert_data.get('src_ip') or alert_data.get('source_ip')
    
    if src_ip:
        ip_data = check_ip_reputation(src_ip)
        
        if ip_data:
            abuse_score = ip_data.get('abuseConfidenceScore', 0)
            
            if abuse_score > 75:
                risk_score += 40
                risk_factors.append(f"IP malicious (abuse score: {abuse_score}/100)")
            elif abuse_score > 50:
                risk_score += 25
                risk_factors.append(f"IP suspicious (abuse score: {abuse_score}/100)")
    
    # 2. Check time (off-hours)
    timestamp = alert_data.get('timestamp')
    if timestamp:
        try:
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            hour = dt.hour
            
            # Off-hours: 22h-6h
            if hour < 6 or hour >= 22:
                risk_score += 20
                risk_factors.append(f"Off-hours connection ({hour:02d}:00)")
        except:
            pass
    
    # 3. Check failed attempts
    failed_attempts = alert_data.get('failed_attempts', 0)
    
    if failed_attempts >= 10:
        risk_score += 20
        risk_factors.append(f"High failed attempts ({failed_attempts})")
    elif failed_attempts >= 5:
        risk_score += 10
        risk_factors.append(f"Medium failed attempts ({failed_attempts})")
    
    # 4. Check if success after failures
    successful = alert_data.get('successful_logins', 0) > 0 or alert_data.get('success', False)
    
    if successful and failed_attempts >= 3:
        risk_score += 20
        risk_factors.append("Successful login after multiple failures")
    
    # 5. Determine verdict
    if risk_score >= 70:
        verdict = "TRUE POSITIVE"
        confidence = "High"
        color = "\033[91m"  # Red
    elif risk_score >= 40:
        verdict = "SUSPICIOUS"
        confidence = "Medium"
        color = "\033[93m"  # Yellow
    else:
        verdict = "LIKELY FALSE POSITIVE"
        confidence = "Low"
        color = "\033[92m"  # Green
    
    return {
        'risk_score': risk_score,
        'risk_factors': risk_factors,
        'verdict': verdict,
        'confidence': confidence,
        'color': color
    }


def print_analysis(alert_data, analysis):
    """
    Affiche l'analyse formatée
    """
    reset = "\033[0m"
    
    print("\n" + "="*60)
    print("ALERT TRIAGE ANALYSIS")
    print("="*60)
    
    # Alert Info
    print(f"\n🚨 ALERT DETAILS:")
    print(f"   ID:       {alert_data.get('alert_id', 'N/A')}")
    print(f"   Type:     {alert_data.get('type', alert_data.get('event_type', 'N/A'))}")
    print(f"   Severity: {alert_data.get('severity', 'N/A')}")
    print(f"   Source:   {alert_data.get('src_ip', alert_data.get('source_ip', 'N/A'))}")
    print(f"   User:     {alert_data.get('user', alert_data.get('username', 'N/A'))}")
    print(f"   Time:     {alert_data.get('timestamp', 'N/A')}")
    
    # Risk Analysis
    print(f"\n⚡ RISK ANALYSIS:")
    print(f"   Risk Score: {analysis['risk_score']}/100")
    print(f"   Confidence: {analysis['confidence']}")
    
    if analysis['risk_factors']:
        print(f"\n   Risk Factors:")
        for factor in analysis['risk_factors']:
            print(f"   🚩 {factor}")
    else:
        print(f"\n   ✅ No significant risk factors")
    
    # Verdict
    print(f"\n📊 VERDICT:")
    print(f"   {analysis['color']}{analysis['verdict']}{reset}")
    
    # Recommendations
    print(f"\n💡 RECOMMENDATIONS:")
    
    if analysis['risk_score'] >= 70:
        print(f"   ⚠️  ESCALATE to SOC L2 immediately")
        print(f"   ⚠️  Block source IP on firewall")
        print(f"   ⚠️  Disable affected user account")
        print(f"   ⚠️  Begin forensic investigation")
    elif analysis['risk_score'] >= 40:
        print(f"   ⚠️  Manual investigation required")
        print(f"   ⚠️  Verify with user if connection legitimate")
        print(f"   ⚠️  Monitor closely for 24h")
    else:
        print(f"   ✅ Mark as False Positive")
        print(f"   ✅ Document reasoning in ticket")
        print(f"   ✅ Close alert")
    
    print("\n" + "="*60 + "\n")


def main():
    """
    Fonction principale
    """
    if len(sys.argv) < 2:
        print("Usage: python alert_triage.py <alert.json>")
        print("Example: python alert_triage.py alert_12345.json")
        sys.exit(1)
    
    alert_file = sys.argv[1]
    
    try:
        with open(alert_file, 'r') as f:
            alert_data = json.load(f)
    except FileNotFoundError:
        print(f"[!] Error: File '{alert_file}' not found")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"[!] Error: Invalid JSON in '{alert_file}'")
        sys.exit(1)
    
    print(f"\n🔍 Alert Triage Helper")
    print(f"Analyzing: {alert_file}\n")
    
    # Analyze
    analysis = analyze_alert(alert_data)
    
    # Print results
    print_analysis(alert_data, analysis)
    
    # Save analysis
    output_file = alert_file.replace('.json', '_analysis.json')
    result = {
        'alert': alert_data,
        'analysis': {
            'risk_score': analysis['risk_score'],
            'risk_factors': analysis['risk_factors'],
            'verdict': analysis['verdict'],
            'confidence': analysis['confidence']
        },
        'timestamp': datetime.now().isoformat()
    }
    
    with open(output_file, 'w') as f:
        json.dump(result, f, indent=2)
    
    print(f"📁 Analysis saved to: {output_file}")


if __name__ == "__main__":
    main()