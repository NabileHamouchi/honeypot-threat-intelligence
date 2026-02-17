#!/usr/bin/env python3
"""
IP Enrichment Tool
Enrichit une IP avec threat intelligence (reputation, geolocation, WHOIS)

Usage:
    python ip_enrichment.py <IP_ADDRESS>
    
Example:
    python ip_enrichment.py 185.220.101.50
"""

import requests
import json
import sys
import os
from datetime import datetime
from dotenv import load_dotenv

# Charge les variables d'environnement depuis .env
load_dotenv()


def check_abuseipdb(ip_address):
    """
    Vérifie reputation IP sur AbuseIPDB
    
    Args:
        ip_address (str): L'adresse IP à vérifier
        
    Returns:
        dict: Données de reputation ou None si erreur
    """
    print(f"[*] Checking AbuseIPDB for {ip_address}...")
    
    # Récupère la clé API depuis le fichier .env
    api_key = os.getenv('ABUSEIPDB_API_KEY')
    
    if not api_key:
        print("[!] Error: ABUSEIPDB_API_KEY not found in .env file")
        return None
    
    url = "https://api.abuseipdb.com/api/v2/check"
    
    headers = {
        'Key': api_key,
        'Accept': 'application/json'
    }
    
    params = {
        'ipAddress': ip_address,
        'maxAgeInDays': 90,
        'verbose': True
    }
    
    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        
        if response.status_code == 200:
            data = response.json()['data']
            return {
                'abuseConfidenceScore': data.get('abuseConfidenceScore', 0),
                'totalReports': data.get('totalReports', 0),
                'numDistinctUsers': data.get('numDistinctUsers', 0),
                'lastReportedAt': data.get('lastReportedAt', 'N/A'),
                'isMalicious': data.get('abuseConfidenceScore', 0) > 50,
                'usageType': data.get('usageType', 'Unknown'),
                'isp': data.get('isp', 'Unknown')
            }
        elif response.status_code == 429:
            print("[!] AbuseIPDB API rate limit exceeded (1000 requests/day)")
            return None
        else:
            print(f"[!] AbuseIPDB API error: {response.status_code}")
            return None
        
    except requests.exceptions.Timeout:
        print("[!] AbuseIPDB API request timeout")
        return None
    except Exception as e:
        print(f"[!] Error checking AbuseIPDB: {e}")
        return None


def check_ipinfo(ip_address):
    """
    Récupère géolocalisation via IPInfo.io
    
    Args:
        ip_address (str): L'adresse IP à vérifier
        
    Returns:
        dict: Données de géolocalisation ou None si erreur
    """
    print(f"[*] Checking IPInfo.io for {ip_address}...")
    
    url = f"https://ipinfo.io/{ip_address}/json"
    
    try:
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            return {
                'country': data.get('country', 'Unknown'),
                'city': data.get('city', 'Unknown'),
                'region': data.get('region', 'Unknown'),
                'org': data.get('org', 'Unknown'),
                'timezone': data.get('timezone', 'Unknown'),
                'loc': data.get('loc', 'Unknown')
            }
        else:
            print(f"[!] IPInfo.io error: {response.status_code}")
            return None
            
    except requests.exceptions.Timeout:
        print("[!] IPInfo.io request timeout")
        return None
    except Exception as e:
        print(f"[!] Error checking IPInfo: {e}")
        return None


def analyze_risk(abuse_data, geo_data):
    """
    Analyse le niveau de risque basé sur les données collectées
    
    Args:
        abuse_data (dict): Données AbuseIPDB
        geo_data (dict): Données de géolocalisation
        
    Returns:
        dict: Analyse de risque avec score et verdict
    """
    risk_score = 0
    risk_factors = []
    
    # Critère 1: Reputation score
    if abuse_data:
        abuse_score = abuse_data.get('abuseConfidenceScore', 0)
        if abuse_score > 75:
            risk_score += 40
            risk_factors.append(f"High abuse score ({abuse_score}/100)")
        elif abuse_score > 50:
            risk_score += 25
            risk_factors.append(f"Medium abuse score ({abuse_score}/100)")
        elif abuse_score > 25:
            risk_score += 10
            risk_factors.append(f"Low abuse score ({abuse_score}/100)")
    
    # Critère 2: Nombre de rapports
    if abuse_data:
        total_reports = abuse_data.get('totalReports', 0)
        if total_reports > 100:
            risk_score += 20
            risk_factors.append(f"Many abuse reports ({total_reports})")
        elif total_reports > 50:
            risk_score += 10
            risk_factors.append(f"Multiple abuse reports ({total_reports})")
    
    # Critère 3: Géolocalisation
    if geo_data:
        high_risk_countries = ['RU', 'CN', 'KP', 'IR', 'BY']
        country = geo_data.get('country', '')
        if country in high_risk_countries:
            risk_score += 30
            risk_factors.append(f"High-risk country ({country})")
    
    # Critère 4: Type d'usage (Data Center = plus suspect)
    if abuse_data:
        usage_type = abuse_data.get('usageType', '')
        if 'Data Center' in usage_type or 'Hosting' in usage_type:
            risk_score += 10
            risk_factors.append("Data Center/Hosting IP (often used by bots)")
    
    # Critère 5: Activité récente
    if abuse_data:
        last_report = abuse_data.get('lastReportedAt')
        if last_report and last_report != 'N/A':
            risk_score += 5
            risk_factors.append("Recently reported (active threat)")
    
    # Détermination du verdict
    if risk_score >= 70:
        verdict = "⚠️  MALICIOUS - Block immediately"
        color = "\033[91m"  # Red
        recommendation = "critical"
    elif risk_score >= 40:
        verdict = "⚠️  SUSPICIOUS - Investigate further"
        color = "\033[93m"  # Yellow
        recommendation = "investigate"
    else:
        verdict = "✅ CLEAN - Likely legitimate"
        color = "\033[92m"  # Green
        recommendation = "monitor"
    
    return {
        'risk_score': risk_score,
        'risk_factors': risk_factors,
        'verdict': verdict,
        'color': color,
        'recommendation': recommendation
    }


def print_report(ip_address, abuse_data, geo_data, risk_analysis):
    """
    Affiche le rapport formaté dans le terminal
    
    Args:
        ip_address (str): L'IP analysée
        abuse_data (dict): Données AbuseIPDB
        geo_data (dict): Données géolocalisation
        risk_analysis (dict): Analyse de risque
    """
    reset_color = "\033[0m"
    bold = "\033[1m"
    
    print("\n" + "="*70)
    print(f"{bold}IP INTELLIGENCE REPORT{reset_color}")
    print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*70)
    
    print(f"\n🎯 {bold}TARGET IP:{reset_color} {ip_address}")
    
    # Section Geolocation
    if geo_data:
        print(f"\n📍 {bold}GEOLOCATION:{reset_color}")
        print(f"   Country:    {geo_data.get('country', 'Unknown')}")
        print(f"   City:       {geo_data.get('city', 'Unknown')}")
        print(f"   Region:     {geo_data.get('region', 'Unknown')}")
        print(f"   ISP/Org:    {geo_data.get('org', 'Unknown')}")
        print(f"   Timezone:   {geo_data.get('timezone', 'Unknown')}")
        print(f"   Coords:     {geo_data.get('loc', 'Unknown')}")
    else:
        print(f"\n📍 {bold}GEOLOCATION:{reset_color} Data not available")
    
    # Section Reputation
    if abuse_data:
        print(f"\n🔍 {bold}REPUTATION (AbuseIPDB):{reset_color}")
        print(f"   Abuse Score:      {abuse_data.get('abuseConfidenceScore', 0)}/100")
        print(f"   Total Reports:    {abuse_data.get('totalReports', 0)}")
        print(f"   Distinct Users:   {abuse_data.get('numDistinctUsers', 0)}")
        print(f"   Last Reported:    {abuse_data.get('lastReportedAt', 'N/A')}")
        print(f"   Usage Type:       {abuse_data.get('usageType', 'Unknown')}")
        print(f"   ISP:              {abuse_data.get('isp', 'Unknown')}")
        print(f"   Is Malicious:     {abuse_data.get('isMalicious', False)}")
    else:
        print(f"\n🔍 {bold}REPUTATION:{reset_color} Data not available")
    
    # Section Risk Analysis
    print(f"\n⚡ {bold}RISK ANALYSIS:{reset_color}")
    print(f"   Risk Score: {risk_analysis['risk_score']}/100")
    
    if risk_analysis['risk_factors']:
        print(f"\n   Risk Factors:")
        for factor in risk_analysis['risk_factors']:
            print(f"   🚩 {factor}")
    else:
        print(f"   ✅ No significant risk factors detected")
    
    # Verdict
    print(f"\n📊 {bold}VERDICT:{reset_color}")
    print(f"   {risk_analysis['color']}{risk_analysis['verdict']}{reset_color}")
    
    # Recommendations
    print(f"\n💡 {bold}RECOMMENDATIONS:{reset_color}")
    
    if risk_analysis['recommendation'] == 'critical':
        print(f"   ⚠️  {bold}IMMEDIATE ACTIONS REQUIRED:{reset_color}")
        print(f"      • Block IP on firewall immediately")
        print(f"      • Check if IP accessed other systems")
        print(f"      • Disable any compromised accounts")
        print(f"      • Escalate to SOC L2/L3 if compromise detected")
        print(f"      • Document in ticketing system (Jira/ServiceNow)")
    elif risk_analysis['recommendation'] == 'investigate':
        print(f"   ⚠️  {bold}INVESTIGATION REQUIRED:{reset_color}")
        print(f"      • Monitor activity closely")
        print(f"      • Verify legitimacy of connection")
        print(f"      • Check user behavior patterns")
        print(f"      • Consider temporary rate-limiting")
        print(f"      • Document findings")
    else:
        print(f"   ✅ {bold}STANDARD MONITORING:{reset_color}")
        print(f"      • No immediate action required")
        print(f"      • Continue standard monitoring")
        print(f"      • Log for future reference")
    
    print("\n" + "="*70 + "\n")


def save_report(ip_address, abuse_data, geo_data, risk_analysis):
    """
    Sauvegarde le rapport en JSON
    
    Args:
        ip_address (str): L'IP analysée
        abuse_data (dict): Données AbuseIPDB
        geo_data (dict): Données géolocalisation
        risk_analysis (dict): Analyse de risque
        
    Returns:
        str: Nom du fichier créé
    """
    output_file = f"ip_report_{ip_address.replace('.', '_')}.json"
    
    report_data = {
        'ip': ip_address,
        'timestamp': datetime.now().isoformat(),
        'abuse_data': abuse_data,
        'geo_data': geo_data,
        'risk_analysis': {
            'risk_score': risk_analysis['risk_score'],
            'risk_factors': risk_analysis['risk_factors'],
            'verdict': risk_analysis['verdict'],
            'recommendation': risk_analysis['recommendation']
        }
    }
    
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        return output_file
    except Exception as e:
        print(f"[!] Error saving report: {e}")
        return None


def main():
    """
    Fonction principale
    """
    # Vérification des arguments
    if len(sys.argv) < 2:
        print("\n❌ Usage Error")
        print("="*50)
        print("Usage: python ip_enrichment.py <IP_ADDRESS>")
        print("\nExample:")
        print("  python ip_enrichment.py 185.220.101.50")
        print("  python ip_enrichment.py 8.8.8.8")
        print("="*50 + "\n")
        sys.exit(1)
    
    ip_address = sys.argv[1]
    
    # Validation basique de l'IP
    parts = ip_address.split('.')
    if len(parts) != 4:
        print(f"\n❌ Error: '{ip_address}' is not a valid IP address")
        sys.exit(1)
    
    print(f"\n🔍 IP Enrichment Tool")
    print(f"Analyzing: {ip_address}")
    print("-" * 50)
    
    # Étape 1: Vérification AbuseIPDB
    abuse_data = check_abuseipdb(ip_address)
    
    # Étape 2: Vérification IPInfo
    geo_data = check_ipinfo(ip_address)
    
    # Étape 3: Analyse des risques
    risk_analysis = analyze_risk(abuse_data, geo_data)
    
    # Étape 4: Affichage du rapport
    print_report(ip_address, abuse_data, geo_data, risk_analysis)
    
    # Étape 5: Sauvegarde du rapport
    output_file = save_report(ip_address, abuse_data, geo_data, risk_analysis)
    
    if output_file:
        print(f"📁 Report saved to: {output_file}")
        print(f"💾 You can copy-paste this report into your Jira ticket\n")
    
    # Code de sortie basé sur le risque
    if risk_analysis['risk_score'] >= 70:
        sys.exit(2)  # Critical
    elif risk_analysis['risk_score'] >= 40:
        sys.exit(1)  # Warning
    else:
        sys.exit(0)  # OK


if __name__ == "__main__":
    main()