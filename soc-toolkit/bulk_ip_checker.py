#!/usr/bin/env python3
"""
Bulk IP Checker
Check reputation de 100+ IPs en batch
"""

import os
import sys
import csv
import requests
import time
from dotenv import load_dotenv
from datetime import datetime

# Charge variables d'environnement
load_dotenv()


def check_ip(ip_address, api_key):
    """
    Check une seule IP via AbuseIPDB
    """
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {'Key': api_key, 'Accept': 'application/json'}
    params = {'ipAddress': ip_address, 'maxAgeInDays': 90}
    
    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        
        if response.status_code == 200:
            data = response.json()['data']
            return {
                'ip': ip_address,
                'score': data.get('abuseConfidenceScore', 0),
                'reports': data.get('totalReports', 0),
                'country': data.get('countryCode', 'Unknown'),
                'isp': data.get('isp', 'Unknown')
            }
        else:
            return {'ip': ip_address, 'score': 0, 'reports': 0, 'country': 'Error', 'isp': 'Error'}
    
    except Exception as e:
        return {'ip': ip_address, 'score': 0, 'reports': 0, 'country': 'Error', 'isp': str(e)}


def classify_risk(score):
    """
    Classifie le risque basé sur le score
    """
    if score >= 75:
        return "HIGH RISK"
    elif score >= 50:
        return "MEDIUM RISK"
    else:
        return "LOW RISK"


def print_progress_bar(current, total, bar_length=40):
    """
    Affiche barre de progression
    """
    progress = current / total
    block = int(bar_length * progress)
    bar = "█" * block + "░" * (bar_length - block)
    print(f"\r[{bar}] {current}/{total} ({progress*100:.1f}%)", end='', flush=True)


def main():
    """
    Fonction principale
    """
    if len(sys.argv) < 2:
        print("Usage: python bulk_ip_checker.py <ip_list.txt>")
        print("Example: python bulk_ip_checker.py ips_to_check.txt")
        print("\nIP list format (one IP per line):")
        print("185.220.101.50")
        print("192.0.2.45")
        print("...")
        sys.exit(1)
    
    input_file = sys.argv[1]
    
    # Check API key
    api_key = os.getenv('ABUSEIPDB_API_KEY')
    
    if not api_key:
        print("[!] Error: ABUSEIPDB_API_KEY not found in .env file")
        print("Please add your API key to the .env file")
        sys.exit(1)
    
    # Load IPs
    try:
        with open(input_file, 'r') as f:
            ips = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[!] Error: File '{input_file}' not found")
        sys.exit(1)
    
    print(f"\n🔍 Bulk IP Checker")
    print(f"Loading IPs from: {input_file}")
    print(f"Total IPs to check: {len(ips)}\n")
    
    # Check chaque IP
    results = []
    
    print("Processing IPs...")
    for i, ip in enumerate(ips, 1):
        result = check_ip(ip, api_key)
        result['risk'] = classify_risk(result['score'])
        results.append(result)
        
        print_progress_bar(i, len(ips))
        
        # Rate limiting: 1 requête/seconde (gratuit = 1000/jour)
        time.sleep(1.1)
    
    print("\n\n✅ Processing complete!\n")
    
    # Statistics
    high_risk = sum(1 for r in results if r['risk'] == "HIGH RISK")
    medium_risk = sum(1 for r in results if r['risk'] == "MEDIUM RISK")
    low_risk = sum(1 for r in results if r['risk'] == "LOW RISK")
    
    print("="*60)
    print("SUMMARY STATISTICS")
    print("="*60)
    print(f"\n📊 Risk Distribution:")
    print(f"   🔴 HIGH RISK (score ≥75):    {high_risk:3d} IPs ({high_risk/len(ips)*100:.1f}%)")
    print(f"   🟡 MEDIUM RISK (score 50-74): {medium_risk:3d} IPs ({medium_risk/len(ips)*100:.1f}%)")
    print(f"   🟢 LOW RISK (score <50):      {low_risk:3d} IPs ({low_risk/len(ips)*100:.1f}%)")
    
    # Top 10 most dangerous
    sorted_results = sorted(results, key=lambda x: x['score'], reverse=True)
    
    print(f"\n🚨 Top 10 Most Dangerous IPs:")
    for i, r in enumerate(sorted_results[:10], 1):
        print(f"   {i:2d}. {r['ip']:15s}  Score: {r['score']:3d}/100  {r['country']:3s}  ({r['reports']} reports)")
    
    # Save to CSV
    output_file = input_file.replace('.txt', '_results.csv')
    
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['ip', 'score', 'risk', 'reports', 'country', 'isp'])
        writer.writeheader()
        writer.writerows(results)
    
    print(f"\n📁 Results saved to: {output_file}")
    print("="*60 + "\n")


if __name__ == "__main__":
    main()