#!/usr/bin/env python3
"""
IOC Extractor
Extrait automatiquement les IoCs (IPs, URLs, domains, hashes) d'un texte
"""

import re
import sys
from collections import defaultdict

def extract_ips(text):
    """
    Extrait les adresses IP (IPv4)
    """
    # Regex pour IPv4
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    ips = re.findall(ip_pattern, text)
    
    # Filtre IPs privées (on garde que les publiques)
    public_ips = []
    for ip in ips:
        octets = ip.split('.')
        first_octet = int(octets[0])
        second_octet = int(octets[1])
        
        # Skip private IPs (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
        if first_octet == 10:
            continue
        if first_octet == 172 and 16 <= second_octet <= 31:
            continue
        if first_octet == 192 and second_octet == 168:
            continue
        if first_octet == 127:  # localhost
            continue
        
        public_ips.append(ip)
    
    return list(set(public_ips))  # Remove duplicates


def extract_urls(text):
    """
    Extrait les URLs (http/https)
    """
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    urls = re.findall(url_pattern, text)
    return list(set(urls))


def extract_domains(text):
    """
    Extrait les noms de domaine
    """
    # Pattern pour domaines (ex: malicious.com, phishing-site.ru)
    domain_pattern = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b'
    domains = re.findall(domain_pattern, text.lower())
    
    # Filtre domaines communs légitimes (pour réduire bruit)
    common_domains = ['google.com', 'microsoft.com', 'apple.com', 'amazon.com']
    filtered = [d for d in domains if d not in common_domains]
    
    return list(set(filtered))


def extract_hashes(text):
    """
    Extrait les hashes (MD5, SHA1, SHA256)
    """
    hashes = {
        'md5': [],
        'sha1': [],
        'sha256': []
    }
    
    # MD5: 32 hex chars
    md5_pattern = r'\b[a-fA-F0-9]{32}\b'
    hashes['md5'] = re.findall(md5_pattern, text)
    
    # SHA1: 40 hex chars
    sha1_pattern = r'\b[a-fA-F0-9]{40}\b'
    hashes['sha1'] = re.findall(sha1_pattern, text)
    
    # SHA256: 64 hex chars
    sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
    hashes['sha256'] = re.findall(sha256_pattern, text)
    
    return hashes


def extract_emails(text):
    """
    Extrait les adresses email
    """
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    emails = re.findall(email_pattern, text)
    return list(set(emails))


def print_results(iocs):
    """
    Affiche les IoCs extraits de manière formatée
    """
    print("\n" + "="*60)
    print("IOC EXTRACTION REPORT")
    print("="*60)
    
    # IPs
    if iocs['ips']:
        print(f"\n📍 IP ADDRESSES FOUND: {len(iocs['ips'])}")
        for ip in iocs['ips']:
            print(f"   - {ip}")
    else:
        print(f"\n📍 IP ADDRESSES FOUND: 0")
    
    # URLs
    if iocs['urls']:
        print(f"\n🔗 URLs FOUND: {len(iocs['urls'])}")
        for url in iocs['urls']:
            print(f"   - {url}")
    else:
        print(f"\n🔗 URLs FOUND: 0")
    
    # Domains
    if iocs['domains']:
        print(f"\n🌐 DOMAINS FOUND: {len(iocs['domains'])}")
        for domain in iocs['domains']:
            print(f"   - {domain}")
    else:
        print(f"\n🌐 DOMAINS FOUND: 0")
    
    # Emails
    if iocs['emails']:
        print(f"\n📧 EMAILS FOUND: {len(iocs['emails'])}")
        for email in iocs['emails']:
            print(f"   - {email}")
    else:
        print(f"\n📧 EMAILS FOUND: 0")
    
    # Hashes
    total_hashes = sum(len(v) for v in iocs['hashes'].values())
    if total_hashes > 0:
        print(f"\n🔐 FILE HASHES FOUND: {total_hashes}")
        if iocs['hashes']['md5']:
            print(f"   MD5 ({len(iocs['hashes']['md5'])}):")
            for h in iocs['hashes']['md5']:
                print(f"      {h}")
        if iocs['hashes']['sha1']:
            print(f"   SHA1 ({len(iocs['hashes']['sha1'])}):")
            for h in iocs['hashes']['sha1']:
                print(f"      {h}")
        if iocs['hashes']['sha256']:
            print(f"   SHA256 ({len(iocs['hashes']['sha256'])}):")
            for h in iocs['hashes']['sha256']:
                print(f"      {h}")
    else:
        print(f"\n🔐 FILE HASHES FOUND: 0")
    
    print("\n" + "="*60 + "\n")


def save_to_csv(iocs, output_file):
    """
    Sauvegarde les IoCs en CSV
    """
    with open(output_file, 'w') as f:
        f.write("type,value\n")
        
        for ip in iocs['ips']:
            f.write(f"ip,{ip}\n")
        
        for url in iocs['urls']:
            f.write(f"url,{url}\n")
        
        for domain in iocs['domains']:
            f.write(f"domain,{domain}\n")
        
        for email in iocs['emails']:
            f.write(f"email,{email}\n")
        
        for hash_type, hash_list in iocs['hashes'].items():
            for h in hash_list:
                f.write(f"{hash_type},{h}\n")
    
    print(f"📁 IoCs saved to: {output_file}")


def main():
    """
    Fonction principale
    """
    if len(sys.argv) < 2:
        print("Usage: python ioc_extractor.py <input_file>")
        print("Example: python ioc_extractor.py alert.txt")
        print("\nOr pipe text:")
        print("echo 'malicious IP 185.220.101.50' | python ioc_extractor.py -")
        sys.exit(1)
    
    input_file = sys.argv[1]
    
    # Lecture du texte
    if input_file == '-':
        # Read from stdin
        text = sys.stdin.read()
    else:
        try:
            with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
                text = f.read()
        except FileNotFoundError:
            print(f"[!] Error: File '{input_file}' not found")
            sys.exit(1)
    
    print(f"\n🔍 IOC Extractor")
    print(f"Analyzing: {input_file}\n")
    
    # Extraction
    iocs = {
        'ips': extract_ips(text),
        'urls': extract_urls(text),
        'domains': extract_domains(text),
        'emails': extract_emails(text),
        'hashes': extract_hashes(text)
    }
    
    # Affichage
    print_results(iocs)
    
    # Sauvegarde CSV
    if input_file != '-':
        output_file = input_file.rsplit('.', 1)[0] + '_iocs.csv'
    else:
        output_file = 'iocs.csv'
    
    save_to_csv(iocs, output_file)


if __name__ == "__main__":
    main()