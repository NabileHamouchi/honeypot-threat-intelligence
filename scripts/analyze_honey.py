#!/usr/bin/env python3
"""
Honeypot Log Analyzer
Analyse les logs JSON de Cowrie et affiche des statistiques
"""

import json
from collections import Counter
from datetime import datetime

def load_cowrie_logs(filepath):
    """Charge les logs JSON de Cowrie"""
    logs = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    entry = json.loads(line.strip())
                    logs.append(entry)
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        print(f"❌ Fichier non trouvé : {filepath}")
        return []
    return logs

def analyze_logs(logs):
    """Analyse les logs et extrait les statistiques"""
    
    # Compteurs
    ips = []
    usernames = []
    passwords = []
    commands = []
    sessions_success = 0
    sessions_failed = 0
    
    for entry in logs:
        event_id = entry.get('eventid', '')
        
        # Login failed
        if event_id == 'cowrie.login.failed':
            sessions_failed += 1
            ip = entry.get('src_ip', 'N/A')
            user = entry.get('username', 'N/A')
            pwd = entry.get('password', 'N/A')
            
            ips.append(ip)
            usernames.append(user)
            passwords.append(pwd)
        
        # Login success
        elif event_id == 'cowrie.login.success':
            sessions_success += 1
            ip = entry.get('src_ip', 'N/A')
            ips.append(ip)
        
        # Commandes exécutées
        elif event_id == 'cowrie.command.input':
            cmd = entry.get('input', 'N/A')
            commands.append(cmd)
    
    # Compter les occurrences
    ip_counter = Counter(ips)
    user_counter = Counter(usernames)
    pwd_counter = Counter(passwords)
    cmd_counter = Counter(commands)
    
    return {
        'total_attempts': sessions_failed + sessions_success,
        'failed_attempts': sessions_failed,
        'success_attempts': sessions_success,
        'top_ips': ip_counter.most_common(5),
        'top_users': user_counter.most_common(5),
        'top_passwords': pwd_counter.most_common(5),
        'top_commands': cmd_counter.most_common(5),
        'unique_ips': len(ip_counter),
        'unique_users': len(user_counter),
    }

def display_dashboard(stats):
    """Affiche le dashboard dans le terminal"""
    
    # Header
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    print("=" * 60)
    print(f"=== 🍯 DASHBOARD HONEYPOT - {now} ===")
    print("=" * 60)
    
    # Stats globales
    print(f"\n📊 STATISTIQUES GLOBALES")
    print(f"Nombre total de tentatives : {stats['total_attempts']}")
    print(f"  - Échecs : {stats['failed_attempts']}")
    print(f"  - Réussites : {stats['success_attempts']}")
    print(f"IPs uniques : {stats['unique_ips']}")
    print(f"Usernames uniques : {stats['unique_users']}")
    
    # Top IPs
    print(f"\n--- 🚩 TOP 5 DES ADRESSES IP (ATTAQUANTS) ---")
    for ip, count in stats['top_ips']:
        print(f"IP: {ip:<18} | Attaques: {count}")
    
    # Top Users
    print(f"\n--- 👤 TOP 5 DES UTILISATEURS CIBLÉS ---")
    for user, count in stats['top_users']:
        print(f"User: {user:<15} | Tentatives: {count}")
    
    # Top Passwords
    print(f"\n--- 🔑 TOP 5 DES MOTS DE PASSE TESTÉS ---")
    for pwd, count in stats['top_passwords']:
        # Masquer partiellement les passwords longs
        display_pwd = pwd[:20] + "..." if len(pwd) > 20 else pwd
        print(f"Pass: {display_pwd:<15} | Tentatives: {count}")
    
    # Top Commands (si disponibles)
    if stats['top_commands'] and stats['top_commands'][0][0] != 'N/A':
        print(f"\n--- 💻 TOP 5 DES COMMANDES EXÉCUTÉES ---")
        for cmd, count in stats['top_commands']:
            display_cmd = cmd[:40] + "..." if len(cmd) > 40 else cmd
            print(f"Cmd: {display_cmd:<40} | Exec: {count}")
    
    # Footer
    print("=" * 60)
    print()

def main():
    """Fonction principale"""
    
    # Chemin du fichier de logs Cowrie
    # Adapter selon ton chemin
    log_file = '/home/cowrie/cowrie/var/log/cowrie/cowrie.json'
    
    print("🔍 Chargement des logs Cowrie...")
    logs = load_cowrie_logs(log_file)
    
    if not logs:
        print("❌ Aucun log trouvé ou fichier vide")
        return
    
    print(f"✅ {len(logs)} événements chargés")
    
    print("📊 Analyse en cours...")
    stats = analyze_logs(logs)
    
    print("✅ Analyse terminée\n")
    
    # Afficher le dashboard
    display_dashboard(stats)

if __name__ == "__main__":
    main()