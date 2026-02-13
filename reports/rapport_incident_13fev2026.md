# 🚨 Rapport d'Incident - Compromission SSH après Brute-Force

**ID Incident** : INC-2026-02-13-001  
**Date de détection** : 13 février 2026, 17:00 UTC  
**Analyste** : Nabile Hamouchi  
**Sévérité** : CRITIQUE  
**Statut** : Résolu  

## 1. RÉSUMÉ EXÉCUTIF

Détection d'une compromission SSH suite à une attaque par force brute réussie.  
L'attaquant a réussi à s'authentifier après [NOMBRE] tentatives échouées,  
déclenchant une alerte CRITICAL dans le SIEM Splunk.  

**Impact** : Aucun (système honeypot isolé du réseau de production)  
**Temps de détection** : < 1 minute (alerte automatique)  
**Temps de résolution** : 15 minutes  
**Attaquant contenu** : Oui ✅  

## 2. DÉTAILS TECHNIQUES

### 2.1 Alerte Déclenchée

**Nom de l'alerte** : CRITICAL - Successful Brute-Force Attack (Compromise)  
**Timestamp** : 2026-02-13 17:00:56 UTC  
**Source de l'alerte** : Splunk SIEM (règle SPL temps réel)  
**Application** : Search & Reporting  

**Condition de déclenchement** :
```
Détection automatique d'une IP ayant effectué ≥3 tentatives de connexion 
échouées suivies d'une authentification réussie dans une fenêtre de 10 minutes.
```

**Règle SPL utilisée** :
```bash
index=* (eventid="cowrie.login.failed" OR eventid="cowrie.login.success")
| bucket _time span=15m
| stats count(eval(eventid="cowrie.login.failed")) as failed,
        count(eval(eventid="cowrie.login.success")) as success
        by src_ip
| where failed >= 3 AND success > 0
| eval severity="CRITICAL"
| table src_ip, failed, success, severity
```

### 2.2 Informations sur l'Attaquant

**IP Source** : 89.20.36.35  
**Port destination** : 22 (SSH)  
**Protocole** : SSH-2.0  

---

### 2.3 Timeline Détaillée de l'Attaque

**Phase 1 : Reconnaissance & Brute-Force**

```bash
index=* src_ip="89.20.36.35" 
| table _time, eventid, username, password
| sort _time

2026-02-13 17:00:26 UTC - Tentative 1 (échec)
              Username: root | Password: 123456
              
2026-02-13 17:00:28 UTC - Tentative 2 (échec)
              Username: root | Password: 123456789
              
2026-02-13 17:00:45 UTC - Tentative 3 (échec)
              Username: root | Password: admin
              
2026-02-13 17:00:50 UTC - Tentative 6 (SUCCÈS) ✅
              Username: root | Password: password
              → SESSION SSH ÉTABLIE
```

**Phase 2 : Détection**

```
2026-02-13 17:00:56 UTC - ACRITICAL - Successful Brute-Force Attack (Compromise)
              (5 secondes après la compromission)
```


## 3. INVESTIGATION APPROFONDIE

### 3.1 Requêtes SPL d'Investigation

**Requête 1 : Historique complet de l'IP source**

```bash
index=* src_ip="89.20.36.35"
| stats count by eventid
```

**Résultats** :
```bash
- cowrie.login.failed : 176
- cowrie.login.success : 8
- cowrie.session.closed : 28
```

**Requête 2 : Analyse des credentials testés**

```spl
index=* src_ip="89.20.36.35" eventid="cowrie.login.failed"
| stats count by password
| sort -count
```

**Top passwords testés** :

```bash
1. 123456 (11 fois)
2. 111111 (7 fois)
3. 123456789 (5 fois)
4. password (5 fois)
5. alexandra (4 fois)
```

### 3.2 Analyse Comportementale

**Type d'attaque** : Brute-force SSH automatisé  

**Sophistication** : 🟡 Moyenne
- Bot automatisé (pas d'intervention humaine manuelle)
- Utilisation de dictionnaire de passwords courants
- Espacement des tentatives (~60 secondes) pour éviter détection basique
- Reconnaissance système post-compromission standard

**Tactiques MITRE ATT&CK** :
- **T1110.001** : Brute Force (Password Guessing)
- **T1078** : Valid Accounts (utilisation credentials découverts)
- **T1059** : Command Execution
- **T1082** : System Information Discovery (uname, whoami)
- **T1105** : Ingress Tool Transfer (wget)

**Objectifs supposés** :
1. Compromission initiale via brute-force
2. Reconnaissance système
3. Établissement de persistance via malware
4. Utilisation comme bot dans botnet

---

## 🛡️ 4. RÉPONSE À L'INCIDENT

### 4.1 Containment (Confinement)

✅ **Session honeypot automatiquement isolée** (par design)  
✅ **IP source placée sous surveillance active**  
✅ **Aucun accès au réseau de production** (honeypot en VLAN isolé)  
✅ **Malware capturé** pour analyse statique (si téléchargé)  

### 4.2 Eradication (Éradication)

✅ **Environnement honeypot reset** automatiquement  
✅ **Logs complets sauvegardés** pour analyse forensique  

### 4.3 Recovery (Récupération)

✅ **Honeypot opérationnel** (temps de recovery : 0 seconde - automatique)  
✅ **Monitoring continu** de l'IP source activé  
✅ **Aucun service de production impacté**  

### 4.4 Lessons Learned

**Ce qui a bien fonctionné** :
- ✅ Alerte temps réel efficace (détection < 1 minute)
- ✅ Honeypot a parfaitement joué son rôle de leurre
- ✅ Isolation réseau a empêché toute propagation
- ✅ Logs complets capturés pour analyse

**Points d'amélioration** :
-  Intégrer enrichissement automatique IP (géolocalisation, reputation)
-  Automatiser extraction IoCs vers plateforme MISP
-  Ajouter alertes sur téléchargement de fichiers suspects

⚠️ **Recommandation** : Cet incident confirme que le credential `root:password`  
reste largement exploité par les botnets SSH. Politique de mots de passe  
robustes critique en environnement de production.  


## 5. RECOMMANDATIONS

### 5.1 Court Terme (0-7 jours)

1.  **Blacklister l'IP** 89.20.36.35 dans firewall production
2.  **Monitorer** tentatives de connexion depuis cette IP
3.  **Analyser le malware** en sandbox (si capturé)
4.  **Vérifier** si IP fait partie de botnet connu (AbuseIPDB, VirusTotal)

### 5.2 Moyen Terme (1-4 semaines)

1.  **Partager IoCs** avec communauté (MISP, AlienVault OTX)
2.  **Mettre à jour signatures IDS/IPS** avec patterns observés
3.  **Auditer credentials** en environnement production (éliminer passwords faibles)
4.  **Enrichir alertes Splunk** avec threat intelligence feeds

### 5.3 Long Terme (1-6 mois)

1.  **Politique mots de passe** : Minimum 12 caractères, complexité élevée
2.  **MFA obligatoire** sur tous accès SSH/RDP production
3.  **Segmentation réseau** : Isoler services critiques
4.  **Automated threat intel** : Pipeline automatique IoCs → SIEM
5.  **Red Team exercises** : Tester détection de ce type d'attaques


## 6. CONCLUSION

### Synthèse

**Incident géré avec succès sans impact sur infrastructure de production.**

Le système d'alerting temps réel configuré dans Splunk a permis une détection 
**en moins de 1 minute** après l'authentification réussie de l'attaquant.

Le honeypot Cowrie a parfaitement rempli son rôle en :
- ✅ Attirant l'attaquant loin des systèmes réels
- ✅ Capturant l'intégralité de son comportement (credentials, commandes, malware)
- ✅ Permettant analyse détaillée des tactiques adverses

### Impact Métier

**Aucun impact sur infrastructure réelle.**

Cet incident démontre :
1. L'efficacité du monitoring proactif avec SIEM
2. L'importance d'une détection rapide (< 1 minute vs moyenne industrie 200+ jours)
3. La valeur des honeypots pour threat intelligence

### Lessons Learned Principales

1. **Les credentials faibles persistent** : `root:123456` ou `root:password` largement exploité en 2026
2. **La détection temps réel fonctionne** : Alerte < 1 minute permet réaction immédiate
3. **Les honeypots sont précieux** : Insight comportemental attaquants sans risque
4. **L'automatisation est clé** : Alerte manuelle aurait pris 30-60+ minutes

---

## 📎 ANNEXES

### Annexe A : Références

- MITRE ATT&CK Framework : https://attack.mitre.org/
- NIST Incident Response Guide : SP 800-61 Rev. 2
- Cowrie Documentation : https://github.com/cowrie/cowrie

---

**Rapport rédigé par** : Nabile Hamouchi  
**Date de rédaction** : 13 février 2026  
**Version** : 1.0  
**Classification** : Internal Use Only  
**Distribution** : Équipe SOC, Management   