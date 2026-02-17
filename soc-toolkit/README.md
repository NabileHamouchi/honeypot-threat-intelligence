# 🛠️ SOC Automation Toolkit

> Collection de 5 scripts Python pour automatiser les 
> tâches répétitives en SOC et réduire le temps de triage

[![Python](https://img.shields.io/badge/Python-3.8+-blue)]()
[![Status](https://img.shields.io/badge/Status-Production--Ready-success)]()

---

## 🎯 Objectif

Réduire le temps de triage d'alertes et d'investigation 
de **30 minutes à 2 minutes** par incident grâce à 
l'automation des tâches répétitives en SOC.

---

## 🐍 Les 5 Scripts

### 1. IP Enrichment Tool (`ip_enrichment.py`)

**Enrichit une IP avec threat intelligence**

| | |
|---|---|
| **APIs** | AbuseIPDB (reputation) + IPInfo.io (geolocation) |
| **Gain** | 5 min → 30 sec par IP |
| **Output** | Rapport terminal + fichier JSON |
```bash
python ip_enrichment.py 185.220.101.50
```
```
IP: 185.220.101.50
Country: Russia · ISP: BadHosting LLC
Abuse Score: 100/100 · Reports: 547
VERDICT: ⚠️ MALICIOUS - Block immediately
```

---

### 2. IOC Extractor (`ioc_extractor.py`)

**Extrait automatiquement tous les IoCs d'un texte**

| | |
|---|---|
| **Extrait** | IPs · URLs · Domains · Emails · Hashes MD5/SHA1/SHA256 |
| **Gain** | 10 min → 10 sec |
| **Output** | Rapport terminal + fichier CSV |
```bash
python ioc_extractor.py phishing_email.txt
```

**Use cases** :
- Analyse emails de phishing
- Parsing logs volumineux
- Extraction IoCs de rapports threat intel externes

---

### 3. Alert Triage Helper (`alert_triage.py`)

**Calcule un risk score et recommande True/False Positive**

| | |
|---|---|
| **Input** | Fichier JSON de l'alerte |
| **Gain** | 30 min → 2 min par alerte |
| **Output** | Score 0-100 + verdict + recommandations |
```bash
python alert_triage.py alert.json
```
```
Risk Score: 95/100
VERDICT: TRUE POSITIVE (High confidence)
→ Block IP immediately
→ Escalate to L2
```

---

### 4. IR Report Generator (`ir_report_generator.py`)

**Génère un template rapport d'incident pré-rempli**

| | |
|---|---|
| **Format** | Markdown (compatible Jira / Confluence) |
| **Gain** | 1h → 15 min |
| **Output** | Fichier .md prêt à compléter |
```bash
python ir_report_generator.py --ip 185.220.101.50 --user root
```

---

### 5. Bulk IP Checker (`bulk_ip_checker.py`)

**Vérifie la réputation de 100+ IPs simultanément**

| | |
|---|---|
| **Input** | Fichier .txt avec une IP par ligne |
| **Gain** | 5h → 5 min |
| **Output** | Rapport terminal + fichier CSV complet |
```bash
python bulk_ip_checker.py ip_list.txt
```
```
High Risk (score >75):    12 IPs ⚠️
Medium Risk (50-75):       5 IPs
Clean (<50):             183 IPs ✅

Saved to: ip_bulk_analysis.csv
```

---

## 📊 Impact en SOC Réel

| Tâche | Sans scripts | Avec scripts | Gain/jour |
|-------|-------------|--------------|-----------|
| Check 50 IPs | 250 min | 25 min | **3h45** |
| Triage 30 alertes | 900 min | 60 min | **14h** |
| Analyse 10 emails phishing | 100 min | 5 min | **1h35** |
| Documentation 5 incidents | 300 min | 75 min | **3h45** |
| **TOTAL** | **1 550 min** | **165 min** | **~23h/jour** |

---

## 🚀 Installation
```bash
cd soc-toolkit

# Installer les dépendances
pip install -r requirements.txt

# Configurer la clé API
cp .env.example .env
# Éditer .env et ajouter ta clé AbuseIPDB
```

---

## 🔑 Configuration API

**Fichier `.env` requis** :
```
ABUSEIPDB_API_KEY=ta_clé_ici
```

**Obtenir une clé gratuite** :
1. Créer compte : https://www.abuseipdb.com/register
2. Account → API → Copy key
3. Limite : 1 000 requêtes/jour gratuit

---

## 💡 Workflow Complet

### Scénario : Alerte SSH brute-force reçue
```bash
# Étape 1 : Enrichir l'IP source
python ip_enrichment.py 185.220.101.50
# → Score 100/100, Russia, MALICIOUS

# Étape 2 : Analyser l'alerte
python alert_triage.py alert_SOC12345.json
# → TRUE POSITIVE, Risk 95/100

# Étape 3 : Générer rapport pour L2
python ir_report_generator.py --ip 185.220.101.50
# → incident_report.md créé

# Escalade au L2 avec rapport joint ✅
```

---

## 🔒 Sécurité

> ⚠️ **Ne jamais commit le fichier `.env`** sur GitHub

- ✅ `.gitignore` configuré pour exclure `.env`
- ✅ Clés API chargées via `python-dotenv`
- ✅ Aucune clé en dur dans le code

---

## 📚 Dépendances
```
requests==2.31.0
python-dotenv==1.0.0
```

---

**Auteur** : Nabile Hamouchi  
**Date** : Février 2026  
**Contexte** : Projet portfolio M2 Cybersécurité  
**Repo principal** : [Honeypot Threat Intelligence](../README.md)