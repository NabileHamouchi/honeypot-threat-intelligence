# 🍯 Honeypot Threat Intelligence Platform

> Infrastructure complète de détection de menaces SSH avec 
> monitoring SIEM temps réel et automation SOC

[![Stack](https://img.shields.io/badge/Stack-Cowrie%20%7C%20Splunk%20%7C%20GCP-blue)]()
[![Status](https://img.shields.io/badge/Status-Completed-success)]()
[![Python](https://img.shields.io/badge/Python-3.8+-yellow)]()

---

## 🎯 Objectif

Projet SOC démontrant la mise en place d'une infrastructure 
complète de détection et d'analyse de menaces SSH en environnement 
cloud réel, avec monitoring SIEM, alerting automatisé et toolkit 
d'automation Python.

---

## 🏗️ Architecture


![Architecture](screenshots/architecture_lab.png)

---

## 🛠️ Stack Technique

| Composant | Technologie |
|-----------|-------------|
| **Honeypot** | Cowrie (SSH/Telnet honeypot) |
| **SIEM** | Splunk Enterprise + Universal Forwarder |
| **Cloud** | Google Cloud Platform (2 VMs GCP) |
| **Scripting** | Python 3 |
| **Alerting** | SPL (Splunk Processing Language) |
| **Visualisation** | Splunk Dashboard (3 panels temps réel) |

---

## 📊 Résultats (48h de collecte)

| Métrique | Valeur |
|----------|--------|
| **Tentatives d'intrusion** | 2 642 captées et analysées |
| **IPs malveillantes uniques** | 20+ identifiées |
| **Compromissions réussies** | 110 sessions (taux 5%) |
| **Incidents détectés** | 18 alertes déclenchées |
| **Temps de détection** | < 1 minute après compromission |
| **Disponibilité** | 99.9% (48h uptime continu) |
| **Latence ingestion** | < 30 secondes |

---

## 🚨 Système d'Alerting Temps Réel

| Alerte | Sévérité | Condition | Délai |
|--------|----------|-----------|-------|
| Brute-Force Attack | HIGH | ≥ 15 tentatives / 10 min | < 1 min |
| Compromission SSH | CRITICAL | 3 échecs + 1 succès | < 1 min |

---

## 📸 Screenshots

### Dashboard Temps Réel
![Dashboard](screenshots/01_dashboard_complet.png)

### Alertes Déclenchées
![Alertes](screenshots/03_triggered_alerts.png)

---

## 📁 Structure du Projet
```
honeypot-threat-intel/
├── README.md
├── requirements.txt
├── scripts/                    # Scripts Python automation
│   └── parse_logs.py          # Parsing logs JSON Cowrie
├── screenshots/               # Captures dashboard et alertes
│   ├── architecture_lab.png
│   ├── 01_dashboard_complet.png
│   └── 03_triggered_alerts.png
├── reports/                   # Rapports d'incidents
│   └── rapport_incident_13fev2026.md
└── soc-toolkit/               # SOC Automation Toolkit
    ├── README.md
    ├── ip_enrichment.py
    ├── ioc_extractor.py
    ├── alert_triage.py
    ├── ir_report_generator.py
    └── bulk_ip_checker.py
```

---

## 🎓 Compétences Démontrées

✅ **Infrastructure** : Déploiement multi-VM cloud (GCP), 
isolation réseau, configuration services  
✅ **SIEM** : Configuration Splunk complète (indexation, 
parsing, dashboards, alertes SPL)  
✅ **Requêtes SPL** : Agrégations, corrélations, 
top commands, timechart  
✅ **Alerting** : Monitoring temps réel (détection < 1 min)  
✅ **Investigation** : Analyse comportementale, extraction 
IoCs, documentation structurée  
✅ **Python** : Automation parsing logs, génération 
statistiques  
✅ **SOC Automation** : Toolkit 5 scripts 
([voir soc-toolkit](./soc-toolkit/README.md))

---

## 🔗 Composant 2 : SOC Automation Toolkit

En complément du honeypot, j'ai développé un toolkit 
de 5 scripts Python pour automatiser les tâches 
répétitives en SOC.

**Gain de temps** : ~20h économisées par jour 
pour un SOC recevant 50 alertes

📖 **Documentation complète** : 
[SOC Toolkit README](./soc-toolkit/README.md)

---

**Auteur** : Nabile Hamouchi  
**Date** : Février 2026  
**Contexte** : Projet portfolio M2 Cybersécurité  
**Objectif** : Stage SOC/SIEM Analyst (4-6 mois) · Mars 2026