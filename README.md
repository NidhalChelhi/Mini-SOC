# Mini-SOC: Plateforme de Détection d'Intrusion et Gestion d'Alertes

**Projet de Cybersécurité - 2025/2026**  
**Responsable:** Houcemeddine HERMASSI  
**Étudiants:** Nidhal Chelhi et Rochdi Fridhi

---

## 📋 Description du Projet

Ce projet consiste en la conception, le déploiement et la validation d'une plateforme complète de détection d'intrusions combinant:

- **Suricata** (Network Intrusion Detection System - NIDS)
- **Wazuh** (Host Intrusion Detection System - HIDS)
- **Elastic Stack** (SIEM pour la centralisation et visualisation)

L'objectif est de créer un mini Security Operations Center (SOC) capable de surveiller le réseau et les hôtes, détecter les intrusions, et centraliser les alertes de sécurité.

---

## 🏗️ Architecture

### Composants du Système

| Composant          | IP              | Rôle                          |
| ------------------ | --------------- | ----------------------------- |
| **Elastic Stack**  | 192.168.229.143 | SIEM (Elasticsearch + Kibana) |
| **Wazuh Manager**  | 192.168.229.146 | Gestionnaire HIDS             |
| **Suricata NIDS**  | 192.168.229.147 | Détection réseau              |
| **Linux Client-1** | 192.168.229.145 | Hôte surveillé (Wazuh Agent)  |
| **Kali Linux**     | 192.168.229.148 | Machine d'attaque (tests)     |

### Technologies Utilisées

- **Système d'exploitation:** Ubuntu Server 22.04 (sauf Kali Linux)
- **Virtualisation:** VMware Workstation
- **NIDS:** Suricata avec règles Emerging Threats
- **HIDS:** Wazuh Manager + Agent
- **SIEM:** Elasticsearch 8.x + Kibana 8.x
- **Collecteur de logs:** Filebeat
- **Outils de test:** Nmap, Metasploit, Hydra

---

## 🚀 Fonctionnalités Implémentées

### ✅ Détection Réseau (NIDS)

- Surveillance du trafic réseau en temps réel
- Détection de scans de ports (Nmap)
- Détection d'attaques HTTP malveillantes
- Alertes sur tentatives d'exploitation

### ✅ Détection Hôte (HIDS)

- Surveillance des tentatives de connexion
- Détection de brute force SSH
- Monitoring des modifications de fichiers
- Alertes sur activités suspectes système

### ✅ Centralisation & Visualisation

- Collecte centralisée de tous les logs (Wazuh + Suricata)
- Dashboard Kibana avec:
  - Timeline des alertes
  - Classification par sévérité
  - Top IPs attaquantes
  - Ports ciblés
  - Signatures d'attaque réseau

---

## 📊 Dashboard & Visualisations

Le dashboard Kibana affiche:

- **Wazuh Alert Timeline:** Évolution temporelle des alertes
- **Total Alerts:** Compteur en temps réel
- **Attacking IPs:** Analyse des sources d'attaque
- **Alert Severity:** Distribution par gravité (syslog, pam, authentication, ossec)
- **Network Attack Signatures:** Signatures détectées par Suricata
- **Targeted Ports:** Ports les plus ciblés

Voir les captures d'écran dans le dossier `screenshots/`.

---

## 🧪 Tests Effectués

Les tests suivants ont été réalisés depuis Kali Linux (192.168.229.148):

1. **Scan de ports (Nmap)**

   - Détecté par Suricata
   - Alertes générées dans Kibana

2. **Brute Force SSH**

   - Détecté par Wazuh Agent
   - Corrélation avec alertes Wazuh Manager

3. **Attaques HTTP malveillantes**
   - Path traversal attempts
   - SQL injection attempts
   - Détectées par Suricata

---

## 📂 Structure du Projet

Voir le fichier `PROJECT-STRUCTURE.txt` pour la structure complète.

---

## 📖 Documentation

La documentation complète se trouve dans le dossier `docs/`:

- Installation Guide
- Configuration Guide
- Testing Guide
- User Manual

---

## 🎓 Compétences Acquises

- Configuration d'un IDS/IPS réseau (Suricata)
- Déploiement d'un HIDS distribué (Wazuh)
- Intégration SIEM avec Elastic Stack
- Corrélation d'événements de sécurité
- Création de dashboards de monitoring
- Tests d'intrusion et validation

---

## 📝 Livrables

- ✅ Plateforme SOC fonctionnelle
- ✅ Configurations documentées
- ✅ Dashboard opérationnel
- ✅ Tests de validation
- ✅ Documentation technique complète

---

## 👤 Auteur

**Nidhal Chelhi**  
Projet de Cybersécurité - Module sous la supervision de Houcemeddine HERMASSI

---

## 📅 Date

Janvier 2026
