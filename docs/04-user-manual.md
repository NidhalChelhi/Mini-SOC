\# Manuel Utilisateur - Mini-SOC Platform

\## Table des Matières

1\. \[Introduction](#introduction)

2\. \[Accès à la Plateforme](#accès-à-la-plateforme)

3\. \[Navigation dans Kibana](#navigation-dans-kibana)

4\. \[Utilisation du Dashboard](#utilisation-du-dashboard)

5\. \[Analyse des Alertes](#analyse-des-alertes)

6\. \[Réponse aux Incidents](#réponse-aux-incidents)

7\. \[Maintenance Quotidienne](#maintenance-quotidienne)

8\. \[Dépannage](#dépannage)

---

\## Introduction

\### Qu'est-ce que le Mini-SOC?

Le Mini-SOC (Security Operations Center) est une plateforme de surveillance de sécurité qui combine:

\- \*\*NIDS (Network IDS):\*\* Détection d'intrusions réseau via Suricata

\- \*\*HIDS (Host IDS):\*\* Détection d'intrusions hôte via Wazuh

\- \*\*SIEM:\*\* Centralisation et visualisation via Elastic Stack

\### Pour qui?

Ce manuel s'adresse aux:

\- \*\*Analystes SOC:\*\* Pour surveiller les alertes de sécurité

\- \*\*Administrateurs système:\*\* Pour maintenir la plateforme

\- \*\*Responsables sécurité:\*\* Pour avoir une vue d'ensemble

---

\## Accès à la Plateforme

\### Connexion à Kibana

\*\*URL d'accès:\*\*

```

http://192.168.229.143:5601

```

\*\*Identifiants par défaut:\*\*

\- \*\*Username:\*\* `elastic`

\- \*\*Password:\*\* `\[configuré lors de l'installation]`

\### Premier Accès

1\. Ouvrir un navigateur web (Chrome, Firefox recommandés)

2\. Entrer l'URL: `http://192.168.229.143:5601`

3\. Saisir les identifiants

4\. Cliquer sur \*\*Log in\*\*

\*\*Page d'accueil Kibana:\*\*

\- Menu latéral gauche avec les différentes sections

\- Barre de recherche en haut

\- Contenu principal au centre

---

\## Navigation dans Kibana

\### Menu Principal

| Section | Description | Usage |

|---------|-------------|-------|

| \*\*Discover\*\* | Explorer les logs bruts | Recherche détaillée dans les événements |

| \*\*Dashboard\*\* | Tableaux de bord visuels | Vue d'ensemble des alertes |

| \*\*Visualize\*\* | Créer des visualisations | Personnaliser les graphiques |

| \*\*Alerts\*\* | Gestion des alertes | Configuration des notifications |

| \*\*Stack Management\*\* | Administration | Gérer indices, utilisateurs, etc. |

\### Raccourcis Clavier

| Touche | Action |

|--------|--------|

| `Ctrl + /` | Ouvrir la recherche |

| `Ctrl + K` | Barre de commande rapide |

| `F5` | Rafraîchir les données |

---

\## Utilisation du Dashboard

\### Accéder au Dashboard Principal

1\. Cliquer sur \*\*Dashboard\*\* dans le menu latéral

2\. Sélectionner \*\*"Mini-SOC Main Dashboard"\*\*

\### Composants du Dashboard

\#### 1. Wazuh Alert Timeline

\*\*Fonction:\*\* Affiche l'évolution temporelle des alertes Wazuh

\*\*Interprétation:\*\*

\- \*\*Pics soudains:\*\* Activité suspecte ou attaque en cours

\- \*\*Ligne stable:\*\* Activité normale

\- \*\*Absence d'alertes:\*\* Vérifier que les agents fonctionnent

\*\*Actions:\*\*

\- Cliquer sur un pic pour filtrer les alertes de cette période

\- Ajuster l'intervalle de temps (Last 15 minutes, Last 24 hours, etc.)

\#### 2. Total Alerts

\*\*Fonction:\*\* Compteur du nombre total d'événements

\*\*Interprétation:\*\*

\- \*\*Nombre élevé (>1000/jour):\*\* Possible attaque ou faux positifs

\- \*\*Nombre faible (<10/jour):\*\* Système calme ou agents déconnectés

\#### 3. Attacking IPs

\*\*Fonction:\*\* Liste des adresses IP sources des attaques

\*\*Interprétation:\*\*

\- \*\*IP externe inconnue:\*\* Attaque réelle potentielle → Investiguer

\- \*\*IP interne (192.168.x.x):\*\* Possible compromission interne ou faux positif

\- \*\*IP récurrente:\*\* Attaquant persistant → Bloquer

\*\*Actions:\*\*

\- Cliquer sur une IP pour voir tous ses événements

\- Copier l'IP pour analyse externe (AbuseIPDB, VirusTotal)

\#### 4. Alert Severity

\*\*Fonction:\*\* Distribution des alertes par gravité

\*\*Types d'alertes:\*\*

\- \*\*syslog (~33%):\*\* Événements système généraux

\- \*\*pam (~33%):\*\* Authentifications et accès

\- \*\*authentication success (22%):\*\* Connexions réussies (monitoring)

\- \*\*ossec (~11%):\*\* Alertes Wazuh spécifiques

\*\*Interprétation:\*\*

\- \*\*Pic dans "authentication":\*\* Tentatives de connexion multiples

\- \*\*Augmentation "pam":\*\* Activité utilisateur inhabituelle

\#### 5. Network Attack Signatures

\*\*Fonction:\*\* Signatures d'attaques détectées par Suricata

\*\*Exemples courants:\*\*

\- \*\*"SURICATA HTTP unable to match response":\*\* Trafic HTTP anormal

\- \*\*"ET INFO Http Client Body contains pastebin":\*\* Possible exfiltration

\- \*\*"STREAM CLOSEWAIT FIN":\*\* Anomalie TCP

\- \*\*"ICMPv4 unknown code":\*\* Scan réseau

\*\*Actions:\*\*

\- Cliquer sur une signature pour voir les détails

\- Rechercher la signature sur Internet pour comprendre l'attaque

\#### 6. Targeted Ports

\*\*Fonction:\*\* Ports les plus ciblés par les attaques

\*\*Ports critiques:\*\*

\- \*\*Port 22 (SSH):\*\* Tentatives de connexion à distance

\- \*\*Port 80/443 (HTTP/HTTPS):\*\* Attaques web

\- \*\*Port 3389 (RDP):\*\* Connexion bureau à distance Windows

\- \*\*Port 445 (SMB):\*\* Partage de fichiers Windows

\*\*Interprétation:\*\*

\- \*\*Port 22 en tête:\*\* Brute force SSH probable

\- \*\*Ports élevés (>10000):\*\* Scans de découverte

---

\## Analyse des Alertes

\### Workflow d'Analyse

```

1\. Détection → 2. Investigation → 3. Classification → 4. Réponse

```

\### Étape 1: Détection

\*\*Indicateurs d'alerte:\*\*

\- Nombre total d'alertes soudainement élevé

\- Nouvelle IP dans "Attacking IPs"

\- Signature d'attaque inconnue

\### Étape 2: Investigation

\#### Utiliser Discover pour les détails

1\. Aller dans \*\*Discover\*\*

2\. Sélectionner le Data View:

&nbsp; - `wazuh-alerts-\*` pour alertes hôtes

&nbsp; - `suricata-\*` pour alertes réseau

3\. Filtrer par période: Dernières 15 minutes

4\. Rechercher l'IP ou la signature suspecte

\#### Exemple: Investiguer une IP suspecte

\*\*Requête KQL:\*\*

```

src\_ip: "192.168.229.148"

```

\*\*Champs importants à vérifier:\*\*

\- `src\_ip` / `dest\_ip`: Source et destination

\- `src\_port` / `dest\_port`: Ports utilisés

\- `rule.description`: Description de l'alerte

\- `rule.level`: Niveau de sévérité (0-15)

\- `@timestamp`: Horodatage

\#### Exemple: Voir tous les échecs SSH

\*\*Requête KQL:\*\*

```

rule.description: \*authentication\* AND \*failed\*

```

\### Étape 3: Classification

| Type | Gravité | Action |

|------|---------|--------|

| \*\*Vrai Positif - Critique\*\* | Élevée | Réponse immédiate |

| \*\*Vrai Positif - Mineur\*\* | Moyenne | Investigation approfondie |

| \*\*Faux Positif\*\* | Faible | Ajuster les règles |

| \*\*Test Interne\*\* | Info | Documenter |

\### Étape 4: Réponse

Voir section \[Réponse aux Incidents](#réponse-aux-incidents)

---

\## Réponse aux Incidents

\### Scénario 1: Brute Force SSH Détecté

\*\*Alerte:\*\* Nombreuses tentatives SSH échouées depuis une IP externe

\*\*Actions:\*\*

1\. \*\*Identifier la source\*\*

&nbsp; ```

&nbsp; # Dans Kibana Discover

&nbsp; rule.description: \*sshd\* AND \*authentication\*

&nbsp; ```

2\. \*\*Bloquer l'IP (sur Linux Client)\*\*

&nbsp; ```bash

&nbsp; # Bloquer avec iptables

&nbsp; sudo iptables -A INPUT -s \[IP_ATTAQUANT] -j DROP

&nbsp;

&nbsp; # Ou avec UFW

&nbsp; sudo ufw deny from \[IP_ATTAQUANT]

&nbsp; ```

3\. \*\*Vérifier les connexions réussies\*\*

&nbsp; ```

&nbsp; rule.description: \*authentication\* AND \*success\*

&nbsp; ```

4\. \*\*Documenter l'incident\*\*

\### Scénario 2: Scan de Ports Détecté

\*\*Alerte:\*\* Suricata détecte un scan Nmap

\*\*Actions:\*\*

1\. \*\*Identifier la source dans Kibana\*\*

&nbsp; ```

&nbsp; alert.signature: \*SCAN\* OR \*nmap\*

&nbsp; ```

2\. \*\*Vérifier si des ports sensibles ont été découverts\*\*

3\. \*\*Si IP externe: Bloquer l'IP\*\*

&nbsp; ```bash

&nbsp; # Sur le firewall/routeur

&nbsp; sudo iptables -A INPUT -s \[IP_SCAN] -j DROP

&nbsp; ```

4\. \*\*Si IP interne: Investiguer la machine compromise\*\*

\### Scénario 3: Attaque Web Détectée

\*\*Alerte:\*\* Tentatives SQL Injection ou XSS

\*\*Actions:\*\*

1\. \*\*Identifier les requêtes malveillantes\*\*

&nbsp; ```

&nbsp; alert.signature: \*SQL\* OR \*XSS\* OR \*injection\*

&nbsp; ```

2\. \*\*Vérifier les logs Apache/Nginx\*\*

&nbsp; ```bash

&nbsp; # Sur le serveur web

&nbsp; sudo tail -f /var/log/apache2/access.log

&nbsp; ```

3\. \*\*Bloquer l'IP attaquante\*\*

4\. \*\*Patcher l'application vulnérable\*\*

\### Scénario 4: Fichier Suspect Détecté

\*\*Alerte:\*\* Wazuh détecte un fichier malveillant

\*\*Actions:\*\*

1\. \*\*Localiser le fichier\*\*

&nbsp; ```

&nbsp; rule.description: \*integrity\* OR \*file\*

&nbsp; ```

2\. \*\*Isoler la machine (si nécessaire)\*\*

&nbsp; ```bash

&nbsp; # Déconnecter du réseau

&nbsp; sudo ifconfig ens33 down

&nbsp; ```

3\. \*\*Analyser le fichier\*\*

&nbsp; ```bash

&nbsp; # Vérifier le hash

&nbsp; sha256sum \[fichier_suspect]

&nbsp;

&nbsp; # Rechercher sur VirusTotal

&nbsp; ```

4\. \*\*Supprimer ou mettre en quarantaine\*\*

---

\## Maintenance Quotidienne

\### Checklist Journalière (Analyste SOC)

\#### Matin (9h00)

\- \[ ] \*\*Vérifier le Dashboard\*\*

&nbsp; - Total des alertes dernières 24h

&nbsp; - Nouvelles IPs attaquantes

&nbsp; - Anomalies dans les graphiques

\- \[ ] \*\*Vérifier les agents Wazuh\*\*

&nbsp; ```bash

&nbsp; # Sur Wazuh Manager

&nbsp; ssh socadmin@192.168.229.146

&nbsp; sudo /var/ossec/bin/agent_control -l

&nbsp; ```

&nbsp; Résultat attendu: Tous les agents "Active"

\- \[ ] \*\*Vérifier Suricata\*\*

&nbsp; ```bash

&nbsp; # Sur Suricata VM

&nbsp; ssh socadmin@192.168.229.147

&nbsp; sudo systemctl status suricata

&nbsp; sudo tail -20 /var/log/suricata/fast.log

&nbsp; ```

\- \[ ] \*\*Vérifier Elasticsearch\*\*

&nbsp; ```bash

&nbsp; # Sur Elastic VM

&nbsp; ssh socadmin@192.168.229.143

&nbsp; curl -u elastic:PASSWORD http://localhost:9200/\_cluster/health? pretty

&nbsp; ```

&nbsp; Résultat attendu: `"status" : "green"` ou `"yellow"`

\#### Après-midi (14h00)

\- \[ ] \*\*Analyser les alertes prioritaires\*\*

&nbsp; - Filtrer par niveau: `rule.level >= 10`

&nbsp; - Investiguer chaque alerte critique

\- \[ ] \*\*Mettre à jour les règles Suricata\*\*

&nbsp; ```bash

&nbsp; # Sur Suricata VM

&nbsp; sudo suricata-update

&nbsp; sudo systemctl restart suricata

&nbsp; ```

\#### Fin de journée (17h00)

\- \[ ] \*\*Rapport quotidien\*\*

&nbsp; - Nombre total d'alertes

&nbsp; - Incidents traités

&nbsp; - Actions prises

&nbsp; - Points d'attention pour demain

---

\### Checklist Hebdomadaire (Administrateur)

\#### Lundi

\- \[ ] \*\*Nettoyer les anciens indices Elasticsearch\*\*

&nbsp; ```bash

&nbsp; # Supprimer les indices de plus de 30 jours

&nbsp; curl -u elastic:PASSWORD -X DELETE "http://192.168.229.143:9200/wazuh-alerts-2025-12-\*"

&nbsp; ```

\- \[ ] \*\*Sauvegarder les configurations\*\*

&nbsp; ```bash

&nbsp; # Sur chaque VM

&nbsp; tar -czf /home/socadmin/backup-$(date +%F).tar.gz /etc/

&nbsp; ```

\#### Mercredi

\- \[ ] \*\*Mettre à jour le système\*\*

&nbsp; ```bash

&nbsp; sudo apt update \&\& sudo apt upgrade -y

&nbsp; ```

\#### Vendredi

\- \[ ] \*\*Vérifier les performances\*\*

&nbsp; ```bash

&nbsp; # CPU, RAM, Disk

&nbsp; top

&nbsp; df -h

&nbsp; free -m

&nbsp; ```

\- \[ ] \*\*Exporter le dashboard Kibana\*\*

&nbsp; - Stack Management → Saved Objects → Export

---

\## Dépannage

\### Problème: Pas d'alertes dans Kibana

\*\*Diagnostic:\*\*

1\. \*\*Vérifier les indices\*\*

&nbsp; ```bash

&nbsp; curl -u elastic:PASSWORD "http://192.168.229.143:9200/\_cat/indices?v"

&nbsp; ```

&nbsp; → Doit afficher `wazuh-alerts-\*` et `suricata-\*`

2\. \*\*Vérifier Filebeat sur Wazuh Manager\*\*

&nbsp; ```bash

&nbsp; ssh socadmin@192.168.229.146

&nbsp; sudo systemctl status filebeat

&nbsp; sudo tail -50 /var/log/filebeat/filebeat

&nbsp; ```

3\. \*\*Vérifier Filebeat sur Suricata\*\*

&nbsp; ```bash

&nbsp; ssh socadmin@192.168.229.147

&nbsp; sudo systemctl status filebeat

&nbsp; ```

\*\*Solution:\*\*

```bash

\# Redémarrer Filebeat

sudo systemctl restart filebeat



\# Tester la connexion à Elasticsearch

sudo filebeat test output

```

---

\### Problème: Agent Wazuh déconnecté

\*\*Diagnostic:\*\*

```bash

\# Sur Wazuh Manager

sudo /var/ossec/bin/agent\_control -l

```

Si un agent est "Disconnected":

\*\*Solution:\*\*

```bash

\# Sur l'agent déconnecté (ex: Linux Client)

ssh socadmin@192.168.229.145

sudo systemctl status wazuh-agent



\# Redémarrer l'agent

sudo systemctl restart wazuh-agent



\# Vérifier les logs

sudo tail -50 /var/ossec/logs/ossec.log

```

---

\### Problème: Suricata ne génère pas d'alertes

\*\*Diagnostic:\*\*

```bash

\# Sur Suricata VM

sudo systemctl status suricata

sudo tail -50 /var/log/suricata/suricata.log

```

\*\*Vérifier l'interface réseau:\*\*

```bash

ip a

\# Noter le nom de l'interface (ex: ens33)



\# Vérifier dans la config

sudo grep "interface:" /etc/suricata/suricata.yaml

```

\*\*Solution:\*\*

```bash

\# Éditer la config si nécessaire

sudo nano /etc/suricata/suricata.yaml



\# Redémarrer Suricata

sudo systemctl restart suricata



\# Tester avec un ping

ping -c 5 192.168.229.145

\# Vérifier les logs

sudo tail -f /var/log/suricata/fast.log

```

---

\### Problème: Kibana inaccessible

\*\*Diagnostic:\*\*

```bash

\# Sur Elastic VM

ssh socadmin@192.168.229.143

sudo systemctl status kibana

sudo systemctl status elasticsearch

```

\*\*Solution:\*\*

```bash

\# Redémarrer les services

sudo systemctl restart elasticsearch

\# Attendre 30 secondes

sudo systemctl restart kibana



\# Vérifier les logs

sudo journalctl -u kibana -f

```

---

\### Problème: Espace disque saturé

\*\*Diagnostic:\*\*

```bash

df -h

```

Si `/` est > 90% plein:

\*\*Solution:\*\*

```bash

\# Supprimer les anciens logs

sudo journalctl --vacuum-time=7d



\# Supprimer les anciens indices Elasticsearch

curl -u elastic:PASSWORD -X DELETE "http://localhost:9200/wazuh-alerts-2025-11-\*"



\# Nettoyer les paquets

sudo apt autoremove -y

sudo apt clean

```

---

\## Bonnes Pratiques

\### Sécurité

1\. \*\*Changer les mots de passe par défaut\*\*

&nbsp; ```bash

&nbsp; # Sur Elastic VM

&nbsp; sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic

&nbsp; ```

2\. \*\*Activer HTTPS pour Kibana\*\* (production)

3\. \*\*Restreindre l'accès par IP\*\*

&nbsp; ```bash

&nbsp; # Firewall UFW

&nbsp; sudo ufw allow from 192.168.229.0/24 to any port 5601

&nbsp; ```

\### Performance

1\. \*\*Rotation automatique des indices\*\*

&nbsp; - Configurer ILM (Index Lifecycle Management) dans Elasticsearch

2\. \*\*Limiter la rétention des logs\*\*

&nbsp; - Conserver 30 jours maximum

3\. \*\*Monitorer les ressources\*\*

&nbsp; - CPU < 80%

&nbsp; - RAM < 90%

&nbsp; - Disk < 85%

\### Documentation

1\. \*\*Tenir un journal des incidents\*\*

2\. \*\*Documenter toutes les modifications de config\*\*

3\. \*\*Mettre à jour ce manuel si nécessaire\*\*

---

\## Contact et Support

\*\*Responsable du projet:\*\*

Houcemeddine HERMASSI

\*\*Administrateurs système:\*\*

Nidhal Chelhi
Rochdi Fridhi

\*\*Documentation:\*\*

\- Configuration: `docs/02-configuration-guide.md`

\- Tests: `docs/03-testing-guide.md`

\- GitHub: \[Lien vers le repository]

---

\## Glossaire

| Terme | Définition |

|-------|------------|

| \*\*NIDS\*\* | Network Intrusion Detection System - Détecte les intrusions sur le réseau |

| \*\*HIDS\*\* | Host Intrusion Detection System - Détecte les intrusions sur les hôtes |

| \*\*SIEM\*\* | Security Information and Event Management - Centralise et analyse les logs de sécurité |

| \*\*SOC\*\* | Security Operations Center - Centre de supervision de la sécurité |

| \*\*IDS\*\* | Intrusion Detection System - Système de détection d'intrusions |

| \*\*FIM\*\* | File Integrity Monitoring - Surveillance de l'intégrité des fichiers |

| \*\*Rule\*\* | Règle de détection configurée dans Suricata ou Wazuh |

| \*\*Alert\*\* | Événement de sécurité déclenché par une règle |

| \*\*Index\*\* | Base de données dans Elasticsearch contenant les logs |

| \*\*Data View\*\* | Vue logique des indices dans Kibana |

---

\## Annexes

\### Annexe A: Ports Utilisés

| Service | Port | Protocole |

|---------|------|-----------|

| Elasticsearch | 9200 | HTTP |

| Kibana | 5601 | HTTP |

| Wazuh Manager | 1514 | TCP |

| Wazuh Manager | 1515 | TCP |

| SSH | 22 | TCP |

\### Annexe B: Fichiers de Configuration

| Composant | Fichier de Configuration |

|-----------|--------------------------|

| Elasticsearch | `/etc/elasticsearch/elasticsearch.yml` |

| Kibana | `/etc/kibana/kibana. yml` |

| Wazuh Manager | `/var/ossec/etc/ossec.conf` |

| Wazuh Agent | `/var/ossec/etc/ossec.conf` |

| Suricata | `/etc/suricata/suricata.yaml` |

| Filebeat | `/etc/filebeat/filebeat.yml` |

\### Annexe C: Logs Importants

| Composant | Emplacement des Logs |

|-----------|----------------------|

| Elasticsearch | `/var/log/elasticsearch/` |

| Kibana | `/var/log/kibana/` |

| Wazuh Manager | `/var/ossec/logs/` |

| Wazuh Agent | `/var/ossec/logs/ossec.log` |

| Suricata | `/var/log/suricata/` |

| Filebeat | `/var/log/filebeat/` |

---

\*\*Fin du Manuel Utilisateur\*\*

---

\*Dernière mise à jour: Janvier 2026\*

\*Version: 1.0\*
