# Guide de Configuration - Mini-SOC Platform

## Table des Matières

1. [Configuration Elasticsearch & Kibana](#configuration-elasticsearch--kibana)
2. [Configuration Wazuh Manager](#configuration-wazuh-manager)
3. [Configuration Suricata](#configuration-suricata)
4. [Configuration Wazuh Agent](#configuration-wazuh-agent)
5. [Configuration Filebeat](#configuration-filebeat)
6. [Création du Dashboard Kibana](#création-du-dashboard-kibana)

---

## Configuration Elasticsearch & Kibana

### 1. Accéder à Kibana

URL: `http://192.168.229.143:5601`

**Credentials:**

- Username: `elastic`
- Password: `[mot de passe configuré lors de l'installation]`

### 2. Créer les Data Views (Index Patterns)

**Navigation:** Stack Management → Data Views → Create data view

#### Data View 1: Wazuh Alerts

- **Name:** `wazuh-alerts`
- **Index pattern:** `wazuh-alerts-*`
- **Timestamp field:** `@timestamp`
- Cliquer sur **Create data view**

#### Data View 2: Suricata Logs

- **Name:** `suricata-logs`
- **Index pattern:** `suricata-*`
- **Timestamp field:** `@timestamp`
- Cliquer sur **Create data view**

### 3. Vérifier l'indexation des données

**Navigation:** Discover

- Sélectionner `wazuh-alerts-*`
- Vérifier que des événements apparaissent
- Sélectionner `suricata-*`
- Vérifier que des événements apparaissent

---

## Configuration Wazuh Manager

**VM:** 192.168.229.146

### 1. Configuration de base

Fichier: `/var/ossec/etc/ossec.conf`

Les sections importantes à vérifier:

```xml
<ossec_config>
  <!-- Configuration globale -->
  <global>
    <email_notification>no</email_notification>
    <logall>yes</logall>
    <logall_json>yes</logall_json>
  </global>

  <!-- Configuration des alertes -->
  <alerts>
    <log_alert_level>3</log_alert_level>
    <email_alert_level>12</email_alert_level>
  </alerts>

  <!-- Logging en JSON pour Filebeat -->
  <logging>
    <log_format>json</log_format>
  </logging>

  <!-- Configuration réseau -->
  <remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>tcp</protocol>
  </remote>
</ossec_config>
```

### 2. Enregistrement des agents

Sur le **Wazuh Manager**, lister les agents connectés:

```bash
sudo /var/ossec/bin/agent_control -l
```

Résultat attendu:

```
Available agents:
   ID:  001, Name: linux-client, IP: 192.168.229.145
```

### 3. Activer la détection d'intrusion

Vérifier que ces modules sont activés dans `/var/ossec/etc/ossec.conf`:

```xml
<!-- File Integrity Monitoring -->
<syscheck>
  <disabled>no</disabled>
  <frequency>43200</frequency>
  <directories check_all="yes">/etc,/usr/bin,/usr/sbin</directories>
  <directories check_all="yes">/bin,/sbin</directories>
</syscheck>

<!-- Rootkit Detection -->
<rootcheck>
  <disabled>no</disabled>
</rootcheck>

<!-- Active Response -->
<active-response>
  <disabled>no</disabled>
</active-response>
```

### 4. Redémarrer Wazuh Manager

```bash
sudo systemctl restart wazuh-manager
sudo systemctl status wazuh-manager
```

---

## Configuration Suricata

**VM:** 192.168.229.147

### 1. Configuration réseau

Fichier: `/etc/suricata/suricata.yaml`

#### Identifier l'interface réseau

```bash
ip a
# Identifier l'interface (généralement ens33 ou eth0)
```

#### Configurer l'interface dans suricata.yaml

```yaml
# Interface de capture
af-packet:
  - interface: ens33 # ADAPTER SELON VOTRE INTERFACE
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    tpacket-v3: yes

# Variables réseau
vars:
  address-groups:
    HOME_NET: "[192.168.229.0/24]"
    EXTERNAL_NET: "!$HOME_NET"

    HTTP_SERVERS: "$HOME_NET"
    SMTP_SERVERS: "$HOME_NET"
    SQL_SERVERS: "$HOME_NET"
    DNS_SERVERS: "$HOME_NET"

  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "! 80"
    ORACLE_PORTS: 1521
    SSH_PORTS: 22
```

### 2. Configuration des outputs

Dans le même fichier `/etc/suricata/suricata.yaml`:

```yaml
# EVE JSON output
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert:
            payload: yes
            payload-buffer-size: 4kb
            payload-printable: yes
            packet: yes
            metadata: yes
            http-body: yes
            http-body-printable: yes
        - http:
            extended: yes
        - dns:
            query: yes
            answer: yes
        - tls:
            extended: yes
        - files:
            force-magic: no
        - ssh
        - flow
```

### 3. Mise à jour des règles

```bash
# Mettre à jour les règles Emerging Threats
sudo suricata-update

# Vérifier les sources disponibles
sudo suricata-update list-sources

# Activer Emerging Threats Open
sudo suricata-update enable-source et/open
sudo suricata-update
```

### 4. Tester la configuration

```bash
# Tester la configuration
sudo suricata -T -c /etc/suricata/suricata.yaml -v

# Si OK, redémarrer Suricata
sudo systemctl restart suricata
sudo systemctl status suricata
```

### 5. Vérifier les logs

```bash
# Logs en temps réel
sudo tail -f /var/log/suricata/eve.json

# Alertes rapides
sudo tail -f /var/log/suricata/fast.log
```

---

## Configuration Wazuh Agent

**VM:** Linux Client-1 (192.168.229.145)

### 1. Configuration de l'agent

Fichier: `/var/ossec/etc/ossec.conf`

```xml
<ossec_config>
  <!-- Configuration du serveur Wazuh Manager -->
  <client>
    <server>
      <address>192.168.229.146</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
  </client>

  <!-- Surveillance de l'intégrité des fichiers -->
  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>

    <!-- Répertoires à surveiller -->
    <directories check_all="yes">/etc</directories>
    <directories check_all="yes">/usr/bin,/usr/sbin</directories>
    <directories check_all="yes">/bin,/sbin</directories>
    <directories check_all="yes" realtime="yes">/home</directories>
  </syscheck>

  <!-- Collecte des logs système -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>

  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/apache2/error.log</location>
  </localfile>
</ossec_config>
```

### 2. Redémarrer l'agent

```bash
sudo systemctl restart wazuh-agent
sudo systemctl status wazuh-agent
```

### 3. Vérifier la connexion

```bash
# Sur l'agent
sudo /var/ossec/bin/wazuh-control status

# Vérifier les logs
sudo tail -f /var/ossec/logs/ossec.log
```

---

## Configuration Filebeat

### Sur Wazuh Manager (192.168.229.146)

Fichier: `/etc/filebeat/filebeat.yml`

```yaml
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/ossec/logs/alerts/alerts.json
    json.keys_under_root: true
    json.overwrite_keys: true
    json.add_error_key: true

output.elasticsearch:
  hosts: ["192.168.229.143:9200"]
  username: "elastic"
  password: "YOUR_ELASTIC_PASSWORD"
  indices:
    - index: "wazuh-alerts-%{+yyyy.MM.dd}"

setup.template.name: "wazuh"
setup.template.pattern: "wazuh-*"
setup.ilm.enabled: false

logging.level: info
logging.to_files: true
logging.files:
  path: /var/log/filebeat
  name: filebeat
  keepfiles: 7
```

**Redémarrer Filebeat:**

```bash
sudo systemctl restart filebeat
sudo filebeat test output
sudo filebeat test config
```

---

### Sur Suricata NIDS (192.168.229.147)

Fichier: `/etc/filebeat/filebeat.yml`

```yaml
filebeat.modules:
  - module: suricata
    eve:
      enabled: true
      var.paths: ["/var/log/suricata/eve.json"]

output.elasticsearch:
  hosts: ["192.168.229.143:9200"]
  username: "elastic"
  password: "YOUR_ELASTIC_PASSWORD"
  indices:
    - index: "suricata-%{+yyyy. MM.dd}"

setup.template.name: "suricata"
setup.template.pattern: "suricata-*"
setup.ilm.enabled: false

logging.level: info
logging.to_files: true
logging.files:
  path: /var/log/filebeat
  name: filebeat
  keepfiles: 7
```

**Activer le module Suricata:**

```bash
sudo filebeat modules enable suricata

# Redémarrer Filebeat
sudo systemctl restart filebeat
sudo filebeat test output
sudo filebeat test config
```

---

## Création du Dashboard Kibana

### 1. Importer le Dashboard

Si vous avez un dashboard exporté (`kibana-dashboard.ndjson`):

**Navigation:** Stack Management → Saved Objects → Import

- Sélectionner le fichier `kibana-dashboard.ndjson`
- Cliquer sur **Import**

### 2. Créer un Dashboard Manuellement

**Navigation:** Dashboard → Create dashboard → Add visualization

#### Visualisation 1: Wazuh Alert Timeline

- **Type:** Area chart / Line chart
- **Data view:** `wazuh-alerts-*`
- **Metrics:** Count
- **Buckets:**
  - X-axis: Date Histogram on `@timestamp` (interval: 30s)
  - Split series: Terms on `rule. description` (top 5)

#### Visualisation 2: Total Alerts Counter

- **Type:** Metric
- **Data view:** `wazuh-alerts-*`
- **Metrics:** Count of records

#### Visualisation 3: Attacking IPs

- **Type:** Data table
- **Data view:** Combined (wazuh + suricata)
- **Metrics:** Count
- **Buckets:** Terms on `src_ip` (top 10)

#### Visualisation 4: Alert Severity

- **Type:** Pie chart / Donut chart
- **Data view:** `wazuh-alerts-*`
- **Metrics:** Count
- **Buckets:** Terms on `rule.level` or alert category

#### Visualisation 5: Network Attack Signatures

- **Type:** Horizontal bar chart
- **Data view:** `suricata-*`
- **Metrics:** Count
- **Buckets:** Terms on `alert.signature` (top 10)

#### Visualisation 6: Targeted Ports

- **Type:** Data table / Bar chart
- **Data view:** `suricata-*`
- **Metrics:** Count
- **Buckets:** Terms on `dest_port` (top 10)

### 3. Sauvegarder le Dashboard

- Cliquer sur **Save**
- Nom: `Mini-SOC Main Dashboard`
- Description: `Dashboard centralisé pour la surveillance NIDS/HIDS`

---

## Vérification Finale

### 1. Vérifier les indices Elasticsearch

```bash
curl -u elastic:PASSWORD -X GET "http://192.168.229.143:9200/_cat/indices?v"
```

Résultat attendu:

```
health status index
green  open   wazuh-alerts-2026.01.13
green  open   suricata-2026.01.13
```

### 2. Vérifier les agents Wazuh

Sur le **Wazuh Manager**:

```bash
sudo /var/ossec/bin/agent_control -l
```

### 3. Vérifier Suricata

```bash
sudo systemctl status suricata
sudo tail -f /var/log/suricata/fast.log
```

### 4. Vérifier Filebeat

Sur chaque machine avec Filebeat:

```bash
sudo systemctl status filebeat
sudo tail -f /var/log/filebeat/filebeat
```

---

## Dépannage

### Problème: Pas de données dans Kibana

**Solution 1:** Vérifier Filebeat

```bash
sudo filebeat test output
sudo filebeat test config
sudo systemctl restart filebeat
```

**Solution 2:** Vérifier les indices

```bash
curl -u elastic:PASSWORD "http://192.168.229.143:9200/_cat/indices?v"
```

**Solution 3:** Vérifier les Data Views dans Kibana

- Stack Management → Data Views
- S'assurer que `wazuh-alerts-*` et `suricata-*` existent

### Problème: Wazuh Agent déconnecté

```bash
# Sur l'agent
sudo systemctl restart wazuh-agent

# Sur le manager
sudo /var/ossec/bin/agent_control -l

# Vérifier les logs
sudo tail -f /var/ossec/logs/ossec.log
```

### Problème: Suricata ne génère pas d'alertes

```bash
# Vérifier l'interface
ip a

# Vérifier que Suricata écoute
sudo suricata -T -c /etc/suricata/suricata.yaml

# Redémarrer
sudo systemctl restart suricata
```

---

## Conclusion

La configuration du Mini-SOC est maintenant terminée.  
Le système est prêt pour les tests d'intrusion.

**Prochaine étape:** [03-testing-guide.md](03-testing-guide.md)
