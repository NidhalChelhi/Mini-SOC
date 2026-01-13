\# Guide d'Installation - Mini-SOC Platform

\## Table des Matières

1\. \[Prérequis](#prérequis)

2\. \[Installation Elastic Stack](#installation-elastic-stack)

3\. \[Installation Wazuh Manager](#installation-wazuh-manager)

4\. \[Installation Suricata](#installation-suricata)

5\. \[Installation Wazuh Agent](#installation-wazuh-agent)

6\. \[Installation Filebeat](#installation-filebeat)

---

\## Prérequis

\### Infrastructure Requise

\- \*\*Hyperviseur:\*\* VMware Workstation

\- \*\*Réseau:\*\* 192.168.229.0/24 (NAT ou Bridge)

\- \*\*RAM totale:\*\* Minimum 16 GB

\- \*\*Stockage:\*\* Minimum 100 GB

\### VMs à Créer

| VM | OS | RAM | CPU | Stockage |

|----|-----|-----|-----|----------|

| Elastic Stack | Ubuntu Server 22.04 | 4 GB | 2 | 30 GB |

| Wazuh Manager | Ubuntu Server 22.04 | 2 GB | 2 | 20 GB |

| Suricata NIDS | Ubuntu Server 22.04 | 2 GB | 2 | 20 GB |

| Linux Client | Ubuntu Server 22.04 | 2 GB | 1 | 20 GB |

| Kali Linux | Kali Linux 2024 | 4 GB | 2 | 30 GB |

---

\## Installation Elastic Stack

\*\*VM:\*\* 192.168.229.143

\*\*User:\*\* socadmin / socadmin

\### 1. Mise à jour du système

```bash

sudo apt update \&\& sudo apt upgrade -y

```

\### 2. Installation des dépendances

```bash

sudo apt install curl wget apt-transport-https -y

```

\### 3. Installation d'Elasticsearch

```bash

\# Importer la clé GPG

wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg



\# Ajouter le dépôt Elastic

echo "deb \[signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list. d/elastic-8.x. list



\# Installer Elasticsearch

sudo apt update

sudo apt install elasticsearch -y

```

\### 4. Configuration d'Elasticsearch

Éditer `/etc/elasticsearch/elasticsearch.yml`:

```yaml
cluster.name: mini-soc-cluster

node.name: elastic-node-1

network.host: 192.168.229.143

http.port: 9200

discovery.type: single-node

xpack.security.enabled: true
```

\### 5. Démarrer Elasticsearch

```bash

sudo systemctl daemon-reload

sudo systemctl enable elasticsearch

sudo systemctl start elasticsearch

sudo systemctl status elasticsearch

```

\### 6. Configurer le mot de passe Elasticsearch

```bash

sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic

\# Sauvegarder le mot de passe généré

```

\### 7. Installation de Kibana

```bash

sudo apt install kibana -y

```

\### 8. Configuration de Kibana

Éditer `/etc/kibana/kibana.yml`:

```yaml
server.port: 5601

server.host: "192.168.229.143"

elasticsearch.hosts: \["http://192.168.229.143:9200"]

elasticsearch.username: "elastic"

elasticsearch.password: "YOUR\_ELASTIC\_PASSWORD"
```

\### 9. Démarrer Kibana

```bash

sudo systemctl daemon-reload

sudo systemctl enable kibana

sudo systemctl start kibana

sudo systemctl status kibana

```

\### 10. Vérification

Accéder à Kibana: `http://192.168.229.143:5601`

---

\## Installation Wazuh Manager

\*\*VM:\*\* 192.168.229.146

\*\*User:\*\* socadmin / socadmin

\### 1. Mise jour du système

```bash

sudo apt update \&\& sudo apt upgrade -y

```

\### 2. Installation de Wazuh Manager

```bash

\# Importer la clé GPG

curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh. gpg --import \&\& chmod 644 /usr/share/keyrings/wazuh. gpg



\# Ajouter le dépôt Wazuh

echo "deb \[signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources. list.d/wazuh. list



\# Installer Wazuh Manager

sudo apt update

sudo apt install wazuh-manager -y

```

\### 3. Démarrer Wazuh Manager

```bash

sudo systemctl daemon-reload

sudo systemctl enable wazuh-manager

sudo systemctl start wazuh-manager

sudo systemctl status wazuh-manager

```

\### 4. Vérifier l'installation

```bash

sudo /var/ossec/bin/wazuh-control status

```

---

\## Installation Suricata

\*\*VM:\*\* 192.168.229.147

\*\*User:\*\* socadmin / socadmin

\### 1. Mise à jour du système

```bash

sudo apt update \&\& sudo apt upgrade -y

```

\### 2. Installation de Suricata

```bash

sudo add-apt-repository ppa: oisf/suricata-stable -y

sudo apt update

sudo apt install suricata -y

```

\### 3. Configuration de Suricata

Éditer `/etc/suricata/suricata.yaml`:

```yaml

\# Définir l'interface réseau à surveiller

af-packet:

&nbsp; - interface: ens33  # Adapter selon votre interface

&nbsp;   cluster-id: 99

&nbsp;   cluster-type: cluster\_flow

&nbsp;   defrag: yes



\# Définir les réseaux à protéger

vars:

&nbsp; address-groups:

&nbsp;   HOME\_NET:  "\[192.168.229.0/24]"

&nbsp;   EXTERNAL\_NET:  "!$HOME\_NET"

```

\### 4. Mettre à jour les règles Suricata

```bash

sudo suricata-update

sudo suricata-update list-sources

sudo suricata-update enable-source et/open

sudo suricata-update

```

\### 5. Démarrer Suricata

```bash

sudo systemctl enable suricata

sudo systemctl start suricata

sudo systemctl status suricata

```

\### 6. Vérifier les logs

```bash

sudo tail -f /var/log/suricata/fast.log

```

---

\## Installation Wazuh Agent

\*\*VM:\*\* Linux Client-1 (192.168.229.145)

\*\*User:\*\* socadmin / socadmin

\### 1. Mise à jour du système

```bash

sudo apt update \&\& sudo apt upgrade -y

```

\### 2. Installation du Wazuh Agent

```bash

\# Importer la clé GPG

curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import \&\& chmod 644 /usr/share/keyrings/wazuh.gpg



\# Ajouter le dépôt

echo "deb \[signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list



\# Installer l'agent

sudo apt update

sudo WAZUH\_MANAGER='192.168.229.146' apt install wazuh-agent -y

```

\### 3. Démarrer l'agent

```bash

sudo systemctl daemon-reload

sudo systemctl enable wazuh-agent

sudo systemctl start wazuh-agent

sudo systemctl status wazuh-agent

```

\### 4. Vérifier la connexion au manager

\*\*Sur le Wazuh Manager:\*\*

```bash

sudo /var/ossec/bin/agent\_control -l

```

---

\## Installation Filebeat

Filebeat doit être installé sur \*\*3 VMs:\*\*

1\. Wazuh Manager (192.168.229.146)

2\. Suricata NIDS (192.168.229.147)

3\. Elastic Stack (192.168.229.143) - optionnel

\### Sur Wazuh Manager

```bash

\# Installer Filebeat

sudo apt install filebeat -y



\# Télécharger le module Wazuh pour Filebeat

curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/master/extensions/elasticsearch/7.x/wazuh-template.json



\# Configurer Filebeat pour envoyer à Elasticsearch

```

Éditer `/etc/filebeat/filebeat.yml`:

```yaml

output.elasticsearch:

&nbsp; hosts: \["192.168.229.143:9200"]

&nbsp; username: "elastic"

&nbsp; password:  "YOUR\_ELASTIC\_PASSWORD"

&nbsp; indices:

&nbsp;   - index: "wazuh-alerts-%{+yyyy.MM.dd}"



filebeat.inputs:

&nbsp; - type: log

&nbsp;   enabled: true

&nbsp;   paths:

&nbsp;     - /var/ossec/logs/alerts/alerts.json

&nbsp;   json.keys\_under\_root: true

```

```bash

\# Démarrer Filebeat

sudo systemctl enable filebeat

sudo systemctl start filebeat

sudo systemctl status filebeat

```

\### Sur Suricata NIDS

```bash

\# Installer Filebeat

sudo apt install filebeat -y

```

Éditer `/etc/filebeat/filebeat.yml`:

```yaml

output.elasticsearch:

&nbsp; hosts: \["192.168.229.143:9200"]

&nbsp; username: "elastic"

&nbsp; password:  "YOUR\_ELASTIC\_PASSWORD"

&nbsp; indices:

&nbsp;   - index: "suricata-%{+yyyy.MM.dd}"



filebeat.modules:

&nbsp; - module: suricata

&nbsp;   eve:

&nbsp;     enabled: true

&nbsp;     var.paths: \["/var/log/suricata/eve. json"]

```

```bash

\# Activer le module Suricata

sudo filebeat modules enable suricata



\# Démarrer Filebeat

sudo systemctl enable filebeat

sudo systemctl start filebeat

sudo systemctl status filebeat

```

---

\## Vérification Finale

\### 1. Vérifier les indices dans Elasticsearch

```bash

curl -u elastic:YOUR\_PASSWORD -X GET "http://192.168.229.143:9200/\_cat/indices? v"

```

Vous devriez voir:

\- `wazuh-alerts-\*`

\- `suricata-\*`

\### 2. Vérifier dans Kibana

Accéder à Kibana → Management → Stack Management → Index Management

Vous devriez voir les indices créés.

\### 3. Créer les Data Views

Dans Kibana → Management → Stack Management → Data Views:

\- Créer: `wazuh-alerts-\*`

\- Créer: `suricata-\*`

---

\## Résolution des Problèmes Courants

\### Elasticsearch ne démarre pas

```bash

\# Vérifier les logs

sudo journalctl -u elasticsearch -f



\# Vérifier la configuration

sudo /usr/share/elasticsearch/bin/elasticsearch --version

```

\### Wazuh Agent ne se connecte pas

```bash

\# Sur l'agent

sudo /var/ossec/bin/wazuh-control status



\# Vérifier les logs

sudo tail -f /var/ossec/logs/ossec.log

```

\### Filebeat ne transmet pas les logs

```bash

\# Tester la connexion à Elasticsearch

sudo filebeat test output



\# Vérifier la configuration

sudo filebeat test config

```

---

\## Conclusion

Toutes les composantes du Mini-SOC sont maintenant installées.

Passer au guide de configuration pour finaliser le déploiement.

\*\*Prochaine étape:\*\* \[02-configuration-guide.md](02-configuration-guide.md)
