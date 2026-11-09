# IDS Lab : documentation technique

L'installation et le parcours de démonstration sont dans le [`README.md`](../../README.md). Ce document
explique comment le lab fonctionne. L'historique des choix est dans
[`rapports/journal_decisions.md`](rapports/journal_decisions.md).

Sommaire : [1. Vocabulaire](#1-vocabulaire) · [2. Architecture](#2-architecture) ·
[3. Le réseau](#3-le-réseau) · [4. Les services](#4-les-services) · [5. Le trafic bénin](#5-le-trafic-bénin) ·
[6. Les attaques](#6-les-attaques) · [7. Les datasets](#7-les-datasets) ·
[8. L'entraînement](#8-lentraînement) · [9. La détection en direct](#9-la-détection-en-direct) ·
[10. Pourquoi pas ConCap tel quel](#10-pourquoi-pas-concap-tel-quel) · [11. Choix techniques](#11-choix-techniques) ·
[12. Tests](#12-tests) · [13. Dépannage](#13-dépannage) · [14. Limites](#14-limites-connues) ·
[15. API et formats](#15-api-et-formats) · [16. Questions fréquentes](#16-questions-fréquentes)

---

## 1. Vocabulaire

| Terme | Signification |
| ----- | ------------- |
| **NIDS / ML-IDS** | détecteur d'intrusion réseau / dont la décision vient d'un modèle entraîné |
| **Sonde IDS** | équipement qui reçoit une copie du trafic d'un switch et fait tourner le modèle |
| **Port miroir** | port recevant une copie du trafic : la sonde voit tout sans être sur le chemin |
| **Flux** | conversation (IP et ports source et destination, protocole). Le modèle classe des flux, pas des paquets |
| **Features** | caractéristiques numériques d'un flux : durée, volumes par sens, temps entre paquets, drapeaux TCP |
| **CICFlowMeter** | outil qui transforme un pcap en flux avec environ 80 features ; a servi à construire CIC-IDS2017/2018 |
| **Vérité terrain** | ce qui s'est réellement passé, comparé aux décisions du modèle |
| **Fausse alerte / attaque manquée** | bénin classé attaque / attaque classée bénigne |
| **Évasion** | modifier une attaque pour que le modèle la classe bénigne |
| **Empoisonnement** | corrompre les données d'entraînement |

---

## 2. Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│ INTERFACE — React 19, React Flow, Vite                     code/src/ │
│ éditeur · Trafic, Scénarios, Datasets, IDS, Détection · terminal,    │
│ capture                                                              │
└─────────────────────────────┬────────────────────────────────────────┘
                              │ REST, Server-Sent Events, WebSocket
┌─────────────────────────────▼────────────────────────────────────────┐
│ MOTEUR — Python, FastAPI                           code/backend/app/ │
│ planner, deployer · traffic, traffic_agent · capture, cicflowmeter   │
│ datasets · training · detection                                      │
└───────────┬──────────────────────────────────────────────┬───────────┘
            │ SDK Docker                                   │ fichiers
┌───────────▼────────────────────────────────┐ ┌───────────▼───────────┐
│ RÉSEAU DU LAB (conteneurs)                 │ │ backend/data/         │
│ PC · routeurs · serveurs · sonde IDS       │ │ datasets : pcap, CSV  │
│ switches = bridges Linux                   │ │ modèles : joblib      │
└────────────────────────────────────────────┘ └───────────────────────┘
```

L'interface ne parle jamais de Docker : le moteur traduit chaque action. REST sert aux actions, les
Server-Sent Events aux tâches longues (déploiement, dataset, entraînement), les WebSockets aux terminaux
et captures. Pas de base de données : tout est fichier dans `backend/data/`, ignoré par git.

| Code | Rôle |
| ---- | ---- |
| `src/components/TopologyEditor.jsx` | assemblage de l'interface |
| `src/components/{TrafficPanel,ScenarioPanel,DetectionPanel}.jsx` | panneaux de droite |
| `src/components/{DatasetDialog,ModelDialog}.jsx` | datasets ; modèles et rapport |
| `src/components/{TerminalView,CaptureView}.jsx`, `Dock.jsx` | onglets du bas |
| `src/utils/{ipam,validators,packetDissector,displayFilter}.js` | adressage, contrôles, décodage des paquets |
| `backend/app/planner.py`, `deployer.py` | topologie → plan → conteneurs, mode hub |
| `backend/app/service_listener.py` | vrais services des serveurs |
| `backend/app/traffic.py`, `traffic_agent.py` | trafic bénin, attaques |
| `backend/app/cicflowmeter.py` | découpage du pcap, flux CICFlowMeter |
| `backend/app/datasets.py`, `training.py`, `detection.py` | les trois étapes ML |
| `backend/app/capture.py`, `terminal.py` | sessions WebSocket |
| `backend/config/devices.toml` | images et paquets de chaque équipement |

Pour **ajouter un modèle** : une entrée dans `MODELS` et sa construction dans `Trainer.run`
(`training.py`) ; la détection le prend en charge sans changement, car `model.joblib` porte la liste
ordonnée de ses features.

---

## 3. Le réseau

| Sur le schéma | Dans Docker |
| ------------- | ----------- |
| Switch | réseau `bridge`, un segment de niveau 2 avec son sous-réseau |
| PC | conteneur Alpine avec les clients de chaque service, nmap et hydra |
| Serveur | conteneur Python qui lance les vrais démons déclarés |
| Routeur | conteneur multi-réseaux, `ip_forward=1`, routes statiques |
| Sonde IDS | conteneur relié au switch surveillé, passé en mode hub |

**Règles** : un câble relie toujours un équipement à un switch ; chaque câble est une interface (IP +
masque). Un switch n'a pas d'adresse IP, il porte le réseau. L'IPAM (`src/utils/ipam.js`) attribue tout
automatiquement : réseaux `10.0.N.0/24`, routeurs à partir de `.1`, hôtes à partir de `.10` ; saisir un champ
le passe en manuel. La dernière adresse de chaque réseau est réservée au bridge. Les tables de routage restent
à saisir, hors réseaux directement connectés. Les erreurs de cohérence bloquent la création et sont
revérifiées par le moteur.

**Déploiement** : `planner.py` valide et produit un plan, `deployer.py` l'exécute et envoie sa progression.
Chaque déploiement supprime le précédent, un échec nettoie tout. Toutes les ressources portent le label
`idslab.managed=true`. Le réseau est isolé : pas de route vers l'hôte ni Internet.

**Port miroir** : un bridge Linux apprend les adresses MAC et n'envoie à chaque port que ce qui lui est
destiné. Avec `ageing_time = 0`, il n'apprend plus et diffuse tout, comme un hub : la sonde reçoit une copie
de tout le segment. **Elle ne voit que ce switch** : une attaque qui ne le traverse pas lui est invisible.

**Modifier le réseau** : ■ Arrêter, modifier, ✔ Valider ; rien ne s'applique à chaud.

**Terminal** : clic sur un PC ou un serveur allumé (`exec` Docker avec TTY relayé par WebSocket).

**Capture d'un câble (vue Wireshark)** : sélection du câble puis **Capturer le trafic**, ou double-clic.
Un conteneur éphémère partage la pile réseau de l'équipement et lance `tcpdump`. Le navigateur décode les
paquets (`packetDissector.js`), applique des filtres à la syntaxe Wireshark (`displayFilter.js`) et exporte
un `.pcap`. Limite : 50 000 paquets par capture.

---

## 4. Les services

Une simple bannière ne produit pas les échanges d'une vraie session : le modèle apprendrait des artefacts.

| Service | Port | Implémentation | Contenu |
| ------- | ---- | -------------- | ------- |
| HTTP | 80 | serveur HTTP/1.1 Python, connexions persistantes (annoncé `nginx/1.26.1`) | 20 pages de 6 à 50 Ko, images, téléchargements de 0,45 à 9 Mo, API JSON, `POST /login` |
| HTTPS | 443 | le même en TLS 1.3, certificat auto-signé | idem |
| SSH | 22 | OpenSSH avec SFTP | fichiers de `labuser` |
| FTP | 21 | vsftpd, passif sur 40000-40100, dépôt autorisé | mêmes fichiers, `upload/` |
| Telnet | 23 | telnetd + `/bin/login` | shell, tout en clair |
| SMTP | 25 | OpenSMTPD, tout destinataire vers la boîte de `labuser` | sans authentification ni STARTTLS |
| DNS | 53 | dnsmasq, autorité sur `.lab` | un nom par équipement : `serveur-web.lab` |
| MySQL | 3306 | MariaDB 11 (démarrage de quelques secondes) | base `boutique` : `produits` (200), `commandes` |
| autre nom | – | simulé : bannière en TCP, écho en UDP | pas de vrai protocole |

Le type est reconnu par le **nom** du service, le port usuel ne sert qu'en l'absence de nom. Si un démon
échoue au démarrage, le service retombe sur le simulateur et le journal du serveur l'indique. Compte unique,
volontairement faible pour la force brute : **`labuser` / `password123`**.

Test rapide depuis le terminal d'un PC, avec `S=<IP du serveur>` :

| Service | Commande |
| ------- | -------- |
| Ports | `for p in 21 22 23 25 53 80 443 3306; do nc -zv -w 2 $S $p; done` |
| HTTP, HTTPS | `curl http://$S/` ; `curl -k https://$S/` |
| SSH | `ssh labuser@$S` |
| FTP | `curl ftp://labuser:password123@$S/` |
| Telnet | `telnet $S` |
| SMTP | `echo "Subject: test" > /tmp/m; curl -s smtp://$S --mail-from pc-1@lab --mail-rcpt labuser@lab -T /tmp/m` |
| DNS | `nslookup serveur-web.lab $S` |
| MySQL | `mariadb -h $S -u labuser -ppassword123 boutique -e "SELECT * FROM produits LIMIT 5;"` |

---

## 5. Le trafic bénin

Un **agent** (`traffic_agent.py`) tourne dans un conteneur qui partage la pile réseau de l'émetteur : pour
la sonde, c'est bien le PC qui parle. Chaque action est une session complète avec un vrai client.

| Type | Session |
| ---- | ------- |
| Web | navigation (1 à 4 pages et leurs ressources sur la même connexion, 10 % de téléchargements) ; API (12 %) ; formulaire de connexion (8 %) |
| SSH | commandes (70 %) ou `scp` (30 %) |
| FTP | listing, 1 à 3 transferts |
| SMTP | courriel de 3 à 400 lignes, pièce jointe dans 30 % des cas |
| MySQL | 1 à 6 requêtes |
| Telnet | 1 à 3 commandes |
| DNS | résolution avant 60 % des sessions, requêtes isolées dont des noms inexistants |
| Ping | 1 à 4 paquets, tailles variables |

Poids relatifs : HTTP 5, HTTPS 5, SSH 2, MySQL 2, FTP 1,5, SMTP 1,5, Ping 1,5, Telnet 0,5, autre 0,5. Seuls les
services **ouverts chez les destinataires** reçoivent des sessions.

En SSH, FTP et MySQL, une connexion sur 20 commence par **une** erreur de mot de passe, suivie du bon : une
erreur isolée n'est pas une force brute, et le modèle doit le savoir.

| Fréquence | Pause entre sessions | Sessions en parallèle |
| --------- | -------------------- | --------------------- |
| Lente | 8 à 12 s | 1 |
| Modérée | 2 à 4 s | 1 |
| Soutenue | 0,6 à 1,4 s | 2 |
| Intense | 0,2 à 0,45 s | 3 |

---

## 6. Les attaques

| Scénario | Commande | Classe |
| -------- | -------- | ------ |
| Balayage de découverte | `nmap -sn` | ping-sweep |
| Scan de ports (connect, 200 ports) | `nmap -sT --top-ports 200` | port-scan |
| Scan furtif (SYN, tous les ports) | `nmap -sS -p-` | syn-scan |
| Identification des services | `nmap -sV --top-ports 100` | service-detection |
| Scan approfondi | `nmap -A` | aggressive-scan |
| Force brute SSH, FTP | `hydra -l labuser -P <liste> -f` | ssh-patator, ftp-patator |

Quatre vitesses : nmap `-T2` à `-T5`, hydra 1 à 16 connexions parallèles. Les attaques tournent dans un
conteneur qui partage la pile réseau de la source. Chaque scénario lancé depuis **⚡ Scénarios** produit un CSV
de flux étiquetés téléchargeable (capturé sur la source).

`nmap` et `hydra` sont aussi installés sur les PC, pour rejouer à la main. Ces attaques-là ne sont pas connues
du moteur : elles ne figurent pas dans la vérité terrain. Pendant la génération d'un dataset, elles seraient
étiquetées BENIGN.

---

## 7. Les datasets

**🗂 Datasets** joue un **programme** sur le réseau en marche (`datasets.py`) :

1. la **Sonde IDS** capture le segment dans un pcap unique : c'est le seul point de capture, pour que
   l'entraînement et la détection aient le même point de vue ;
2. des agents bénins tournent pendant toute la durée ;
3. les attaques s'enchaînent, entrecoupées de bénin seul, chacune dans une fenêtre de temps enregistrée ;
4. le pcap est découpé en **fenêtres de 5 s**, et CICFlowMeter transforme chaque fenêtre en flux ;
5. chaque flux est étiqueté.

**Étiquetage** : un flux porte le nom de l'attaque s'il va de la source vers la cible et commence pendant la
fenêtre de l'attaque (marge de 1 s avant, 2 s après), sinon BENIGN. L'agent bénin de la machine attaquante est
**mis en pause** pendant l'attaque, ce qui rend la règle exacte.

**Pourquoi 5 s** : la détection analyse par tranches de 5 s sans attendre la fin des conversations.
L'entraînement doit voir les flux de la même façon. Limite : une conversation longue est coupée.

**Variantes de test** (0 à 5, déterministes) : rejouent le programme en changeant la machine d'attaque, la
vitesse de chaque attaque et l'intensité du bénin. On vérifie ainsi que le modèle a appris un comportement.

**Durées par défaut** : bénin seul 30 s au début, 10 s entre attaques, 20 s à la fin ; attaque limitée à 60 s.

**Sortie** : `backend/data/datasets/<id>/` avec `flows.csv`, `capture.pcap`, `meta.json` (paramètres,
fenêtres, décompte, topologie), téléchargeables depuis l'interface.

---

## 8. L'entraînement

**🧠 IDS** entraîne un **random forest** binaire (BENIGN / ATTACK), 100 arbres par défaut (`training.py`).

- **Features retirées** : `Flow ID`, `Src IP`, `Src Port`, `Dst IP`, `Timestamp`, et `Dst Port` par défaut.
  Sinon le modèle apprendrait « PC-1 attaque » ou « ce port = attaque » plutôt qu'un comportement.
- **Nettoyage** : `inf` et `NaN` remplacés par 0, colonnes constantes écartées.
- **Poids équilibrés par étiquette d'origine** (bénin, port-scan, ssh-patator…) : un scan produit des milliers
  de flux, une force brute quelques dizaines ; sans cela, le scan décide seul de ce qu'est une attaque.
- **Test** : datasets séparés (les variantes), ou fin chronologique du jeu. Pas de découpage aléatoire : des
  flux quasi identiques se retrouveraient des deux côtés et gonfleraient les scores.

| Métrique | Définition |
| -------- | ---------- |
| Attaques détectées | part des flux d'attaque classés attaque (rappel) |
| Fausses alertes | part des flux bénins classés attaque |
| Exactitude | part des flux bien classés (trompeuse si les classes sont déséquilibrées) |
| F1 macro | moyenne des F1 de chaque classe |

### Comment est calculée l'importance des features

Le rapport affiche `feature_importances_` de scikit-learn, c'est-à-dire la **baisse moyenne d'impureté**
(Mean Decrease in Impurity, MDI) :

1. à chaque nœud d'un arbre, on choisit le seuil sur une feature qui sépare le mieux BENIGN et ATTACK ;
2. le gain du nœud est la baisse d'impureté de Gini, pondérée par la part d'échantillons qui atteignent ce
   nœud : `(n_nœud / n) × (Gini_nœud − (n_g / n_nœud) × Gini_g − (n_d / n_nœud) × Gini_d)`, avec
   `Gini = 1 − Σ p_c²` ;
3. pour chaque arbre, on additionne les gains par feature et on normalise pour que la somme vaille 1 ;
4. on fait la moyenne sur tous les arbres.

Une importance de 12 % signifie donc : 12 % de la réduction totale d'impureté lors de l'**entraînement**
vient de décisions sur cette feature. Cela ne dit **pas** que retirer cette feature ferait perdre 12 % de
détection. Trois précautions :

- elle est calculée sur le **jeu d'entraînement** : elle décrit ce que le modèle a utilisé, pas ce qui
  généralise ;
- entre **features corrélées**, très nombreuses dans CICFlowMeter (`Flow Pkts/s` et `Fwd Pkts/s`), l'importance
  se répartit de façon arbitraire ;
- elle ne donne pas de **sens** (une valeur haute indique-t-elle l'attaque ?).

Pour préparer une évasion, on se méfiera donc de ce classement seul : l'importance par permutation sur un jeu
de test (`sklearn.inspection.permutation_importance`) est plus fiable.

Le rapport donne aussi la **détection par type d'attaque** : le score global d'un IDS binaire est dominé par
l'attaque la plus volumineuse et peut masquer une attaque ratée.

## 9. La détection en direct

**🛡 Détection** (`detection.py`) :

1. `tcpdump` tourne sur la sonde et écrit un fichier par fenêtre de 5 s ;
2. chaque fenêtre terminée passe dans un conteneur CICFlowMeter permanent ;
3. le modèle classe chaque flux ;
4. chaque verdict est comparé à la vérité terrain : les attaques lancées depuis ⚡ Scénarios ou 🗂 Datasets
   (source, cible, début, fin), avec la règle d'étiquetage des datasets.

L'agent bénin de la source est suspendu pendant son attaque, comme dans un dataset, puis relancé à la fin : sans
cela, ses sessions seraient comptées comme des attaques manquées.

Le modèle ne reconnaît que ce qu'il a appris : le panneau signale une attaque absente de l'entraînement.

Le bilan compte des **flux**, pas des attaques : une attaque de 200 flux dont 190 sont reconnus donne 190/200.
Les équipements impliqués dans une alerte récente sont entourés de rouge.

Le rapport d'entraînement donne des chiffres reproductibles, la détection montre le comportement en direct.

---

## 10. Pourquoi pas ConCap tel quel

[ConCap](https://github.com/idlab-discover/ConCap) génère des datasets d'IDS à partir de scénarios YAML, sur
Kubernetes. C'était le point de départ prévu.

| | ConCap | Besoin du projet |
| --- | ------ | ---------------- |
| Infrastructure | cluster Kubernetes (k3s), nœuds étiquetés, secret ghcr | Docker seul, piloté depuis l'interface |
| Topologie | réseau plat, sans routeur | LAN, DMZ, routeurs |
| Capture | sur la cible | sur la sonde |
| Trafic bénin | pas de trafic de fond | continu, pendant les attaques |
| Étiquetage | une étiquette par scénario, dans le YAML | par flux, dans un trafic mélangé |
| Flux | pcap entier | fenêtres de 5 s |

**L'argument décisif est le point de vue** : un modèle apprend les flux tels qu'ils sont vus à l'endroit de la
capture. Entraîné sur la vue d'une cible isolée, il serait évalué sur des flux qui ne ressemblent pas à ce
qu'il a appris.

Sont repris : la méthode (scénario → capture → CICFlowMeter → étiquetage connu d'avance) et l'image CICFlowMeter
conteneurisée, donc les colonnes de ConCap et de CIC-IDS. *Sources : README et runbook k3s du dépôt officiel,
consultés le 6 novembre 2026.*

---

## 11. Choix techniques

| Besoin | Choix | Écarté | Raison |
| ------ | ----- | ------ | ------ |
| Interface | React + React Flow | Packet Tracer, GNS3 | intégrée au pipeline ML ; Packet Tracer n'exécute pas de vrais logiciels |
| Moteur | Python, FastAPI, SDK Docker | Node.js | même langage que scikit-learn |
| Machines | conteneurs Docker | VM, Mininet, Kubernetes | dizaines de machines en quelques secondes sur un portable |
| Port miroir | bridge en hub | Open vSwitch, sonde en coupure | inclus dans Docker, sonde hors du chemin |
| Services | vrais démons | bannières | vraies sessions |
| Trafic bénin | agent maison, vrais clients | rejeu de pcap | un pcap rejoué ne correspond pas aux adresses de la topologie |
| Attaques | nmap, hydra | scripts maison | outils de référence, ceux des jeux CIC-IDS |
| Features | CICFlowMeter | features maison | comparable à la littérature |
| Modèle | random forest | réseaux de neurones, SVM | rapide, sans normalisation, explicable ; d'autres modèles sont prévus |
| Stockage | fichiers | base de données | simple, inspectable |

---

## 12. Tests

```bash
cd code/backend && source .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest            # sans Docker, quelques secondes
```

```bash
cd code && npm run build    # l'interface compile
```

| Fichier | Vérifie |
| ------- | ------- |
| `test_planner.py`, `test_examples.py` | topologie → plan ; chaque exemple est accepté et toute machine joint toute autre |
| `test_capture.py` | découpage du flux de capture |
| `test_cicflowmeter.py` | découpage en fenêtres, étiquetage d'un scénario |
| `test_datasets.py` | programmes, variantes, étiquetage par fenêtres |
| `test_training.py` | features, découpages, entraînement, métriques |
| `test_detection.py` | fenêtres, verdicts, vérité terrain |
| `test_benign.py` | services et sessions de l'agent |
| `test_settings.py` | origines autorisées |

---

## 13. Dépannage

| Symptôme | Solution |
| -------- | -------- |
| « Moteur de simulation hors ligne » | moteur non lancé ou Docker arrêté (`docker info`) |
| `permission denied … docker.sock` | `sudo usermod -aG docker $USER`, puis se reconnecter |
| `uvicorn: command not found` | activer l'environnement : `source .venv/bin/activate` |
| `address already in use` | un moteur tourne déjà sur le port 8000 |
| « le moteur a refusé la connexion » | moteur lancé avant une mise à jour, sans `--reload` : le relancer |
| Premier déploiement très long | téléchargement et construction des images, une seule fois |
| « … déjà utilisé sur la machine hôte » | le réseau d'un switch chevauche un réseau Docker existant : le changer |
| Vite refuse de démarrer | Node trop ancien : `cd code && nvm install && nvm use` |
| Import introuvable au build, `@rolldown/binding-…` | `node_modules` périmé : `npm ci` |
| Un service ne répond pas juste après la validation | MySQL met quelques secondes à démarrer |
| `ssh`, `mariadb`… « not found » sur un PC | réseau créé avant l'ajout de ces clients : ■ Arrêter puis ✔ Valider |
| `curl: (60)` en HTTPS | certificat auto-signé : `-k` |
| Service « simulé » dans le journal du serveur | nom non reconnu ou démon absent |
| Aucun flux d'attaque dans un dataset | la sonde ne surveille pas le switch traversé par l'attaque |

Nettoyage manuel complet, moteur arrêté :

```bash
docker rm -f $(docker ps -aq --filter label=idslab.managed=true)
docker network rm $(docker network ls -q --filter label=idslab.managed=true)
docker image rm $(docker image ls -q 'idslab/*')
```

Variables optionnelles : `VITE_API_BASE_URL` (`code/.env`), `IDSLAB_CORS_ORIGINS`, `IDSLAB_DEVICES_CONFIG`,
`IDSLAB_DATA_DIR`, `IDSLAB_CICFLOWMETER_IMAGE`.

---

## 14. Limites connues

- **Trafic bénin synthétique** : vraies sessions, mais un compte, un site, pas de profils d'utilisateurs.
- **Timing** : tout tourne sur un hôte, latence quasi nulle, ce qui change les features temporelles.
- **Couverture d'attaque** : reconnaissance et force brute seulement.
- **Attaques connues seulement** : un modèle supervisé ne reconnaît que les familles apprises.
- **Un modèle par topologie** : l'interface prévient en cas de mélange.
- **Flux à cheval** : un flux qui chevauche deux fenêtres est vu en deux morceaux.
- **La sonde ne voit que son switch.**
- **Force brute** : les protections d'OpenSSH (`PerSourcePenalties`, `MaxStartups`) sont désactivées dans le lab, car
  elles coupaient l'attaque. Un flux de force brute SSH ressemble à une vraie session.
- **Fausses alertes** : environ 5 % en direct lors du dernier test, davantage si des émetteurs n'étaient pas
  présents à l'entraînement. Voir [`rapports/rapport_ids.md`](rapports/rapport_ids.md).

---

## 15. API et formats

Toutes les routes sont décrites en tête de [`backend/app/main.py`](../backend/app/main.py).

**Topologie (JSON, version 2)** : l'interface envoie `{ version, nodes, networks, links }`. Exemples complets
dans `examples/topologies/` ; ajouter un fichier ajoute un exemple au menu, et `test_examples.py` le vérifie.

```json
{ "version": 2,
  "nodes": [{ "id": "pc-1", "type": "pc", "name": "PC-1", "position": { "x": 120, "y": 80 }, "config": { "gateway": "10.0.1.1" } }],
  "networks": [{ "id": "switch-1", "name": "Switch-1", "position": { "x": 120, "y": 240 }, "vlan": null, "subnet": "10.0.1.0/24" }],
  "links": [{ "id": "link-1", "node": "pc-1", "network": "switch-1", "interface": "eth0", "port": "Fa0/1", "ip": "10.0.1.10", "mask": "255.255.255.0" }] }
```

Types de nœuds : `pc`, `server` (`config.services`), `router` (`config.routes`), `ids` (`config.monitoredSegment`).

**Modèle sauvegardé** : `backend/data/models/<id>/model.joblib` (modèle, liste ordonnée des features,
`excludePort`, `flowWindowSec`) et `meta.json` (paramètres et métriques).

---

## 16. Questions fréquentes

**Pourquoi un laboratoire plutôt que CIC-IDS2017 ?** Un jeu figé ne permet pas de lancer une attaque modifiée
et de voir si l'IDS la détecte, ni de vérifier que l'attaque fonctionne encore.

**Le trafic est-il réel ?** Oui : vrais paquets, vrais logiciels. Sont artificiels le comportement des
utilisateurs, choisi par l'agent, et le timing.

**Pourquoi des flux ?** C'est l'approche standard des NIDS à base de ML, et les features n'utilisent jamais le
contenu : le trafic chiffré reste analysable.

**Pourquoi retirer les IP des features ?** Le modèle apprendrait « PC-1 attaque ». Les variantes changent
justement la machine d'attaque.

**Pourquoi un random forest ?** Performant sur des données tabulaires, rapide, sans normalisation. D'autres
modèles sont prévus pour tester le transfert des attaques.

**Pourquoi entraîner plutôt que prendre un modèle préentraîné ?** Un modèle appris ailleurs ne connaît ni nos
latences, ni nos services ; l'évasion et l'empoisonnement exigent de maîtriser le modèle et ses données.

**Est-ce dangereux de lancer nmap et hydra ?** Non : le réseau est isolé de l'hôte et d'Internet.
