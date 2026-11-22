# IDS Lab : documentation technique

L'installation et le parcours de démonstration sont dans le [`README.md`](../../README.md). Ce document
explique comment le lab fonctionne. L'historique des choix est dans
[`rapports/journal_decisions.md`](rapports/journal_decisions.md).

Sommaire : [1. Vocabulaire](#1-vocabulaire) · [2. Architecture](#2-architecture) ·
[Suivre le code](#suivre-le-code--ce-que-déclenche-chaque-bouton) ·
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
│ schéma · Simulation, Datasets, IDS, Détection                        │
└─────────────────────────────┬────────────────────────────────────────┘
                              │ REST (+ polling)
┌─────────────────────────────▼────────────────────────────────────────┐
│ MOTEUR — Python, FastAPI                           code/backend/app/ │
│ lab · traffic, traffic_agent · cicflowmeter                          │
│ datasets · training · detection                                      │
└───────────┬──────────────────────────────────────────────┬───────────┘
            │ docker compose + SDK Docker                  │ fichiers
┌───────────▼────────────────────────────────┐ ┌───────────▼───────────┐
│ RÉSEAU DU LAB (conteneurs)                 │ │ backend/data/         │
│ PC · routeurs · serveurs · sonde IDS       │ │ datasets : pcap, CSV  │
│ switches = bridges Linux                   │ │ modèles : joblib      │
└────────────────────────────────────────────┘ └───────────────────────┘
```

L'interface ne parle jamais de Docker : le moteur traduit chaque action. REST sert aux actions ; pour les
tâches longues (dataset, entraînement), l'interface redemande leur état toutes les secondes (polling). Pas de base de données : tout est fichier dans `backend/data/`, ignoré par git.

### Carte du code

Chemins relatifs à `code/`. Les fichiers en gras sont ceux à lire en premier.

**Interface** (`src/`, React) : les *composants* affichent, les *hooks* gardent l'état et appellent le moteur,
les *utils* sont des fonctions pures (sans état), testables isolément.

| Fichier | Rôle |
| ------- | ---- |
| `main.jsx` | point d'entrée |
| **`App.jsx`** | assemblage : relie les hooks aux composants, aucune logique métier |
| `components/Toolbar.jsx` | choix de la topologie, ▶ Démarrer / ■ Arrêter, boutons des panneaux |
| `components/TopologyCanvas.jsx`, `DeviceNode.jsx` | schéma React Flow (lecture seule) : équipements, câbles, alertes |
| `components/SimulationPanel.jsx`, `DetectionPanel.jsx` | panneaux Simulation (trafic bénin + attaques) et Détection |
| `components/DatasetDialog.jsx`, `ModelDialog.jsx`, `JobProgress.jsx` | datasets ; modèles et rapport ; progression d'une tâche |
| **`hooks/useLab.js`** | état du réseau (topologie en cours, équipements allumés), démarrage et arrêt |
| `hooks/useTraffic.js`, `useDetection.js` | état du trafic et de la détection, rafraîchi toutes les 2 s |
| `hooks/useRecords.js`, `useDatasets.js`, `useModels.js` | listes de datasets et de modèles, et leur création (tâche de fond) |
| `hooks/useAction.js` | `busy` / `error` d'un bouton qui appelle le moteur ; `toggled()` pour les cases à cocher |
| **`services/topologyApi.js`** | **toutes** les requêtes vers le moteur (REST, polling des tâches) |
| **`utils/topology.js`** | lit les `topologies/*/topology.json` ; adresses, cibles d'attaque, destinataires du trafic bénin |
| `config/deviceTypes.js` | couleur, icône et info-bulle de chaque type d'équipement |
| `utils/jobRun.js` | état affiché d'une tâche de fond, mis à jour à chaque interrogation (polling) |
| `utils/format.js`, `styles/app.css` | mise en forme des dates et taux ; styles |

**Moteur** (`backend/app/`, Python) :

| Fichier | Rôle |
| ------- | ---- |
| **`main.py`** | toutes les routes de l'API (liste en tête du fichier) ; crée les objets ci-dessous |
| **`lab.py`** | `LabManager` : `docker compose up` / `down` d'une topologie, retrouve ses conteneurs, lance les conteneurs auxiliaires |
| `traffic_agent.py` | script exécuté **dans** la boîte à outils : l'utilisateur simulé du trafic bénin |
| **`traffic.py`** | `TrafficManager` : agents bénins, catalogue et lancement des attaques |
| `cicflowmeter.py` | découpage d'un pcap en fenêtres de 5 s ; conversion en flux par CICFlowMeter |
| **`datasets.py`** | `DatasetBuilder` : joue un programme, capture, étiquette, sauvegarde |
| **`training.py`** | `Trainer` : features, entraînement, évaluation, sauvegarde du modèle |
| **`detection.py`** | `DetectionManager` : capture continue sur la sonde, classement, vérité terrain |
| `jobs.py` | tâches de fond (thread + état interrogé par l'interface) |
| `store.py` | stockage sur disque des datasets et des modèles (un dossier + `meta.json`) |
| `settings.py` | constantes (dossiers, nom du projet Compose `idslab`, origines autorisées) |

Une erreur prévue est une `HTTPException` de FastAPI : l'interface affiche son message (`detail`).

**Topologies** : `topologies/<id>/docker-compose.yml` (ce que Docker lance) et `topology.json` (ce que
l'interface dessine). **Images** : `docker/server/` (Dockerfile, `services.py`, `vsftpd.conf`) et
`docker/toolbox/Dockerfile` ; les PC, routeurs et sondes utilisent directement l'image `alpine:3.20` (voir §3).

Pour **ajouter un modèle** : le construire dans `Trainer.run` (`training.py`) à la place du random forest ; la détection le prend en charge sans changement, car `model.joblib` porte la liste
ordonnée de ses features.

### Suivre le code : ce que déclenche chaque bouton

Le même schéma revient partout : un **composant** appelle un **hook**, qui appelle `topologyApi.js` ; une
**route** de `main.py` appelle un **gestionnaire** du moteur (`LabManager`, `TrafficManager`…), qui pilote Docker.
Une opération longue devient une **tâche de fond** (`jobs.py`) dont l'interface suit les événements.

**▶ Démarrer le réseau**
1. `Toolbar` → `useLab.start(id)` → `POST /api/lab { topology: id }` ;
2. `main.lab_start` → `LabManager.start` : arrête la topologie précédente (`stop`), puis
   `docker compose -f topologies/<id>/docker-compose.yml up -d --build` ;
3. la réponse donne le nouvel état (`LabManager.status`) : la pastille verte s'allume sur chaque équipement.

**▶ Démarrer (trafic bénin, panneau ⚡ Simulation)**
1. `SimulationPanel.startBenign` calcule pour chaque PC coché ses destinataires (`benignTargets` : toutes les
   autres machines, `server: true` pour un serveur) ;
2. `POST /api/lab/traffic/benign` → `TrafficManager.start_benign` ;
3. le moteur lance un conteneur `toolbox` dans la pile réseau du PC, avec `python3 -c <traffic_agent.py>
   <configuration JSON>` ;
4. dans le conteneur, `traffic_agent.main` → `build_actions` (sessions possibles) → `worker` (boucle : choisit
   une session au hasard selon les poids, la joue, attend).

**⚡ Lancer l'attaque** (panneau ⚡ Simulation)
1. `POST /api/lab/scenarios` → `TrafficManager.run_scenario` vérifie la cible, puis `_pause_benign` arrête
   l'agent bénin de la source ;
2. un conteneur `toolbox` lance la commande `nmap` ou `hydra` ; ses labels Docker (source, cible, attaque)
   servent de **vérité terrain** à la détection ;
3. un thread (`_resume_after`) attend la fin de l'attaque et relance l'agent bénin.

Une fois le scénario terminé, `_scenario_info` renvoie un champ `result` (`{ok, text}` ou `null`), calculé par
`attack_result(attack, logs)` qui lit la sortie de l'outil : mot de passe trouvé (hydra et force brute furtive),
ports ouverts (scans nmap) ou machines actives (balayage). C'est le **résultat de l'attaque** (a-t-elle abouti ?),
**indépendant de la détection** : une évasion réussie trouve le mot de passe tout en restant classée bénigne.

**▶ Générer le dataset**
1. `DatasetDialog.submit` → `POST /api/datasets` → `DatasetBuilder.prepare` vérifie le programme ;
2. tâche de fond `DatasetBuilder.run` → `_generate` pour la base puis chaque variante (`make_variant`) :
   `tcpdump` sur la sonde, agents bénins, chaque attaque jouée par `_play` (fenêtre de temps enregistrée) ;
3. le pcap est découpé et converti (`windowed_flows_csv`), étiqueté (`label_dataset_csv`) et sauvegardé
   (`store.py`).

**▶ Entraîner** : `POST /api/models` → `Trainer.prepare` puis, en tâche de fond, `Trainer.run` :
`load_frames` (CSV) → `feature_matrix` / `drop_constant` (features) → `RandomForestClassifier.fit` →
`evaluate` et `by_attack` (métriques) → `model.joblib` + `meta.json`.

**▶ Démarrer (détection)**
1. `POST /api/lab/detection` → `DetectionManager.start` : `tcpdump -G 5` dans la sonde (un fichier par
   fenêtre de 5 s) et un conteneur CICFlowMeter permanent ;
2. un thread exécute `_tick` chaque seconde : chaque fenêtre terminée → flux → `_classify` ;
3. `_classify` : le modèle prédit, `_known_attacks` reconstitue la vérité terrain à partir des conteneurs
   d'attaque, `outcome_of` décide « alerte », « manquée » ou « bénin » ;
4. `useDetection` interroge `GET /api/lab/detection` toutes les 2 s.

## 3. Le réseau

On ne dessine plus la topologie : on choisit l'une des **trois topologies prêtes**, chacune avec un serveur et
une sonde IDS. Chacune est un dossier de `code/topologies/` :

| Topologie | Réseaux | Sonde IDS sur |
| --------- | ------- | ------------- |
| `1-petit-lan` | un switch 10.0.1.0/24 : Serveur, PC-1 à 3 | le switch (tout le trafic) — topologie des évasions |
| `2-lan-dmz` | LAN 10.0.10.0/24 (PC) + DMZ 10.0.20.0/24 (2 serveurs), un routeur | la DMZ |
| `3-trois-reseaux` | LAN-1 (PC-1, PC-2), transit 10.0.2.0/24, LAN-3 (PC-3, Serveur), deux routeurs | le transit |

| Dans le `docker-compose.yml` | Équipement |
| ---------------------------- | ---------- |
| `networks:` (bridge, sous-réseau fixé) | un switch |
| service `alpine:3.20` | un PC, un routeur (`net.ipv4.ip_forward: 1`) ou la sonde IDS |
| service `idslab/server` (construit depuis `docker/server/`) | un serveur (HTTP, SSH, FTP) |
| service `hub-mode` | passe le switch surveillé en mode hub (voir plus bas) et construit l'image `toolbox` |

Tout est écrit à la main dans le fichier : adresses (`ipv4_address`), passerelles et routes statiques (dans la
`command` de chaque service : `ip route replace default via …`), nom affiché (`hostname`). Comme ces fichiers
ne changent pas, il n'y a rien à vérifier au démarrage : s'ils ont marché une fois, ils marchent toujours. Le
`topology.json` voisin décrit le même réseau pour le dessin (mêmes identifiants, mêmes adresses).

Docker prend l'adresse `.254` de chaque réseau pour l'hôte ; la route par défaut qu'il ajoute vers lui est
retirée (`ip route del default`) ou remplacée par le routeur : le réseau est isolé de l'hôte et d'Internet.

**Démarrer / arrêter** (`lab.py`) : `docker compose -f topologies/<id>/docker-compose.yml up -d --build`, et
`docker compose -p idslab down`. Toutes les topologies portent le même nom de projet (`name: idslab`) : une
seule tourne à la fois. Les conteneurs auxiliaires (trafic, attaques, captures, CICFlowMeter) sont lancés à la
demande par le moteur avec le SDK Docker et portent le label `idslab.managed=true` ; l'arrêt les supprime aussi.

**Port miroir** : un bridge Linux apprend les adresses MAC et n'envoie à chaque port que ce qui lui est
destiné. Avec `ageing_time = 0`, il n'apprend plus et diffuse tout, comme un hub : la sonde reçoit une copie
de tout le segment. C'est ce que fait le service `hub-mode` (conteneur `privileged`, `network_mode: host`, qui
écrit dans `/sys/class/net/br-switch-N/bridge/ageing_time`). **La sonde ne voit que ce switch** : une attaque
qui ne le traverse pas lui est invisible.

**Ajouter une topologie** : copier un dossier de `topologies/`, modifier le `docker-compose.yml` et le
`topology.json` ; elle apparaît dans la liste de l'interface.

---

## 4. Les services

Chaque serveur lance trois vrais services (`docker/server/services.py`). Une simple bannière ne produirait pas
les échanges d'une vraie session : le modèle apprendrait des artefacts.

| Service | Port | Implémentation | Contenu |
| ------- | ---- | -------------- | ------- |
| HTTP | 80 | serveur HTTP/1.1 Python, connexions persistantes (annoncé `nginx/1.26.1`) | 20 pages de 6 à 50 Ko, images, téléchargements de 0,45 à 9 Mo, API JSON, `POST /login` |
| SSH | 22 | OpenSSH avec SFTP | fichiers de `labuser` |
| FTP | 21 | vsftpd (`vsftpd.conf`), passif sur 40000-40100, dépôt autorisé | mêmes fichiers, `upload/` |

Compte unique, créé dans le Dockerfile, volontairement faible pour la force brute : **`labuser` / `password123`**.

Test rapide depuis la boîte à outils, placée dans la pile réseau de PC-1 (topologie 1) :

```bash
docker run --rm -it --network container:idslab-pc-1-1 idslab/toolbox sh
nmap -p 21,22,80 10.0.1.10
sshpass -p password123 ssh -o StrictHostKeyChecking=no labuser@10.0.1.10 ls
```

---

## 5. Le trafic bénin

Un **agent** (`traffic_agent.py`) tourne dans un conteneur qui partage la pile réseau de l'émetteur : pour
la sonde, c'est bien le PC qui parle. Chaque action est une session complète avec un vrai client. Le moteur
lui fournit ses destinataires (IP, et si c'est un serveur) et le compte de démonstration.

| Type | Session |
| ---- | ------- |
| Web | navigation (l'accueil puis 1 à 3 pages en suivant leurs liens, avec leurs ressources sur la même connexion, 10 % de téléchargements) ; API (12 %) ; formulaire de connexion (8 %) |
| SSH | commandes (70 %) ou `scp` (30 %) |
| FTP | listing, 1 à 3 transferts |
| Ping | 1 à 4 paquets, tailles variables, vers toutes les machines |

Poids relatifs : HTTP 5, SSH 2, FTP 1,5, Ping 1,5.

En SSH, FTP et sur le formulaire web, une connexion sur 20 commence par **une** erreur de mot de passe, suivie
du bon : une erreur isolée n'est pas une force brute, et le modèle doit le savoir.

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
| **Force brute FTP (furtive, évasion)** | `ftplib` + commandes de remplissage, cadence humaine | ftp-patator-stealth |

La dernière ligne est une **attaque d'évasion par mimétisme** (Okada) : au lieu de hydra, elle utilise le même
client FTP que le trafic bénin (`ftplib`) et **étoffe chaque essai** avec des commandes FTP autorisées avant
login (FEAT, SYST, STAT, NOOP…) pour donner au flux la forme d'une **session bénigne** (nombre de paquets,
octets, drapeaux PSH, temps inter-paquets). Un login raté « nu » ne suffit pas : c'est un flux pauvre que le
modèle reconnaît comme attaque quel que soit le client. Résultat mesuré et explication « pour étudiant » dans
[`rapports/rapport_evasion.md`](rapports/rapport_evasion.md).

Quatre vitesses « normales » : nmap `-T2` à `-T5`, hydra 1 à 16 connexions parallèles. Les attaques tournent
dans un conteneur qui partage la pile réseau de la source. Pour obtenir des flux étiquetés, on passe par les
datasets.

Une cinquième vitesse, **« Évasion (furtif, temporisé) »**, n'est pas une simple vitesse lente : c'est une
**attaque d'évasion par temporisation** de l'état de l'art (Han/TrafficManipulator, Sharon/TANTRA, voir
[`état de l'art`](etat_de_l_art_attaques_ml_nids.pdf)). nmap y ajoute `--scan-delay 250ms --max-rate 8`, hydra
passe en `-t 1 -W 1` : les paquets sont fortement étalés, de sorte que le rythme du trafic malveillant se
rapproche du bénin. L'hypothèse est que le modèle n'a appris que des attaques **denses** (les quatre vitesses
ci-dessus) ; en étalant les paquets, les features de temps (`Fwd IAT Min`, `Flow IAT Min`) et de volume
sortent de la zone « attaque » apprise et des flux peuvent être classés BENIGN.

**Usage** : ne pas l'inclure dans un dataset d'entraînement (sinon le modèle apprend aussi le rythme lent).
On entraîne sur les vitesses normales, puis on lance l'attaque en vitesse **Évasion** depuis **⚡ Simulation**
et on compare, dans le bilan de détection, le **rappel** (part des flux d'attaque détectés) avant et après, le
tout contre le **coût** payé (l'attaque dure bien plus longtemps). C'est l'expérience « avant/après »
recommandée par l'état de l'art pour mesurer une évasion.

**Résultat mesuré (scan de ports, modèle `20261110-100030`, topologie « Petit LAN »)** : vitesse Rapide
→ 200 flux, **200 détectés (rappel 100 %)**, en 0,1 s ; vitesse Évasion → 200 flux, **200 détectés
(rappel 100 %)**, en 50,7 s. **La temporisation seule n'évade pas ce modèle.** C'est cohérent avec l'état
de l'art : TrafficManipulator et TANTRA visent KitNET, un détecteur **fenêtré au niveau de l'hôte**, alors
qu'ici le random forest décide **par flux** (features CICFlowMeter bidirectionnelles). Chaque sonde de scan
reste un mini-flux de 2–3 paquets, de même forme quel que soit l'espacement : le modèle le reconnaît avec
une confiance de 1,0. Autrement dit, la robustesse est un **couple modèle–extracteur** (enseignement de la
§ « Enseignements » de l'état de l'art), pas une propriété du modèle seul. Pour évader un détecteur par flux,
il faut modifier la **forme des flux eux-mêmes** (compléter les connexions, répartir une force brute sur des
sessions isolées à la Okada, ajouter du remplissage) — c'est la piste de l'évasion ciblée par l'importance
des features, à implémenter ensuite.

Une attaque lancée à la main (par exemple avec `docker run … idslab/toolbox nmap …`) n'est pas connue du
moteur : elle ne figure pas dans la vérité terrain. Pendant la génération d'un dataset, elle serait étiquetée BENIGN.

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

Une attaque dont l'outil échoue (service absent sur la cible, par exemple) déclenche un avertissement pendant la
génération : ses flux ne représentent pas l'attaque annoncée.

**Sortie** : `backend/data/datasets/<id>/` avec `flows.csv`, `capture.pcap`, `meta.json` (paramètres,
fenêtres, décompte), téléchargeables depuis l'interface.

---

## 8. L'entraînement

**🧠 IDS** entraîne un **random forest** binaire (BENIGN / ATTACK), 100 arbres par défaut (`training.py`).

- **Features retirées** : `Flow ID`, `Src IP`, `Src Port`, `Dst IP`, `Timestamp`, et `Dst Port` par défaut.
  Sinon le modèle apprendrait « PC-1 attaque » ou « ce port = attaque » plutôt qu'un comportement.
- **Nettoyage** : `inf` et `NaN` remplacés par 0, colonnes constantes écartées.
- **Poids équilibrés par étiquette d'origine** (bénin, port-scan, ssh-patator…) : un scan produit des milliers
  de flux, une force brute quelques dizaines ; sans cela, le scan décide seul de ce qu'est une attaque.
- **Test** : toujours sur des datasets séparés (en général les variantes du dataset d'entraînement). Pas de
  découpage aléatoire : des flux quasi identiques se retrouveraient des deux côtés et gonfleraient les scores.

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
4. tout flux classé `ATTACK` est affiché comme **attaque détectée**, que le moteur connaisse l'attaque ou non ;
5. la vérité terrain (attaques lancées depuis ⚡ Simulation ou 🗂 Datasets : source, cible, début, fin) sert seulement à
   repérer les flux d'attaque que le modèle a **manqués**, et à donner le score par attaque.

L'agent bénin de la source est suspendu pendant son attaque, comme dans un dataset, puis relancé à la fin : sans
cela, ses sessions seraient comptées comme des attaques manquées.

Le modèle ne reconnaît que ce qu'il a appris : le panneau signale une attaque absente de l'entraînement.

Une attaque lancée en dehors de l'interface (par exemple `docker exec`) apparaît donc normalement si elle est repérée, mais ne peut pas être comptée comme
manquée. Le taux de fausses alertes se mesure dans le rapport d'entraînement, sur des données étiquetées.

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
| Machines | conteneurs Docker, topologies en Docker Compose | VM, Mininet, Kubernetes, topologie dessinée | dizaines de machines en quelques secondes ; Compose est l'outil standard (vu en cours), et des topologies figées n'ont rien à vérifier |
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
| `test_cicflowmeter.py` | découpage d'un pcap en fenêtres, remplissage de la colonne Label |
| `test_datasets.py` | programmes, variantes, étiquetage par fenêtres |
| `test_training.py` | features, entraînement, métriques |
| `test_detection.py` | fenêtres, verdicts, vérité terrain |
| `test_benign.py` | sessions possibles de l'agent bénin |
| `test_settings.py` | origines autorisées ; chaque topologie a son `docker-compose.yml` et son `topology.json` |
| `test_traffic_pause.py` | pause de l'agent bénin de la source pendant une attaque |

---

## 13. Dépannage

| Symptôme | Solution |
| -------- | -------- |
| « Moteur de simulation hors ligne » | moteur non lancé ou Docker arrêté (`docker info`) |
| `permission denied … docker.sock` | `sudo usermod -aG docker $USER`, puis se reconnecter |
| `uvicorn: command not found` | activer l'environnement : `source .venv/bin/activate` |
| `address already in use` | un moteur tourne déjà sur le port 8000 |
| « le moteur a refusé la connexion » | moteur lancé avant une mise à jour, sans `--reload` : le relancer |
| Premier démarrage très long | téléchargement et construction des images, une seule fois |
| `docker compose a échoué : … Pool overlaps` | un autre réseau Docker utilise déjà ce sous-réseau : le supprimer (`docker network ls`) |
| Vite refuse de démarrer | Node trop ancien : `cd code && nvm install && nvm use` |
| Import introuvable au build, `@rolldown/binding-…` | `node_modules` périmé : `npm ci` |
| Un outil ajouté à un Dockerfile est absent | les images sont reconstruites au démarrage : ■ Arrêter puis ▶ Démarrer |
| Un service ne répond pas | journal du serveur : `docker logs idslab-server-1-1` |
| Aucun flux d'attaque dans un dataset | la sonde ne surveille pas le switch traversé par l'attaque |

Nettoyage manuel complet, moteur arrêté :

```bash
docker rm -f $(docker ps -aq --filter label=idslab.managed=true)
docker compose -p idslab down
docker image rm $(docker image ls -q 'idslab/*')
```

---

## 14. Limites connues

- **Trafic bénin synthétique** : vraies sessions, mais un compte, un site, pas de profils d'utilisateurs.
- **Timing** : tout tourne sur un hôte, latence quasi nulle, ce qui change les features temporelles.
- **Couverture d'attaque** : reconnaissance et force brute seulement.
- **Attaques connues seulement** : un modèle supervisé ne reconnaît que les familles apprises.
- **Un modèle par topologie** : un modèle ne vaut que pour le réseau de ses datasets ; ne pas mélanger des
  datasets de topologies différentes.
- **Flux à cheval** : un flux qui chevauche deux fenêtres est vu en deux morceaux.
- **La sonde ne voit que son switch.**
- **Force brute** : les protections d'OpenSSH (`PerSourcePenalties`, `MaxStartups`) sont désactivées dans le lab, car
  elles coupaient l'attaque. Un flux de force brute SSH ressemble à une vraie session.
- **Fausses alertes** : environ 5 % en direct lors du dernier test, davantage si des émetteurs n'étaient pas
  présents à l'entraînement. Voir [`rapports/rapport_ids.md`](rapports/rapport_ids.md).

---

## 15. API et formats

Toutes les routes sont décrites en tête de [`backend/app/main.py`](../backend/app/main.py). Les deux tâches
longues (dataset, entraînement) se suivent par la même route, `GET /api/jobs/{id}`, que l'interface redemande
toutes les secondes (polling), et s'annulent par `POST /api/jobs/{id}/cancel`. Une erreur prévue est une
`HTTPException` : réponse `{ "detail": "message" }` avec son code HTTP.

**Topologie dessinée** (`topologies/<id>/topology.json`) : les identifiants et adresses sont ceux du
`docker-compose.yml`.

```json
{ "name": "Petit LAN", "description": "…",
  "nodes": [{ "id": "pc-1", "type": "pc", "name": "PC-1", "x": 300, "y": -140 },
            { "id": "switch-1", "type": "switch", "name": "Switch-1", "subnet": "10.0.1.0/24", "x": 0, "y": 0 }],
  "links": [{ "node": "pc-1", "switch": "switch-1", "ip": "10.0.1.11" }] }
```

Types : `pc`, `server`, `router`, `ids`, `switch`.

**Dataset sauvegardé** : `backend/data/datasets/<id>/` avec `flows.csv` (une ligne par flux, colonnes CICFlowMeter,
colonne `Label`), `capture.pcap` et `meta.json` (programme, fenêtres des attaques, décompte des étiquettes).

**Modèle sauvegardé** : `backend/data/models/<id>/model.joblib` (le modèle, la liste ordonnée de ses features
et `excludePort` : tout ce que la détection doit savoir) et `meta.json` (paramètres et métriques du rapport).

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
