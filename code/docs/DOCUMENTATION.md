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
│ éditeur · Trafic, Scénarios, Datasets, IDS, Détection · terminal,    │
│ capture                                                              │
└─────────────────────────────┬────────────────────────────────────────┘
                              │ REST (+ polling), WebSocket
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

L'interface ne parle jamais de Docker : le moteur traduit chaque action. REST sert aux actions ; pour les
tâches longues (déploiement, dataset, entraînement), l'interface redemande leur état toutes les secondes (polling) ; les WebSockets servent aux terminaux
et captures. Pas de base de données : tout est fichier dans `backend/data/`, ignoré par git.

### Carte du code

Chemins relatifs à `code/`. Les fichiers en gras sont ceux à lire en premier.

**Interface** (`src/`, React) : les *composants* affichent, les *hooks* gardent l'état et appellent le moteur,
les *utils* sont des fonctions pures (sans état), testables isolément.

| Fichier | Rôle |
| ------- | ---- |
| `main.jsx`, `App.jsx` | point d'entrée ; `ReactFlowProvider` englobe toute l'application |
| **`components/TopologyEditor.jsx`** | assemblage : relie les hooks aux composants, aucune logique métier |
| `components/Toolbar.jsx`, `ExamplesMenu.jsx`, `Palette.jsx` | barre d'outils, menu des exemples, palette d'équipements |
| `components/TopologyCanvas.jsx`, `DeviceNode.jsx`, `CableEdge.jsx` | schéma React Flow : équipements et câbles |
| `components/PropertiesPanel.jsx`, `properties/*.jsx` | panneau de droite : nom, interfaces, passerelle, services, routes |
| `components/DeployDialog.jsx` | bilan des contrôles puis progression du déploiement |
| `components/TrafficPanel.jsx`, `ScenarioPanel.jsx`, `DetectionPanel.jsx` | panneaux Trafic bénin, Scénarios, Détection |
| `components/DatasetDialog.jsx`, `ModelDialog.jsx`, `JobProgress.jsx` | datasets ; modèles et rapport ; progression d'une tâche |
| `components/Dock.jsx`, `TerminalView.jsx`, `CaptureView.jsx` | onglets du bas : terminal (xterm.js), capture façon Wireshark |
| **`hooks/useTopology.js`** | état du schéma (nœuds, câbles) et toutes les actions d'édition ; lance l'IPAM |
| `hooks/useCableTool.js`, `useDock.js` | outil câble ; onglets du bas |
| **`hooks/useDeployment.js`** | état du réseau (allumé, arrêté) et déploiement |
| `hooks/useTraffic.js`, `useDetection.js` | état du trafic et de la détection, rafraîchi toutes les 2 s |
| `hooks/useRecords.js`, `useDatasets.js`, `useModels.js` | listes de datasets et de modèles, et leur création (tâche de fond) |
| `hooks/useAction.js` | `busy` / `error` d'un bouton qui appelle le moteur ; `toggled()` pour les cases à cocher |
| **`services/topologyApi.js`** | **toutes** les requêtes vers le moteur (REST, polling des tâches, URL des WebSockets) |
| `config/deviceTypes.js`, `exampleTopologies.js` | catalogue des types d'équipements et des services ; exemples |
| `utils/serializeTopology.js`, `deserializeTopology.js` | schéma React Flow ↔ JSON envoyé au moteur (voir §15) |
| `utils/ipv4.js`, `ipam.js`, `validators.js` | calcul d'adresses, adressage automatique, contrôles de cohérence |
| `utils/topologyQueries.js`, `trafficTargets.js` | lectures du schéma : câbles d'un équipement, cibles et types de trafic possibles |
| `utils/jobRun.js` | état affiché d'une tâche de fond, mis à jour à chaque événement reçu |
| `utils/pcap.js`, `packetDissector.js`, `displayFilter.js` | capture : paquets reçus, décodage couche par couche, filtres |
| `utils/format.js`, `styles/app.css` | mise en forme des dates et taux ; styles |

**Moteur** (`backend/app/`, Python) :

| Fichier | Rôle |
| ------- | ---- |
| **`main.py`** | toutes les routes de l'API (liste en tête du fichier) ; crée les objets ci-dessous |
| `models.py` | forme du JSON de topologie (pydantic) ; type d'un service ; nom DNS d'un équipement |
| **`planner.py`** | topologie → plan : traduit switches, équipements, câbles et routes (les vérifications sont faites par l'interface, `validators.js`) |
| **`deployer.py`** | `LabManager` : exécute le plan avec Docker, construit les images, lance les conteneurs auxiliaires |
| `service_listener.py` | script exécuté **dans** chaque serveur : démarre les vrais services |
| `traffic_agent.py` | script exécuté **dans** la boîte à outils : l'utilisateur simulé du trafic bénin |
| **`traffic.py`** | `TrafficManager` : agents bénins, catalogue et lancement des attaques |
| `cicflowmeter.py` | découpage d'un pcap en fenêtres de 5 s ; conversion en flux par CICFlowMeter |
| **`datasets.py`** | `DatasetBuilder` : joue un programme, capture, étiquette, sauvegarde |
| **`training.py`** | `Trainer` : features, entraînement, évaluation, sauvegarde du modèle |
| **`detection.py`** | `DetectionManager` : capture continue sur la sonde, classement, vérité terrain |
| `terminal.py`, `capture.py`, `sessions.py` | sessions WebSocket : terminal, capture, fermeture à l'arrêt |
| `jobs.py` | tâches de fond (thread + suite d'événements) |
| `store.py` | stockage sur disque des datasets et des modèles (un dossier + `meta.json`) |
| `errors.py`, `settings.py` | `UserError` (message affiché à l'utilisateur) ; constantes (dossiers, préfixe `idslab`) |

**Images** : `docker/<rôle>/Dockerfile` pour `pc`, `server`, `router`, `ids` et `toolbox` (voir §3).

Pour **ajouter un modèle** : une entrée dans `MODELS` et sa construction dans `Trainer.run`
(`training.py`) ; la détection le prend en charge sans changement, car `model.joblib` porte la liste
ordonnée de ses features.

### Suivre le code : ce que déclenche chaque bouton

Le même schéma revient partout : un **composant** appelle un **hook**, qui appelle `topologyApi.js` ; une
**route** de `main.py` appelle un **gestionnaire** du moteur (`LabManager`, `TrafficManager`…), qui pilote Docker.
Une opération longue devient une **tâche de fond** (`jobs.py`) dont l'interface suit les événements.

**✔ Valider la topologie** (déploiement)
1. `TopologyEditor.handleValidate` : `serializeTopology` produit le JSON, `validateTopology` liste les problèmes ;
2. `useDeployment.validate` : sans problème, `startDeployment` → `POST /api/deployments` ;
3. `main.create_deployment` : `planner.build_plan` traduit la topologie en plan (déjà vérifiée par l'interface), puis
   `jobs.start("deploy", …)` lance `LabManager.deploy` dans un thread ;
4. `deploy` : construit les images, crée un réseau Docker par switch (`_create_network`), un conteneur par
   équipement (`_create_device`), configure routes et interfaces (`_configure_device`), passe le switch surveillé
   en hub (`_enable_hub_mode`) ; chaque étape publie un événement `progress` ;
5. l'interface redemande `GET /api/jobs/{id}` toutes les secondes (`followJob`) ; `applyJobState` met à jour `DeployDialog`.

**▶ Démarrer (trafic bénin)**
1. `TrafficPanel.start` calcule pour chaque émetteur ses cibles (`benignTargetsForDests` : IP et services) ;
2. `POST /api/lab/traffic/benign` → `TrafficManager.start_benign` ;
3. le moteur lance un conteneur `toolbox` dans la pile réseau du PC, avec `python3 -c <traffic_agent.py>
   <configuration JSON>` ;
4. dans le conteneur, `traffic_agent.main` → `build_actions` (sessions possibles) → `worker` (boucle : choisit
   une session au hasard selon les poids, la joue, attend).

**⚡ Lancer le scénario** (attaque)
1. `POST /api/lab/scenarios` → `TrafficManager.run_scenario` vérifie la cible, puis `_pause_benign` arrête
   l'agent bénin de la source ;
2. un conteneur `toolbox` lance la commande `nmap` ou `hydra` ; ses labels Docker (source, cible, attaque)
   servent de **vérité terrain** à la détection ;
3. un thread (`_resume_after`) attend la fin de l'attaque et relance l'agent bénin.

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

**Terminal et capture** : `useDock.open` ajoute un onglet ; `TerminalView` (ou `CaptureView`) ouvre une
WebSocket ; `TerminalSession` relaie un shell (`exec` Docker avec TTY), `CaptureSession` relaie la sortie de
`tcpdump` paquet par paquet, que le navigateur décode (`packetDissector.js`).

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

**Images** : chaque rôle a son Dockerfile dans `code/docker/` (`pc`, `server`, `router`, `ids`, et `toolbox`, la
boîte à outils lancée « dans » un équipement pour le trafic bénin, les attaques et les captures). Le moteur les
construit à chaque déploiement sous le nom `idslab/<rôle>` ; le cache de Docker rend cette étape instantanée tant
qu'aucun Dockerfile n'a changé. Pour ajouter un outil à un équipement, on modifie son Dockerfile.

**Déploiement** : `planner.py` produit un plan, `deployer.py` l'exécute et envoie sa progression.
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

Le type d'un service est son **nom** (`http`, `ssh`…, sans tenir compte des majuscules) : la règle est dans
`models.Service.kind`, et le moteur transmet ce type aux serveurs et aux agents. Si un démon
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
la sonde, c'est bien le PC qui parle. Chaque action est une session complète avec un vrai client. Le moteur
lui fournit tout ce qu'il doit savoir (cibles et type de leurs services, noms DNS, compte de démonstration).

| Type | Session |
| ---- | ------- |
| Web | navigation (l'accueil puis 1 à 3 pages en suivant leurs liens, avec leurs ressources sur la même connexion, 10 % de téléchargements) ; API (12 %) ; formulaire de connexion (8 %) |
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
| **Force brute FTP (furtive, évasion)** | `ftplib` (client bénin), cadence humaine | ftp-patator-stealth |

La dernière ligne est une **attaque d'évasion par mimétisme** (Okada) : au lieu de hydra, elle utilise le même
client FTP que le trafic bénin pour que ses flux ressemblent à des logins ratés légitimes. Résultat mesuré et
explication « pour étudiant » dans [`rapports/rapport_evasion.md`](rapports/rapport_evasion.md).

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
On entraîne sur les vitesses normales, puis on lance l'attaque en vitesse **Évasion** depuis **⚡ Scénarios**
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
4. tout flux classé `ATTACK` est affiché comme **attaque détectée**, que le moteur connaisse l'attaque ou non ;
5. la vérité terrain (attaques lancées depuis ⚡ Scénarios ou 🗂 Datasets : source, cible, début, fin) sert seulement à
   repérer les flux d'attaque que le modèle a **manqués**, et à donner le score par attaque.

L'agent bénin de la source est suspendu pendant son attaque, comme dans un dataset, puis relancé à la fin : sans
cela, ses sessions seraient comptées comme des attaques manquées.

Le modèle ne reconnaît que ce qu'il a appris : le panneau signale une attaque absente de l'entraînement.

Une attaque tapée dans un terminal apparaît donc normalement si elle est repérée, mais ne peut pas être comptée comme
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
| `test_planner.py`, `test_examples.py` | topologie → plan ; pour chaque exemple, toute machine joint toute autre |
| `test_capture.py` | découpage du flux de capture |
| `test_cicflowmeter.py` | découpage d'un pcap en fenêtres, remplissage de la colonne Label |
| `test_datasets.py` | programmes, variantes, étiquetage par fenêtres |
| `test_training.py` | features, découpages, entraînement, métriques |
| `test_detection.py` | fenêtres, verdicts, vérité terrain |
| `test_benign.py` | type d'un service, nom DNS, sessions de l'agent, requête DNS |
| `test_settings.py` | origines autorisées ; chaque rôle a son Dockerfile |

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
| Un outil ajouté à un Dockerfile est absent | les images sont reconstruites au déploiement : ■ Arrêter puis ✔ Valider |
| `curl: (60)` en HTTPS | certificat auto-signé : `-k` |
| Service « simulé » dans le journal du serveur | son nom n'est pas l'un des 8 services réels, ou son démarrage a échoué |
| Aucun flux d'attaque dans un dataset | la sonde ne surveille pas le switch traversé par l'attaque |

Nettoyage manuel complet, moteur arrêté :

```bash
docker rm -f $(docker ps -aq --filter label=idslab.managed=true)
docker network rm $(docker network ls -q --filter label=idslab.managed=true)
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

Toutes les routes sont décrites en tête de [`backend/app/main.py`](../backend/app/main.py). Les trois tâches
longues (déploiement, dataset, entraînement) se suivent par la même route, `GET /api/jobs/{id}`, que
l'interface redemande toutes les secondes (polling), et s'annulent par `POST /api/jobs/{id}/cancel`. Toute erreur destinée à l'utilisateur est
une `UserError` (`errors.py`) : réponse `{ "errors": [message…] }` avec son code HTTP (404, 409 ou 503).

**Topologie (JSON, version 2)** : l'interface envoie `{ version, nodes, networks, links }`. Exemples complets
dans `examples/topologies/` ; ajouter un fichier ajoute un exemple au menu, et `test_examples.py` le vérifie.

```json
{ "version": 2,
  "nodes": [{ "id": "pc-1", "type": "pc", "name": "PC-1", "position": { "x": 120, "y": 80 }, "config": { "gateway": "10.0.1.1" } }],
  "networks": [{ "id": "switch-1", "name": "Switch-1", "position": { "x": 120, "y": 240 }, "subnet": "10.0.1.0/24" }],
  "links": [{ "id": "link-1", "node": "pc-1", "network": "switch-1", "interface": "eth0", "port": "Fa0/1", "ip": "10.0.1.10", "mask": "255.255.255.0" }] }
```

Types de nœuds : `pc`, `server` (`config.services`), `router` (`config.routes`), `ids` (`config.monitoredSegment`).

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
