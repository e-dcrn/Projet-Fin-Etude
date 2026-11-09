# Journal des décisions du projet

Du sujet (septembre 2026) à la réunion du 9 novembre 2026 et au nettoyage qui l'a suivie.

**Sources** : `Sujet.pdf`, slides des 6 et 27 octobre et du 9 novembre, état de l'art, 34 commits du dépôt,
ancienne documentation (`GUIDE.md`, `SERVICES.md`, `ARCHITECTURE.md`, supprimés le 9 novembre et disponibles
dans l'historique git), code. Les comptes rendus oraux des réunions ne sont pas dans le dépôt.

**Lecture des justifications**
- *Documentée* : écrite dans une source du dépôt.
- *Reconstituée* : déduite du code ou de la chronologie ; aucune source ne l'énonce. À corriger si elle est fausse.

**État** : ✅ valable · 🔁 remplacée · ❌ retirée · ⏳ ouverte

---

## 1. Cadrage (septembre – 6 octobre)

| # | Date | Décision | Justification | Source | État |
| - | ---- | -------- | ------------- | ------ | ---- |
| 1 | 16 sept. | Livrables imposés : état de l'art, banc d'essai d'attaques, environnement réseau, dépôt documenté. | Imposé par le sujet de Grégory Blanc. *Documentée.* | `Sujet.pdf` | ✅ |
| 2 | 6 oct. | Comprendre le sujet comme un **démonstrateur pédagogique** en trois parties : environnement réseau façon Packet Tracer, choix du ML-NIDS, choix de l'attaque. | Rendre visibles les effets d'une attaque. *Documentée.* | slides 6 oct., diapo 2 | ✅ |
| 3 | 6 oct. | Prévoir une **vue pour comprendre l'attaque** (en direct ou avant/après). | Objectif pédagogique. *Documentée.* Mise en œuvre actuelle : bilan de détection, l'animation a été retirée (n° 58). | slides 6 oct. | ⏳ |
| 4 | 6 oct. | Suivre le projet sous **JIRA**. | Cadre des projets de fin d'études. *Reconstituée* à partir de la diapo JIRA et du PDF d'introduction. | slides 6 oct., PDF JIRA | ✅ |
| 5 | 6 oct. | **Corpus initial de 8 articles**, classés par type d'attaque (6 évasions, 2 empoisonnements). | Couvrir des mécanismes et des modèles variés. *Documentée.* | slides 6 oct. | 🔁 n° 14 |
| 6 | 6 oct. | Présenter les couples modèle–attaque comme de simples **pistes**, sans choix définitif. | Faisabilité non vérifiée. *Documentée.* | slides 6 oct. | ✅ |
| 7 | 6 oct. | Jalons : état de l'art d'abord, puis clarifier le rôle de ConCap, en parallèle d'une maquette logicielle. | Ordre de dépendance. *Documentée.* | slides 6 oct. | ✅ |
| 8 | 6 oct. | Exigence à vérifier pour toute attaque : **tromper le détecteur tout en gardant l'effet réseau**. | C'est la différence entre une attaque réaliste et une attaque sur un CSV. *Documentée.* | slides 6 oct. | ✅ |

## 2. Prototype et état de l'art (10 – 27 octobre)

| # | Date | Décision | Justification | Source | État |
| - | ---- | -------- | ------------- | ------ | ---- |
| 9 | 10 oct. | Interface web sur mesure **React + React Flow + Vite**, plutôt que Packet Tracer ou GNS3. | Packet Tracer simule les paquets sans exécuter de vrais logiciels ; l'interface doit s'intégrer au pipeline ML. *Documentée.* | `4d3ceb5`, GUIDE §8 | ✅ |
| 10 | 10 oct. | Moteur **Python + FastAPI + SDK Docker**, plutôt que Node.js. | Même langage que scikit-learn et pandas. *Documentée.* | `facf9b7`, GUIDE §8 | ✅ |
| 11 | 10 oct. | **Conteneurs Docker** plutôt que VM, Mininet ou Kubernetes. | Dizaines de machines en quelques secondes sur un portable. *Documentée.* | GUIDE §8 | ✅ |
| 12 | 10 oct. | Modèle réseau : **un switch est un réseau**, un câble relie toujours un équipement à un switch ; adressage automatique (IPAM) ; validations côté interface **et** moteur. | Correspondance directe avec les réseaux Docker ; pas de saisie d'adresses. *Reconstituée* (le modèle est documenté, le pourquoi non). | `facf9b7`, ancien `code/README.md` | ✅ |
| 13 | 10 oct. | **Sonde passive** sur un switch passé en hub (`ageing_time = 0`), plutôt qu'Open vSwitch ou une sonde en coupure. | Inclus dans Docker ; une sonde en coupure couperait le réseau si elle tombe. *Documentée.* | `deployer.py`, GUIDE §8 | ✅ |
| 14 | 12–27 oct. | Corpus porté à **11 articles** : ajout d'Alhussien, PCAP-Backdoor et Ma. | L'empoisonnement ne couvrait ni l'attaquant externe, ni les portes dérobées, ni les attaques sur paquets. *Documentée.* | slides 27 oct. | ✅ |
| 15 | 10 oct. | Terminal sur chaque PC et serveur, capture type Wireshark sur chaque lien, filtres, export pcap. | Observer le réseau réel. *Reconstituée.* Conservés le 9 nov. (n° 63). | slides 27 oct. | ✅ |
| 16 | 10 oct. | Topologies d'exemple livrées avec le projet, testées automatiquement. | Démarrer vite, garantir la connectivité. *Reconstituée.* | `9d2276d`, `test_examples.py` | ✅ |
| 17 | 27 oct. | Priorité proposée : **une expérience complète sur une topologie simple**, sans multiplier les modèles. | Valider la chaîne avant la variété. *Documentée.* | slides 27 oct. | ✅ |

## 3. Pipeline de données (30 octobre – 6 novembre)

| # | Date | Décision | Justification | Source | État |
| - | ---- | -------- | ------------- | ------ | ---- |
| 18 | 30 oct. | **Animation des paquets** (une boule par paquet, tcpdump sur chaque équipement). | Rendre le trafic visible, esprit Packet Tracer. *Documentée.* | `fe3fd3c` | ❌ n° 58 |
| 19 | 30 oct. | **CICFlowMeter** via l'image conteneurisée de ConCap, plutôt que des features maison. | Mêmes colonnes que CIC-IDS et ConCap : comparable à la littérature. *Documentée.* | `cicflowmeter.py` | ✅ |
| 20 | 30 oct. | Exporteur de flux **interne** de repli (`flows.py`). | Autonomie si Docker ou l'image manquent. *Documentée.* | `flows.py` | ❌ n° 59 |
| 21 | 30 oct. | Trafic bénin et attaques séparés dans **deux panneaux**. | Deux usages différents. *Reconstituée.* | `fe3fd3c` | ✅ |
| 22 | 30 oct. | Attaques réalisées avec **nmap puis hydra**, plutôt que des scripts maison. | Outils de référence, ceux des jeux CIC-IDS. *Documentée.* | GUIDE §8 | ✅ |
| 23 | 30 oct. | **Quatre vitesses** d'attaque (nmap `-T2` à `-T5`, hydra 1 à 16 connexions). | Diversifier les flux. *Documentée.* | `traffic.py` | ✅ |
| 24 | 6 nov. | **Ne pas utiliser ConCap tel quel** ; reprendre sa méthode et son CICFlowMeter. | Kubernetes, réseau plat, capture sur la cible, pas de bénin, étiquette par scénario, pcap entier. Argument décisif : le point de vue. *Documentée.* | GUIDE §7, slides 9 nov. | ✅ |
| 25 | 6 nov. | Générer les **datasets dans le lab**, sur la topologie réelle. | Conséquence du n° 24. *Documentée.* | `53741b7` | ✅ |
| 26 | 6 nov. | Bénin et attaques **joués en même temps**, attaques en série. | Un trafic réaliste est mélangé. *Documentée.* | slides 9 nov. | ✅ |
| 27 | 6 nov. | **Étiquetage par flux** : source → cible pendant la fenêtre de l'attaque, marges de 1 s et 2 s. | Trafic mélangé, décalage possible des horloges. *Documentée.* | `datasets.py` | ✅ |
| 28 | 6 nov. | **Pause de l'agent bénin de l'attaquant** pendant son attaque, dans les datasets. | Rendre la règle d'étiquetage exacte. *Documentée.* | `datasets.py` | ✅ étendue n° 65 |
| 29 | 6 nov. | **Fenêtres de 5 s** identiques à l'entraînement et en détection. | Sans cela, un ping d'une minute forme un flux à l'entraînement et des fragments en détection. *Documentée.* | `cicflowmeter.py` | ✅ ⏳ valeur à tester |
| 30 | 6 nov. | **Variantes de test** : autre machine, autre vitesse, autre intensité de bénin ; déterministes. | Vérifier qu'un comportement est appris, pas « telle machine ». *Documentée.* | `datasets.py` | ✅ |
| 31 | 6 nov. | Datasets et modèles stockés en **fichiers**, sans base de données. | Simple, inspectable, téléchargeable. *Documentée.* | GUIDE §8 | ✅ |
| 32 | 6 nov. | **Entraîner sur nos données** plutôt que prendre un modèle préentraîné. | Un modèle externe ne connaît pas notre réseau ; les attaques exigent de maîtriser modèle et données. *Documentée.* | slides 9 nov. | ✅ |
| 33 | 6 nov. | **Random forest** comme premier modèle. | Rapide, sans normalisation, explicable, présent dans la littérature NIDS (Das). *Documentée.* | GUIDE §8 et §11 | ✅ |
| 34 | 6 nov. | Retirer **identifiants, IP et ports source** des features. | Sinon : « PC-1 attaque ». *Documentée.* | `training.py` | ✅ |
| 35 | 6 nov. | Retirer aussi **`Dst Port` par défaut** (option). | Dans un petit lab, raccourci « tout ce qui ne vise pas le port 80 est une attaque ». *Documentée.* | `training.py` | ✅ |
| 36 | 6 nov. | **Pas de découpage aléatoire** : variantes séparées ou fin chronologique. | Des flux quasi identiques des deux côtés gonflent les scores. *Documentée.* | `training.py` | ✅ |
| 37 | 6 nov. | Modes binaire **et multiclasse**. | Comparer les deux. *Reconstituée.* | `53741b7` | ❌ n° 61 |
| 38 | 6 nov. | `class_weight="balanced"`. | Datasets très déséquilibrés. *Documentée.* | `training.py` | 🔁 n° 67 |
| 39 | 6 nov. | **Détection en direct par fenêtres**, avec conteneur CICFlowMeter permanent. | Éviter le coût de démarrage à chaque fenêtre (~1,5 s au lieu de plusieurs). *Documentée.* | `cicflowmeter.py` | ✅ |
| 40 | 6 nov. | Comparer les verdicts à une **vérité terrain** connue du moteur. | Mesurer en conditions réelles. *Documentée.* | `detection.py` | ✅ corrigée n° 65 |
| 41 | 6 nov. | Toujours **garder visibles les erreurs** du modèle dans les événements. | Un gros scan ne doit pas masquer une attaque manquée. *Documentée.* | `detection.py` | ✅ |
| 42 | 6 nov. | **Vrais services** (OpenSSH, vsftpd, OpenSMTPD, dnsmasq, MariaDB…), simulateur seulement pour les noms inconnus. | Une bannière ferait apprendre des artefacts. *Documentée.* | `fbf68a2` | ✅ |
| 43 | 6 nov. | **Agent bénin à sessions complètes**, vrais clients, plutôt qu'un rejeu de pcap. | Un pcap rejoué ne correspond pas aux adresses ni aux services. *Documentée.* | GUIDE §8 | ✅ |
| 44 | 6 nov. | Une erreur de mot de passe sur 20 sessions SSH, FTP, MySQL. | Une erreur isolée n'est pas une force brute. *Documentée.* | SERVICES §5 | ✅ |
| 45 | 6 nov. | Prédominance de la navigation web dans les poids. | Comme sur un vrai réseau. *Documentée.* | SERVICES §5 | ✅ |
| 46 | 6 nov. | Compte unique `labuser` / `password123`, volontairement faible. | La force brute doit réussir pour illustrer l'attaque. *Documentée.* | SERVICES §3 | ✅ |
| 47 | 6 nov. | Détecter le type d'un service par son **nom**, le port seulement à défaut. | Permet un SSH sur un port non standard. *Documentée.* | SERVICES §1 | ✅ |
| 48 | 6 nov. | Isoler le réseau (aucune route vers l'hôte ni Internet). | Attaques sans risque pour l'extérieur. *Documentée.* | GUIDE §11 | ✅ |
| 49 | 6 nov. | Mémoriser la **topologie** avec chaque dataset et avertir en cas de mélange. | Un modèle ne vaut que pour son réseau. *Documentée.* | `datasets.py` | ✅ |
| 50 | 6 nov. | Clients des services installés sur les PC. | Vérifier chaque service à la main. *Documentée.* | `89a8c6e` | ✅ |

## 4. Préparation de la réunion (8 – 9 novembre)

| # | Date | Décision | Justification | Source | État |
| - | ---- | -------- | ------------- | ------ | ---- |
| 51 | 8 nov. | La **Sonde IDS est le seul point de capture** des datasets. | Même point de vue en entraînement et en détection. *Documentée.* | `6521fa0` | ✅ |
| 52 | 8 nov. | nmap et hydra aussi sur les PC. | Rejouer à la main. *Documentée.* | `2c81a42` | ✅ |
| 53 | 9 nov. | Une case par **service réellement ouvert** pour le bénin. | Ne proposer que le possible. *Documentée.* | `fe4bf2c`, `a9aff0b` | ✅ |
| 54 | 9 nov. | **Aucun score dans les slides**. | Aucun résultat chiffré enregistré dans le dépôt. *Documentée.* | `slides_9_nov.tex` | ✅ |
| 55 | 9 nov. | Feuille de route : ligne de base → évasion par timing sur le random forest → second modèle et transfert → empoisonnement ou porte dérobée. | Le sujet demande plusieurs attaques et plusieurs modèles ; commencer par le plus simple à mesurer. *Documentée.* | slides 9 nov. | ⏳ à confirmer selon la réunion |
| 56 | 9 nov. | Deux conditions à une démonstration d'évasion : ligne de base solide, et attribuer la cause (modèle ou découpage en fenêtres). | Éviter une conclusion fausse. *Documentée.* | slides 9 nov. | ✅ |

## 5. Après la réunion du 9 novembre

Problèmes de la démo : attaques manquées sans explication, importance des features inexpliquée.

| # | Décision | Justification | Source | État |
| - | -------- | ------------- | ------ | ---- |
| 57 | Critère de tri du code : ce qui sert la chaîne réseau → données → entraînement → détection → attaques contre le modèle reste. | Demande de l'équipe. | cette session | ✅ |
| 58 | **Retirer l'animation des paquets**. | Aucun lien avec la chaîne ML, et un tcpdump de plus par équipement. | cette session | ✅ |
| 59 | **Retirer l'exporteur interne** ; sans CICFlowMeter, erreur explicite. | Ses colonnes ne sont pas celles de CICFlowMeter : un modèle ne peut pas les utiliser. | cette session | ✅ |
| 60 | **Retirer `code/concap/`**. | Non utilisé (n° 24). L'historique git le conserve. | cette session | ✅ |
| 61 | **Retirer le mode multiclasse**. | Choix de l'équipe ; le modèle présenté est binaire. Le détail par attaque reste (n° 66). | décision de l'équipe | ✅ |
| 62 | **Garder les exports CSV et pcap** ; l'export d'un scénario utilise désormais les mêmes fenêtres de 5 s. | Choix de l'équipe. Les fenêtres : même préparation que les données du modèle. | décision de l'équipe | ✅ |
| 63 | **Garder** découpage temporel, vue Wireshark, terminal, variantes. | Non désignés au retrait par l'équipe. | décision de l'équipe | ✅ |
| 64 | Six fichiers markdown fusionnés en **deux** (`README.md`, `DOCUMENTATION.md`). Slides inchangées, conservées comme archives. | Redondance ; les slides reflètent ce qui a été présenté. | cette session | ✅ |
| 65 | **Pause de l'agent bénin de l'attaquant aussi en détection en direct.** | Ses flux étaient comptés comme des attaques manquées (voir le rapport IDS). | `traffic.py` | ✅ |
| 66 | **Score par type d'attaque**, à l'entraînement et en direct. | Le score global masquait une force brute largement ratée derrière le volume des scans. | `training.py`, `detection.py` | ✅ |
| 67 | **Poids équilibrés par étiquette d'origine**, au lieu de `class_weight` binaire. | Un scan (65 000 flux possibles) ne doit pas décider seul de ce qu'est une attaque. | `training.py` | ✅ |
| 68 | **Liste de 61 mots de passe** au lieu de 8. | 8 essais produisaient une poignée de flux. | `traffic.py` | ✅ |
| 69 | Désactiver `PerSourcePenalties` d'OpenSSH et relever `MaxStartups`. | Ces protections d'OpenSSH coupaient la force brute (« Connection reset by peer »). Choix de lab : un serveur réel les garderait. | `service_listener.py` | ✅ |
| 70 | Importance des features **expliquée** dans le rapport et la documentation (Gini, sur l'entraînement). | Question posée en réunion. | `ModelDialog.jsx`, `DOCUMENTATION.md` §8 | ✅ |
| 72 | Recommander un dataset couvrant **toutes les attaques montrées**, et vérifier le score par attaque avant une démo. | Un modèle supervisé ne reconnaît que ce qu'il a appris. | `code/docs/rapports/rapport_ids.md` | ✅ |
| 71 | L'arrêt du réseau tolère un conteneur déjà en cours de suppression. | Il renvoyait une erreur 500 si un scénario se terminait au même moment. | `deployer.py` | ✅ |
| 73 | Une alerte sans attaque connue devient **« Alerte non vérifiée »** ; une attaque de dataset en échec déclenche un avertissement. | Le moteur ne connaît pas les attaques manuelles (voir `rapport_scan_manuel.md`) ; le dataset Simple contenait des forces brutes échouées sans alerte. | `DetectionPanel.jsx`, `datasets.py` | ✅ |
| 74 | **Le verdict du modèle prime** : tout flux classé `ATTACK` est affiché comme attaque détectée. La vérité terrain ne sert qu'à signaler les attaques manquées ; les fausses alertes se lisent dans le rapport d'entraînement. Remplace le n° 73 pour le libellé. | Reléguer une détection en « fausse alerte » ou « non vérifiée » contredisait le modèle sans information supplémentaire : le moteur ne peut pas savoir si une attaque manuelle a eu lieu. | `detection.py`, `DetectionPanel.jsx` | ✅ |

## 6. Questions encore ouvertes

| Question | Pourquoi elle reste ouverte |
| -------- | --------------------------- |
| Combien de modèles, lesquels ? | Question posée à Grégory Blanc dans les slides du 9 novembre ; la réponse n'est pas dans le dépôt. |
| Le lab seul suffit-il, ou faut-il CIC-IDS2017 ? | Idem. |
| Quelle attaque d'empoisonnement privilégier ? | Idem. |
| Effet de la taille de la fenêtre sur la détection | Hypothèse à tester avant l'évasion par timing (n° 56). |
