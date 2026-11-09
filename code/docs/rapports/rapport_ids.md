# Rapport : pourquoi l'IDS ne détectait pas les attaques

Test de bout en bout du 9 novembre 2026, dans Chrome, sur l'exemple « Mini-entreprise » (3 PC dans le LAN,
2 serveurs et la sonde dans la DMZ), avec le trafic bénin « Mixte intense » actif.

## Verdict

**La chaîne technique marchait : capture, flux et classement fonctionnaient. Le problème venait de la mesure et
des données.** Trois causes se cumulaient, et un score global de 96,5 % les cachait.

| # | Cause | Effet |
| - | ----- | ----- |
| 1 | La vérité terrain comptait le trafic normal de l'attaquant comme une attaque | De faux « Manquée », sur des flux que le modèle classait correctement |
| 2 | La force brute et la plupart des scans étaient absents ou presque de l'entraînement | Le modèle ne les reconnaissait pas |
| 3 | Le rapport ne donnait qu'un score binaire global | Une attaque ratée restait invisible derrière le volume des scans |

**Réserve** : les datasets et le modèle de la démo ne sont pas dans le dépôt. J'ai reproduit le symptôme que vous
m'avez décrit (attaques manquées), mais je ne peux pas prouver que votre modèle de la démo souffrait exactement
des mêmes causes.

## Reproduction

Dataset avec un scan connect et une force brute SSH (2 répétitions chacune), plus 2 variantes de test, puis
entraînement avec les réglages par défaut.

- **Hors ligne** : 96,5 % d'attaques détectées, 0 fausse alerte. Le modèle semblait excellent.
- **En direct** : la force brute SSH donnait **1 flux détecté sur 14**.

| Attaque en direct | Détectés / vrais + faux manqués | Observation |
| ----------------- | ------------------------------- | ----------- |
| Scan connect | 202 / 209 | Les 7 manqués visent les ports 80 et 443 : trafic normal de PC-1 |
| Scan SYN | 65 315 / 65 328 (13 manqués, cumul avec les autres essais) | Attaque non apprise, mais très typée |
| Force brute SSH | 1 / 14 | 6 manqués réels sur le port 22 ; les autres sont du DNS et de l'ICMP de l'agent |
| Force brute FTP | 0 / 22 | Attaque non apprise ; 8 manqués sur le port 21, le reste vient de l'agent |
| Identification des services | 105 / 143 | Les manqués visent surtout 80, 443, 3306 : trafic normal |
| Balayage de découverte | 0 / 75 | Attaque non apprise ; manqués surtout sur 80 et 443 |
| Scan approfondi | 1 005 / 1 144 | Manqués surtout sur 80, 443, 3306 |

## Causes prouvées

### 1. Vérité terrain polluée

Pendant un dataset, l'agent bénin de la machine attaquante est mis en pause. **Pas en détection en direct.** La
règle (« flux source → cible pendant l'attaque = attaque ») comptait donc ses sessions web, DNS et ping comme des
attaques. Le modèle les classait bénignes, à raison, et l'interface affichait « Manquée », souvent avec une
confiance de 100 %. Le cas extrême est le balayage d'un sous-réseau, où tout le trafic de l'attaquant vers la DMZ
était compté.

### 2. Données d'entraînement insuffisantes

Le dataset contenait 406 flux `port-scan` contre **7 flux `ssh-patator`**.

- `class_weight="balanced"` équilibre seulement BENIGN et ATTACK : à l'intérieur de ATTACK, le scan décidait seul.
- 8 mots de passe seulement, et l'une des 2 exécutions de la base a échoué.
- OpenSSH 10 (`PerSourcePenalties`) coupait la force brute (`Connection reset by peer`, code de sortie 255).
- Un flux de force brute SSH ressemble à une vraie session : médianes de 13 paquets aller et 167 ms, contre 21
  paquets et 187 ms pour le bénin.
- Un modèle supervisé ne reconnaît que ce qu'il a appris : le balayage de découverte, absent de ce dataset, donnait 0.

### 3. Score global trompeur

Sur le test, le score par classe (non affiché à l'époque) donnait :

| Classe | Détectés |
| ------ | -------- |
| port-scan | 752 / 764 |
| **ssh-patator** | **12 / 28** |
| BENIGN (fausses alertes) | 0 / 369 |

Le 96,5 % global portait à 96 % sur des flux de scan. **Rien dans l'interface ne permettait de voir que la force brute
était mal détectée.**

## Hypothèses écartées

| Hypothèse | Résultat |
| --------- | -------- |
| Paquets perdus à cause de `tcpdump -G` et de la suppression des fichiers | Écartée : tcpdump n'écrit plus dans un fichier une fois sa période écoulée, et les 65 000 flux du scan SYN sont bien arrivés |
| La sonde ne voit pas les attaques | Écartée sur ce réseau : elle surveille la DMZ, cible de toutes les attaques. Reste vrai pour toute attaque qui ne passe pas par son switch |
| Écart de features entre entraînement et direct | **Non mesuré directement** (comparaison de distributions non faite). Les taux hors ligne et en direct sont cohérents |

## Corrections

| Correctif | Fichier |
| --------- | ------- |
| Agent bénin de la source en pause pendant un scénario, comme pour les datasets ; reprise à la fin réelle de la dernière attaque | `backend/app/traffic.py` |
| Marge avant la reprise de l'agent dans les datasets (l'étiquetage restait imprécis sur 2 s) | `backend/app/datasets.py` |
| Score **par type d'attaque**, à l'entraînement et en direct ; signalement d'une attaque non apprise | `training.py`, `detection.py`, `ModelDialog.jsx`, `DetectionPanel.jsx` |
| Poids équilibrés par étiquette d'origine | `backend/app/training.py` |
| 61 mots de passe au lieu de 8 | `backend/app/traffic.py` |
| Protections d'OpenSSH désactivées dans le lab | `backend/app/service_listener.py` |

Hors IDS, le test a aussi révélé qu'arrêter le réseau pouvait renvoyer une erreur 500 pendant la fin d'un scénario
(`deployer.py`, corrigé).

**Bug de mon propre correctif, trouvé pendant le test** : l'agent ne reprenait pas si l'attaque durait plus de 90 s
(scan approfondi : 118 s). Corrigé et couvert par un test.

## Résultats après correction

Nouveau dataset contenant **les 7 attaques** (base : 68 088 flux ; 43 flux SSH, 89 FTP, 16 ping-sweep), 2 variantes
de test.

**Hors ligne**, sur les variantes :

| Attaque | Détectés |
| ------- | -------- |
| syn-scan | 131 076 / 131 076 |
| aggressive-scan | 2 149 / 2 152 |
| port-scan | 701 / 702 |
| service-detection | 569 / 571 |
| ftp-patator | 109 / 111 |
| ssh-patator | 95 / 97 |
| ping-sweep | 20 / 34 |
| **Fausses alertes** | **60 / 2 142 (2,8 %)** |

**En direct dans Chrome**, 5 émetteurs bénins actifs :

| Attaque | Avant | Après |
| ------- | ----- | ----- |
| Scan connect | 202 / 209 | **202 / 202** |
| Force brute SSH | 1 / 14 | **15 / 15** |
| Force brute FTP | 0 / 22 | **18 / 18** |
| Identification des services | 105 / 143 | **218 / 220** |
| Balayage de découverte | 0 / 75 | **6 / 7** |
| Scan approfondi | 1 005 / 1 144 | **1 066 / 1 066** |
| Scan SYN | 13 manqués au total | **0 manqué** (47 536 flux comptés) |

**La comparaison n'isole pas chaque correctif** : le modèle « après » a aussi appris 5 attaques de plus que le
modèle « avant ». Pour FTP, le balayage et les services, l'amélioration vient en grande partie de cette couverture.

96 tests automatiques passent, le build de l'interface aussi, sans erreur console pendant le parcours.

## Limites restantes

- **Fausses alertes en direct : environ 5 %** (79 sur 1 401 flux bénins lors de la dernière mesure), contre 2,8 %
  hors ligne. Environ la moitié venait d'un serveur émetteur : le preset « Mixte intense » coche aussi les serveurs,
  qui n'émettaient pas à l'entraînement. Un dataset avec ces émetteurs devrait réduire ce taux (non testé).
- **Balayage de découverte fragile** (20/34 hors ligne, 6/7 en direct) : 16 flux à l'entraînement.
- **Force brute SSH** : hydra termine en moins de 2 s et ne produit que 15 flux par exécution. C'est peu pour une
  ligne de base.
- **Un seul essai, une seule topologie, un seul modèle.** Ces chiffres sont une preuve de fonctionnement, pas une
  évaluation.
- **La force brute ne marche contre OpenSSH 10 que parce que ses protections sont désactivées** : à dire en
  soutenance.

## À savoir pour la soutenance : l'importance des features

Le rapport affiche la baisse moyenne d'impureté de Gini (`feature_importances_`), calculée sur l'**entraînement** ;
le calcul exact est détaillé dans [`DOCUMENTATION.md`, section 8](../DOCUMENTATION.md#8-lentraînement).

Le premier modèle en donne un exemple. L'importance de Gini plaçait en tête `Bwd RST Flags` (10,9 %) et
`Fwd Packets/s` (10,6 %), alors que sur le jeu de test, l'importance par permutation plaçait en tête
`Fwd Packet Length Mean` (0,34 point de rappel macro) : un classement différent, et aucune feature ne pèse lourd
seule, car beaucoup sont redondantes. **Pour choisir quoi modifier lors d'une évasion, ne pas se fier au seul
classement de Gini.**

## Recommandation pour la prochaine démo

Générer le dataset avec **toutes les attaques qu'on compte montrer**, plusieurs répétitions de force brute, et
**vérifier le tableau « Détection par type d'attaque »** avant la réunion. Durée mesurée : environ 42 minutes pour
la base et les 2 variantes avec les 7 attaques.
