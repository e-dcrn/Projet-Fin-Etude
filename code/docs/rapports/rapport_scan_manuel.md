# Rapport : `nmap -sT` depuis le terminal affiché « Fausse alerte »

Enquête du 9 novembre 2026, sur la topologie « Petit LAN avec serveur web » et le modèle **Simple**
(`20261109-211252`).

## Verdict

**L'IDS détecte le scan manuel exactement comme le scénario. Le modèle n'est pas en cause.**

Ce qui change, c'est uniquement le **libellé** du bilan. « Fausse alerte » veut dire : le modèle a levé une alerte,
et le moteur ne connaît aucune attaque correspondante. Or le moteur ne connaît que les attaques qu'il lance lui-même.
Un `nmap` tapé dans un terminal lui est invisible : il classe donc une vraie détection en erreur.

## Le symptôme, dans votre session

Relevé dans l'état du moteur à l'issue de votre essai (bilan cumulé : 404 flux, 398 alertes).

| | Scan manuel | Bouton Scénario |
| --- | --- | --- |
| Heure | 21:14:40 | 21:15:30 |
| Verdict du modèle | `ATTACK` | `ATTACK` |
| Alertes | 199 | 199 |
| Confiance des événements conservés | 1,00 | 1,00 |
| **Affichage** | **Fausse alerte, réel : BENIGN** | **Détectée, réel : port-scan** |

Seul le champ « réel » diffère.

## Cause exacte

Pour chaque flux, [`detection.py`](../../backend/app/detection.py) compare deux informations indépendantes :

```
verdict du modèle   : ATTACK / BENIGN      ← calculé à partir du trafic
vérité terrain      : une attaque connue ? ← calculée à partir des conteneurs lancés par le moteur
```

| Verdict | Vérité terrain | Affichage |
| ------- | -------------- | --------- |
| ATTACK | attaque connue | Détectée |
| BENIGN | attaque connue | Manquée |
| ATTACK | rien de connu | **Fausse alerte** |
| BENIGN | rien de connu | bénin correct |

`_known_attacks()` ne cherche que les conteneurs auxiliaires portant le rôle `scenario` ou `dataset` :

| | Bouton Scénario | Terminal |
| --- | --- | --- |
| Exécution | conteneur auxiliaire créé par le moteur, qui partage la pile réseau du PC | `exec` d'un shell dans le PC (`terminal.py`) |
| Le moteur connaît l'outil lancé ? | oui, c'est lui qui le lance | non, il relaie seulement les frappes |
| Source, cible, début, fin | enregistrés via les labels et l'état Docker | inconnus |
| Présent dans la vérité terrain | **oui** | **non** |

Le moteur pourrait lire les frappes du terminal, mais déduire de façon fiable qu'il s'agit d'une attaque (scripts,
alias, commandes coupées) serait fragile.

## Vérification expérimentale

Trois essais alternés depuis PC-1 vers Serveur-Web, sans trafic bénin, modèle Simple. La même sonde capture aussi
chaque essai, pour extraire et classer les flux indépendamment du panneau.

Commande manuelle jouée par `docker exec` dans PC-1 : c'est le même chemin d'exécution que le terminal, sans le TTY.

| Essai | Mode | Flux du scan capturés | Classés ATTACK | Bilan affiché |
| ----- | ---- | --------------------- | -------------- | ------------- |
| 1 | Manuel | 200 | 199 | 199 fausses alertes |
| 1 | Scénario | 200 | 199 | 199 détectés, 1 manqué |
| 2 | Manuel | 200 | 199 | 199 fausses alertes |
| 2 | Scénario | 200 | 199 | 199 détectés, 1 manqué |
| 3 | Manuel | 200 | 199 | 199 fausses alertes |
| 3 | Scénario | 200 | 199 | 199 détectés, 1 manqué |

Chaque essai contient 402 paquets, dans les deux modes.

**Les flux sont indiscernables.** Médianes sur les 3 essais, pour les features les plus importantes du modèle :

| Feature | Importance (Gini) | Manuel | Scénario |
| ------- | ----------------- | ------ | -------- |
| Bwd RST Flags | 16,8 % | 1 | 1 |
| RST Flag Count | 11,8 % | 1 | 1 |
| Bwd Packets/s | 10,1 % | 125 000 | 125 000 |
| Flow IAT Max | 9,3 % | 8 µs | 8 µs |
| Flow Packets/s | 8,6 % | 250 000 | 250 000 |
| Fwd Seg Size Min | 7,4 % | 40 | 40 |
| Fwd Packets/s | 6,8 % | 125 000 | 125 000 |

Sur **toutes** les features du modèle, aucune moyenne ne diffère de plus de 20 % entre les deux modes.

Le seul flux non détecté est, dans les deux modes, un flux classé bénin (`dstPort` 80 dans votre session, confiance
0,57) : le port réellement ouvert sur ce serveur.

La différence de version de nmap n'a pas d'effet mesurable : 7.95 sur les PC, 7.99 dans la boîte à outils.

## Conséquences

| Situation | Ce que dit le bilan | Ce qu'il faut comprendre |
| --------- | ------------------- | ------------------------ |
| Attaque manuelle repérée | Fausse alerte | **Vraie détection, mal étiquetée** |
| Attaque manuelle non repérée | bénin | **Attaque manquée, invisible** |
| Attaque par Scénario | Détectée / Manquée | Correct |

Le second cas compte pour la suite du projet : **une évasion testée à la main afficherait zéro alerte et aucune
attaque manquée**, sans que le bilan ne prouve qu'une attaque a eu lieu. Pour les mesures, passer par Scénarios, ou
intégrer l'attaque modifiée au catalogue.

## Autre problème trouvé : le dataset Simple ne contient aucune force brute

Le dataset **Simple** a été généré sur « Petit LAN avec serveur web », dont le serveur **n'ouvre que le port 80**.

- Les 2 forces brutes SSH du dataset ont échoué : `hydra … Connection refused`, code de sortie 255, en 0,9 s.
- Leurs flux `ssh-patator` (2 par dataset) sont de simples connexions refusées, étiquetées comme une attaque.
- Le score « ssh-patator : 4/4 » du modèle Simple **ne prouve donc rien sur la force brute**.

**Il faut un serveur avec un service SSH**, par exemple l'exemple « Mini-entreprise » (Serveur-Fichiers), ou ajouter SSH dans
« Ports ouverts ». Le moteur enregistre déjà ce code de sortie dans `meta.json`, mais rien n'avertit l'utilisateur.

## Pistes de correction

**Mise à jour** : l'option A a d'abord été appliquée, puis remplacée par une simplification. Une alerte est désormais
toujours affichée comme **attaque détectée**, car le moteur ne peut pas savoir si une attaque manuelle a eu lieu : il
n'avait aucune raison de contredire le modèle. La vérité terrain sert seulement à signaler les attaques manquées (voir
le journal, n° 74). D est appliquée ; B et C ne le sont pas. Le tableau ci-dessous décrit l'analyse d'origine.

| Option | Principe | Avantage | Limite |
| ------ | -------- | -------- | ------ |
| **A. Libellé honnête (recommandée)** | Une alerte sans attaque connue devient « Alerte non vérifiée » | Quelques lignes, vrai en toutes circonstances | Ne compte pas les attaques manuelles manquées |
| B. Déclarer une attaque manuelle | Un bouton « J'attaque depuis PC-1 vers X » ouvre une fenêtre de vérité terrain | Bilan exact, y compris les attaques manquées | Une action de plus à la main |
| C. Détecter nmap et hydra dans les PC | Surveiller les processus lancés dans le conteneur | Automatique | Fragile, et traite mal les autres outils ou commandes |
| D. Avertir à la génération | Avertir quand une attaque de dataset se termine en erreur (code de sortie ≠ 0) | Évite un dataset trompeur comme Simple | Indépendant du libellé |

Reste à faire : **B** quand vous testerez des évasions à la main.

## Portée de l'enquête

- **Chrome** : l'extension n'a accès qu'aux onglets qu'elle a ouverts, pas au vôtre. J'ai lu le même état directement
  dans le moteur, celui que le panneau affiche.
- **Votre bilan** a été remplacé par mes essais, la détection étant la même session. Le relevé de votre essai est
  repris dans ce rapport ; la détection est de nouveau arrêtée, et vos conteneurs et votre scénario sont intacts.
- Les essais ont été faits sans trafic bénin, comme dans votre session. Avec du trafic, le raisonnement ne change pas,
  mais les flux normaux de l'attaquant ne sont pas mis en pause lors d'une attaque manuelle.
- Vérification limitée au scan connect sur cette topologie.
