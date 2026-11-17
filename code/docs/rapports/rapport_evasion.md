# Rapport : évasion d'un ML-NIDS par-flux

Expériences du 17 novembre 2026, dans Chrome, sur IDS Lab. Objectif du PFE : passer d'une chaîne ML-IDS qui
fonctionne de bout en bout à une **attaque adversariale** de l'état de l'art — ici une **évasion** (tromper un
modèle déjà entraîné), au niveau des vrais paquets.

## En bref (pour un étudiant)

**Comment « voit » l'IDS.** Il ne regarde pas les paquets un par un. Pour chaque **connexion** (un « flux »), il
calcule une petite fiche de statistiques : combien de paquets, quelle taille moyenne, combien d'octets, combien
de temps. Puis il décide, **fiche par fiche** : normale ou attaque. Point clé : **il juge chaque connexion sur
sa forme (taille / volume), pas sur le rythme auquel les connexions arrivent.**

**Évasion 1 — ralentir l'attaque (temporisation) : ❌ ne marche pas.** Ralentir change *quand* les connexions
arrivent, pas *à quoi ressemble* chacune. Un scan de port reste une connexion minuscule (1 paquet aller, 1
retour, 0 donnée), lente ou rapide : sa fiche est identique et criarde, donc détectée à 100 %.
> *Analogie : pour passer inaperçu à l'entrée d'une soirée, arriver plus lentement ne sert à rien si tu portes
> toujours le même costume reconnaissable. Le videur regarde ton costume, pas ta vitesse de marche.*

**Évasion 2 — imiter le trafic normal (mimétisme) : ✅ marche.** Le trafic normal contient déjà des logins
ratés (un utilisateur qui se trompe de mot de passe). L'IDS n'a donc pas appris « login raté = attaque », mais a
appris à reconnaître l'**outil** d'attaque (hydra), qui laisse une signature. En refaisant la force brute avec le
**même outil que le trafic normal** (la bibliothèque `ftplib`) et au **même rythme humain**, chaque essai produit
une fiche quasi identique à un vrai login raté : l'IDS ne les distingue plus et **88,5 % passent pour du normal**.
> *Même analogie : cette fois tu mets exactement le même costume que les invités attendus. Le videur te laisse
> entrer, parce que tu ne ressembles plus à l'intrus qu'il a appris à repérer.*

**La leçon.** Contre un IDS qui juge **chaque connexion sur sa forme**, changer le **rythme** ne sert à rien ; il
faut changer la **forme des connexions** pour qu'elles ressemblent au trafic normal. C'est ce que l'état de l'art
résume par : la robustesse dépend du **couple modèle + façon de calculer les features**, pas du modèle seul.

## Le détecteur attaqué

Random forest binaire (BENIGN / ATTACK), entraîné sur les features **CICFlowMeter** calculées **par flux**
bidirectionnel, par fenêtres de 5 s (voir [`DOCUMENTATION.md`](../DOCUMENTATION.md) §8). C'est un point
déterminant : le modèle ne voit ni les paquets bruts, ni une statistique glissante au niveau de l'hôte — il
voit **un vecteur de features par flux**. Les features les plus utilisées (importance MDI) sont des tailles de
paquets (`Packet Length Mean/Max/Std`, `Average Packet Size`), des temps (`Fwd IAT Min`, `Flow IAT Min`), la
fenêtre TCP initiale (`FWD Init Win Bytes`) et les drapeaux (`SYN Flag Count`).

## Expérience 1 — Évasion par temporisation (Han/TrafficManipulator, Sharon/TANTRA)

**Idée.** Le modèle n'a appris que des attaques denses (scans `-T2`..`-T5`, hydra en rafale). On ralentit et on
étale fortement l'attaque pour que son rythme ressemble au trafic bénin. Implémenté comme une vitesse d'attaque
« Évasion (furtif, temporisé) » : nmap `-T2 --scan-delay 250ms --max-rate 8`, hydra `-t 1 -W 1`.

**Protocole.** Topologie « Petit LAN » (le modèle `20261110-100030` lui correspond). Détection en direct active.
Même attaque (scan de ports connect, PC-1 → Serveur-Web 10.0.1.10) lancée en vitesse Rapide puis Évasion ;
comparaison du rappel (part des flux d'attaque détectés) et du coût (durée).

**Résultat.**

| Vitesse | Flux | Détectés | Rappel | Durée de l'attaque |
| ------- | ---- | -------- | ------ | ------------------ |
| Rapide  | 200  | 200      | **100 %** | 0,1 s |
| Évasion | 200  | 200      | **100 %** | 50,7 s |

Confiance du modèle = 1,0 sur chaque flux, avant comme après. **La temporisation seule n'évade pas ce modèle.**

**Pourquoi (mesuré sur les flux).** Un flux de scan est intrinsèquement dégénéré : 1 paquet aller / 1 retour,
**0 octet de payload**, durée ≈ 4 µs, un seul drapeau SYN. Un flux bénin : ~22+22 paquets, ~965 o/paquet, durée
longue. L'espacement des sondes ne change **pas la forme d'un flux** — il ne touche qu'une densité inter-flux
que le modèle par-flux ne regarde pas. C'est exactement la limite annoncée par l'état de l'art :
TrafficManipulator et TANTRA visent **KitNET**, un détecteur **fenêtré au niveau de l'hôte**, dont les features
sont des statistiques glissantes sensibles au rythme. Ici l'extracteur est **par flux**.

**Enseignement.** La robustesse n'est pas une propriété du modèle seul mais du **couple modèle–extracteur**
(§ « Enseignements » de l'état de l'art). Une évasion qui marche contre KitNET ne se transfère pas
mécaniquement à un random forest CICFlowMeter.

## Ce que disent les données sur « quoi modifier »

Médianes par classe (datasets de l'expérience 1) :

| feature                    | BENIGN | port-scan | ssh-patator |
| -------------------------- | ------ | --------- | ----------- |
| Total Fwd / Bwd Packet     | 22/22  | 1/1       | 17/16       |
| Packet Length Mean         | 965    | 0         | 113         |
| Total Length of Bwd Packet | 10550  | 0         | 2194        |
| Flow Duration (µs)         | 846394 | 4         | 144814      |

Pour évader un détecteur **par flux**, il faut donc changer la **forme du flux** (nombre de paquets, octets,
durée), pas son rythme. Deux conséquences :
- le **scan de ports** est quasi inattaquable ainsi : un port fermé renvoie 1 paquet (RST), impossible d'y
  injecter du volume ;
- la **force brute** est plus prometteuse, mais une tentative d'authentification **échouée** est structurellement
  courte (pas de session applicative). On ne peut pas la « gonfler » après coup.

Point clé découvert dans le trafic bénin : l'agent bénin fait lui-même des **logins ratés** (un « typo », SSH et
FTP, voir `traffic_agent.HumanUser`). Donc le bénin contient déjà des flux de login raté. Ce qui distingue
`ftp-patator` du bénin n'est pas « login raté vs réussi », mais la **micro-structure du client** (hydra) et le
fait que l'attaque en enchaîne des dizaines en rafale.

## Expérience 2 — Évasion par mimétisme du client (Okada)

**Idée (Okada et al., « XAI-driven black-box adversarial attacks »).** Modifier précisément les flux pour qu'ils
ressemblent au bénin dans les features utilisées par le modèle, et répartir la force brute sur des sessions qui
ressemblent à des sessions légitimes. Réalisation ici : la **force brute FTP furtive**
(`ftp-bruteforce-stealth`) utilise le **même client que l'agent bénin** (`ftplib`) et la **même cadence
humaine** (pauses de 1–4 s) au lieu de hydra. Chaque essai raté produit alors un flux quasi identique au login
raté que l'agent bénin génère déjà ; après le mot de passe correct, une session bénigne (LIST + téléchargements)
est jouée. Sous-catégorie `ftp-patator-stealth`, pour mesurer son rappel séparément.

**Protocole (refait de zéro).** Topologie « Petit LAN + services (SSH, FTP) ». Datasets et modèles précédents
supprimés.
- Dataset **Entraînement** : bénin (HTTP/SSH/FTP/ICMP) + scan de ports + force brute FTP **normale** (hydra).
- Dataset **Test** : bénin + force brute FTP **normale** + force brute FTP **furtive**.
- Entraînement sur le dataset d'entraînement, test sur le dataset de test ; lecture du rappel par sous-catégorie.

**Résultat (modèle `20261117-204143`, 17 novembre 2026, tout refait de zéro).** Random forest entraîné sur le
dataset d'entraînement (BENIGN 1699, port-scan 409, ftp-patator 53), évalué sur le dataset de test (BENIGN 2243,
ftp-patator 60, ftp-patator-stealth 26). Détection par type d'attaque :

| Attaque (jeu de test)             | Flux | Détectés | Rappel   |
| --------------------------------- | ---- | -------- | -------- |
| ftp-patator (normale, hydra)      | 60   | 50       | **83,3 %** |
| ftp-patator-stealth (furtive)     | 26   | 3        | **11,5 %** |

Faux positifs sur le bénin = **0 %** (les logins ratés « typo » de l'agent bénin restent bien classés BENIGN).

**L'évasion fonctionne.** En imitant le client bénin (`ftplib`) et sa cadence humaine, **88,5 % des flux de la
force brute FTP furtive sont classés BENIGN** par un modèle qui détecte pourtant la même force brute lancée avec
hydra (83,3 %). La différence ne tient ni à la cible, ni au protocole, ni au nombre d'essais, mais uniquement à
la **forme des flux** : hydra a une micro-structure que le modèle a apprise comme « attaque » ; le client bénin
produit des flux que le modèle a appris comme « normaux ». C'est l'évasion Okada réalisée en problem-space.

**Coût de l'attaque.** Lenteur (cadence humaine : ~1 essai/2,5 s au lieu d'une rafale hydra) et le fait de devoir
imiter un client légitime. On ne « casse » pas le modèle : on reste sous son seuil en ressemblant au bénin.

## Conclusion

1. L'évasion par **temporisation** (TrafficManipulator/TANTRA) échoue contre un random forest **par flux**
   (démontré, rappel 100 % → 100 %) : ce n'est pas un échec d'implémentation mais un enseignement sur le couple
   modèle–extracteur.
2. L'évasion par **mimétisme du client bénin** (Okada) réussit : la force brute FTP furtive tombe à **11,5 %**
   de rappel (contre 83,3 % pour la même attaque lancée avec hydra), sans aucun faux positif ajouté.
3. Règle générale pour ce détecteur : pour évader un ML-NIDS **par flux**, il faut rendre les **flux** eux-mêmes
   semblables au bénin dans les features utilisées ; agir seulement sur le **rythme** ne suffit pas.

## Reproduire

Topologie « Petit LAN + services (SSH, FTP) ». Deux datasets (sans variantes) : un d'entraînement
(bénin HTTP/SSH/FTP/ICMP intense + `tcp-connect-scan` + `ftp-bruteforce`), un de test (même bénin +
`ftp-bruteforce` + `ftp-bruteforce-stealth`). Entraîner un random forest sur l'entraînement, tester sur le test,
lire « Détection par type d'attaque ». L'attaque furtive est `ftp-bruteforce-stealth` dans le catalogue
(`backend/app/traffic.py`), sous-catégorie `ftp-patator-stealth`.
