# Bibliographie commentée — Démonstrateur d’attaques contre un ML-NIDS

Recherche du 6 octobre 2026 à partir de la médiathèque Télécom SudParis / IMT-BS sur Moodle. Les liens ci-dessous passent par le proxy institutionnel et peuvent demander une connexion à l’école.

## Accès et méthode

La rubrique « Ressources numériques → Articles pour la Recherche » fournit ScienceDirect et IEEE Xplore. Les deux plateformes ont reconnu l’accès Télécom SudParis. Requêtes utilisées :

- ScienceDirect : `"adversarial" AND "network intrusion detection" AND "realistic"`.
- IEEE Xplore : `"network intrusion detection" AND "poisoning"`.

Sélection ciblée sur l’évasion, l’empoisonnement et le réalisme des expériences. Les résumés et des sections du texte intégral des références 1 à 7 ont été consultés, sans lecture exhaustive de chaque article. Pour la référence 8, la vérification porte sur la notice et le résumé. Aucun code n’a été exécuté, aucun résultat reproduit et aucun PDF téléchargé. Les priorités et suggestions sont une appréciation pour le projet, pas un résultat des auteurs.

## 1. Priorité élevée : cadre de réalisme

**João Vitorino, Isabel Praça, Eva Maia. SoK: Realistic adversarial attacks and defenses for intelligent network intrusion detection.** *Computers & Security*, vol. 134, 103433, 2023. DOI : 10.1016/j.cose.2023.103433.

[Lire via ScienceDirect de l’école](https://www-sciencedirect-com.mediaproxy.imtbs-tsp.eu/science/article/pii/S0167404823003437)

Synthèse en accès ouvert, consultée via le portail institutionnel. Elle étudie les contraintes nécessaires pour que les exemples adversariaux correspondent à un trafic réseau valide. À utiliser pour structurer l’état de l’art et les critères de réalisme : connaissance de l’attaquant, caractéristiques modifiables, dépendances entre caractéristiques, respect des protocoles et conservation de la fonction de l’attaque. Une revue sert à choisir les expériences ; elle ne constitue pas une attaque à reproduire.

## 2. Priorité élevée : attaque transférable et passage aux paquets

**Zhongshu Mao, Yiqin Lu, Zhe Cheng, Kaiqiong Chen. Exploring transferable adversarial attacks for Deep Learning-based Network Intrusion Detection.** *Journal of Network and Computer Applications*, octobre 2025. DOI : 10.1016/j.jnca.2025.104255.

[Lire via ScienceDirect de l’école](https://www-sciencedirect-com.mediaproxy.imtbs-tsp.eu/science/article/pii/S1084804525001523)

Texte intégral accessible par l’abonnement. Propose SPTS, un cadre d’attaques transférables sans requêtes au modèle cible, et DGM. Le cadre hiérarchise les caractéristiques et rectifie leurs dépendances. Évaluation sur CIC-IDS-2018 et le trafic réseau de TON_IoT, avec MLP, CNN, ResCNN, LSTM et attention.

La section 5.3.2 transforme les perturbations en modifications de PCAP puis réextrait les caractéristiques avec CICFlowMeter. Cette évaluation ne porte que sur TON_IoT et 36 980 flux retenus. Les performances d’attaque diminuent après cette reconstruction : les auteurs discutent les écarts statistiques introduits par la conversion. Ce point est particulièrement pertinent pour un projet qui doit caractériser le réalisme. Modifier un PCAP et réextraire ses caractéristiques ne suffit toutefois pas, à lui seul, à démontrer le succès d’une attaque applicative dans un réseau actif.

Le résumé fournit le dépôt [TransAdvAttForNIDS](https://github.com/maozhongshu1995/TransAdvAttForNIDS), tandis que la rubrique « Data availability » indique que le code sera disponible sur demande. Cette incohérence doit être résolue en vérifiant le dépôt. Son contenu, sa licence et son fonctionnement restent à vérifier avant de retenir définitivement cette reproduction.

## 3. Priorité élevée : évasion sous contraintes

**Islam Debicha, Benjamin Cochez, Tayeb Kenaza, Thibault Debatty, Jean-Michel Dricot, Wim Mees. Adv-Bot: Realistic adversarial botnet attacks against network intrusion detection systems.** *Computers & Security*, vol. 129, 103176, 2023. DOI : 10.1016/j.cose.2023.103176.

[Lire via ScienceDirect de l’école](https://www-sciencedirect-com.mediaproxy.imtbs-tsp.eu/science/article/pii/S016740482300086X)

Texte intégral accessible par l’abonnement. Étudie l’évasion en boîte noire par transfert, sous contraintes syntaxiques et sémantiques, en visant la conservation de la fonctionnalité du trafic de botnet. Les expériences utilisent CTU-13 et CSE-CIC-IDS2018, avec notamment MLP, Random Forest et KNN.

Intérêt : comparer une attaque dédiée aux botnets au cadre plus général SPTS. La notice indique que les données sont disponibles sur demande ; ne pas supposer que tous les artefacts de reproduction sont publics. Il faudra vérifier séparément le passage aux paquets, le rejeu et le maintien de la fonction malveillante avant de conclure à une validation réseau complète.

## 4. Priorité élevée : empoisonnement des labels

**Tapadhir Das, Raj Mani Shukla, Shamik Sengupta. Poisoning the Well: Adversarial Poisoning on ML-Based Software-Defined Network Intrusion Detection Systems.** *IEEE Transactions on Network Science and Engineering*, vol. 12, no 1, p. 252–262, janvier–février 2025. Publication en ligne le 5 novembre 2024. DOI : 10.1109/TNSE.2024.3492032.

[Lire via IEEE Xplore de l’école](https://ieeexplore-ieee-org.mediaproxy.imtbs-tsp.eu/document/10742913/)

Référence incluse dans l’abonnement ; texte HTML accessible. Propose les attaques Min-CSLM et Max-CSLM, fondées sur la similarité cosinus pour sélectionner des manipulations de labels. Étudie Random Forest, SVM et MLP dans des configurations SDN à un ou plusieurs contrôleurs.

Bon candidat pour couvrir l’entraînement et comparer plusieurs familles de modèles. Hypothèse déterminante : l’attaquant doit pouvoir compromettre les labels d’entraînement. Cette capacité doit être explicitée ; elle ne découle pas automatiquement du contrôle du trafic réseau.

## 5. Priorité élevée : empoisonnement et défense de référence

**Sridhar Venkatesan, Harshvardhan Sikka, Rauf Izmailov, Ritu Chadha, Alina Oprea, Michael J. de Lucia. Poisoning Attacks and Data Sanitization Mitigations for Machine Learning Models in Network Intrusion Detection Systems.** *MILCOM 2021*. DOI : 10.1109/MILCOM52596.2021.9652916.

[Lire via IEEE Xplore de l’école](https://ieeexplore-ieee-org.mediaproxy.imtbs-tsp.eu/document/9652916/)

Référence incluse dans l’abonnement ; texte HTML accessible. Étudie une attaque d’empoisonnement de disponibilité en boîte blanche, avec insertion d’échantillons mal étiquetés et contraintes sur les valeurs des flux. Le détecteur étudié concerne les scans réseau. Propose aussi Nested Training, une défense de nettoyage par désaccord entre modèles.

Intérêt : disposer d’un couple attaque/défense et d’un budget d’empoisonnement mesurable. Les résultats sont liés au détecteur et au jeu de données étudiés ; les contraintes sur les caractéristiques ne prouvent pas automatiquement un rejeu réseau fonctionnel.

## 6. Priorité moyenne : combinaison entraînement et inférence

**Hesamodin Mohammadian, Arash Habibi Lashkari, Ali A. Ghorbani. Poisoning and Evasion: Deep Learning-Based NIDS under Adversarial Attacks.** *21st Annual International Conference on Privacy, Security and Trust (PST)*, 2024. DOI : 10.1109/PST62714.2024.10788064.

[Lire via IEEE Xplore de l’école](https://ieeexplore-ieee-org.mediaproxy.imtbs-tsp.eu/document/10788064/)

Référence incluse dans l’abonnement ; texte HTML accessible. Combine un empoisonnement par modification d’étiquettes avec une évasion fondée sur une carte de saillance. L’article annonce des évaluations sur CIC-IDS2017, CIC-IDS2018 et CIC-UNSW-NB15.

Intérêt : examiner l’effet d’une évasion sur un modèle déjà empoisonné, après avoir étudié chaque attaque séparément. La reconstruction et le rejeu de trafic doivent être vérifiés avant de retenir cette méthode pour la partie réseau du démonstrateur.

## 7. Complément : données synthétiques

**Marc Chalé, Nathaniel D. Bastian. Generating realistic cyber data for training and evaluating machine learning classifiers for network intrusion detection systems.** *Expert Systems with Applications*, 30 novembre 2022. DOI : 10.1016/j.eswa.2022.117936.

[Lire via ScienceDirect de l’école](https://www-sciencedirect-com.mediaproxy.imtbs-tsp.eu/science/article/pii/S0957417422011757)

Texte intégral accessible par l’abonnement. Étudie la génération de données tabulaires par CTGAN et TVAE à partir de données d’un réseau réel, puis l’apprentissage avec différents mélanges de données réelles et synthétiques.

Utile si le banc souffre d’un manque de données ou pour discuter la représentativité de l’entraînement. Ce travail ne doit pas être assimilé à un générateur de paquets valides ou à un environnement de test réseau. Les proportions de données réelles recommandées par les auteurs restent spécifiques à leurs expériences.

## 8. Complément récent : synthèse des contraintes pratiques

**Md Mehedi Hasan, Rafiqul Islam, Quazi Mamun, Md Zahidul Islam, Junbin Gao. Adversarial attacks against network intrusion detection systems: Bridging the gap between theoretical vulnerabilities and practical constraints.** *Internet of Things*, vol. 38, 101997, juillet 2026. DOI : 10.1016/j.iot.2026.101997.

[Lire via ScienceDirect de l’école](https://www-sciencedirect-com.mediaproxy.imtbs-tsp.eu/science/article/pii/S2542660526001277)

Revue en accès ouvert consultée via le portail institutionnel. Notice et résumé vérifiés. Traite la traduction des caractéristiques en paquets, le respect des protocoles, la conservation de la sémantique et les limites des jeux de données. Complète le SoK de 2023 pour actualiser l’état de l’art. Les chiffres agrégés du résumé demandent une lecture de la méthode avant d’être repris dans le rapport.

## Choix proposé pour démarrer

Lire d’abord le SoK, puis SPTS/DGM et Adv-Bot. Pour la partie entraînement, choisir entre Poisoning the Well et l’article MILCOM selon l’accès aux artefacts et le modèle de menace retenu. Garder la combinaison empoisonnement–évasion comme extension.

Pour chaque expérience, documenter : connaissances et contrôle de l’attaquant, budget de perturbation ou d’empoisonnement, performance initiale du détecteur, succès de l’attaque, faux positifs, coût en temps et trafic, validité des paquets et conservation de l’action applicative. Comparer successivement perturbations tabulaires, PCAP modifiés et trafic exécuté dans le réseau de test. Cette progression permet de mesurer l’écart de réalisme au cœur du projet.
