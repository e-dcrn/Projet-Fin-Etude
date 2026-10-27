# Attaques concrètes contre des ML-NIDS — sélection pour GB2

Recherche du 6 octobre 2026. Objectif : identifier des couples **modèle–attaque** utilisables dans un démonstrateur, avec données, implémentations et limites. Les accès institutionnels IEEE Xplore et ScienceDirect ont été utilisés ; les sources ouvertes des auteurs complètent la sélection.

Les PDF sont joints, sauf celui de SecFedNIDS, référencé par son article et son dépôt. Les entrées 9 à 12 (empoisonnement et portes dérobées) ont été ajoutées le 27 octobre 2026 à partir du moteur FOCUS de la médiathèque. Les dépôts ont été consultés, mais leur code n’a pas été exécuté : disponibilité du code et reproduction réussie restent deux choses distinctes.

## 1. TrafficManipulator — premier candidat pour l’évasion

**Han et al., 2021. Evaluating and Improving Adversarial Robustness of Machine Learning-Based Network Intrusion Detectors.** IEEE JSAC. DOI : 10.1109/JSAC.2021.3087242.

- **Cibles :** Kitsune/KitNET (ensemble d’autoencodeurs), MLP, régression logistique, arbre de décision, SVM et Isolation Forest ; extracteurs AfterImage ou CICFlowMeter.
- **Attaques :** PGA/PBA, génération adversariale et optimisation PSO ; modification des délais et ajout de paquets pour diminuer la détection.
- **Données :** Kitsune et CICIDS2017, notamment Mirai, SSDP DoS, scans et DDoS.
- **Support concret :** transformation de PCAP, réextraction des caractéristiques et comparaison des scores. Le dépôt expose une chaîne KitNET et PSO ; ne pas supposer que toute la partie GAN de l’article est intégrée dans un script prêt à lancer.
- **Démonstrateur :** afficher détection avant/après, score d’anomalie, délai et volume supplémentaires.

[Article](https://doi.org/10.1109/JSAC.2021.3087242) · [Accès école](https://ieeexplore-ieee-org.mediaproxy.imtbs-tsp.eu/document/9448103/) · [Code des auteurs](https://github.com/dongtsi/TrafficManipulator)

PDF : `01_Han_2021_TrafficManipulator.pdf`.

## 2. Attaque XAI d’Okada — particulièrement adaptée à un réseau de VM

**Okada et al., 2025. Xai-driven black-box adversarial attacks on network intrusion detectors.** International Journal of Information Security. DOI : 10.1007/s10207-025-01016-0. Grégory Blanc figure parmi les auteurs.

- **Cible :** MLP à deux couches cachées de 256 neurones, décliné avec CICFlowMeter ou Zeek.
- **Attaque :** KernelSHAP identifie des caractéristiques utiles à l’évasion, puis des transformations du trafic les modifient : comportement PSH ou séparation des sessions TCP, notamment pour la force brute FTP.
- **Données :** CICIDS2017, TON_IoT et trafic produit localement ; scénarios FTP et XSS.
- **Support concret :** expériences entre machines virtuelles Kali et CentOS, capture du trafic et vérification de l’activité malveillante.
- **Limite :** aucun dépôt complet des auteurs identifié ; reconstruction expérimentale à prévoir.

[Article et PDF ouverts](https://link.springer.com/article/10.1007/s10207-025-01016-0)

PDF : `02_Okada_2025_XAI_trafic_reel.pdf`.

## 3. TANTRA — évasion par les délais

**Sharon et al., 2022. TANTRA: Timing-Based Adversarial Network Traffic Reshaping Attack.** IEEE TIFS. DOI : 10.1109/TIFS.2022.3201377.

- **Cibles :** Autoencoder, KitNET et Isolation Forest.
- **Attaque :** modifier les intervalles entre paquets pour imiter les temporisations bénignes. Le LSTM génère l’attaque ; il n’est pas le NIDS ciblé.
- **Données :** Kitsune et CICIDS2017, plusieurs activités malveillantes.
- **Support concret :** temporisation du trafic, sans modifier le contenu applicatif.
- **Code :** dépôt original non identifié ; une reproduction ultérieure est fournie dans le dépôt de Mao, section TANTRA, avec LSTM, transformation PCAP et réextraction CICFlowMeter.
- **Démonstrateur :** faire varier le budget de délai et observer détection et latence.

[Article](https://doi.org/10.1109/TIFS.2022.3201377) · [Accès école](https://ieeexplore-ieee-org.mediaproxy.imtbs-tsp.eu/document/9865980/) · [Reproduction ultérieure](https://github.com/maozhongshu1995/TransAdvAttForNIDS)

PDF : `03_Sharon_2022_TANTRA.pdf`.

## 4. Attaques structurelles de GNN — le choix du réseau devient visible

**Venturi, Stabili et Marchetti, 2024. Problem space structural adversarial attacks for Network Intrusion Detection Systems based on Graph Neural Networks.** Version arXiv v2 consultée.

- **Cibles :** E-GraphSAGE et LineGraphSAGE.
- **Attaques :** C2x_B, C2x_M, U2x et Add Node ; modification des communications constituant les arêtes et nœuds du graphe.
- **Exemple conseillé :** C2x_B ajoute des communications bénignes depuis un hôte compromis afin de modifier son voisinage et masquer un flux malveillant conservé.
- **Données :** CTU-13 et ToN-IoT.
- **Code :** préparation, entraînement et attaques structurelles disponibles.
- **Limite :** évaluations sur netflows/graphes ; l’intégration du code dans un réseau actif avec capture de paquets reste à réaliser.

[Prépublication](https://arxiv.org/abs/2403.11830) · [Code des auteurs](https://github.com/andreaventuri01/Structural_attacks_GNN_NIDS)

PDF : `04_Venturi_2024_attaques_structurelles_GNN.pdf`.

## 5. SPTS/DGM — attaques transférables avec contraintes réseau

**Mao et al., 2025. Exploring transferable adversarial attacks for Deep Learning-based Network Intrusion Detection.** JNCA. DOI : 10.1016/j.jnca.2025.104255.

- **Cibles :** MLP, CNN, ResCNN, LSTM et Self-attention.
- **Attaques :** SPTS et DGM ; perturbations calculées sur des modèles substituts et transférées vers la cible, avec contraintes sur les caractéristiques. Le dépôt fournit notamment MI-FGSM.
- **Données :** CICIDS2018 et TON_IoT.
- **Support concret :** code de contraintes, passage aux PCAP, réextraction par CICFlowMeter et évaluation.
- **Limite :** vérifier séparément qu’un trafic transformé accomplit encore l’activité malveillante en réseau actif ; le passage aux PCAP ne suffit pas à le prouver.

[Article](https://doi.org/10.1016/j.jnca.2025.104255) · [Code des auteurs](https://github.com/maozhongshu1995/TransAdvAttForNIDS)

PDF déjà obtenu et conservé : `05_Mao_2025_SPTS_DGM.pdf`.

## 6. TIKI-TAKA — comparaison de plusieurs attaques et modèles

**Zhang, Costa-Pérez et Patras, 2022. Adversarial Attacks Against Deep Learning-Based Network Intrusion Detection Systems and Defense Mechanisms.** IEEE/ACM Transactions on Networking. DOI : 10.1109/TNET.2021.3137084.

- **Cibles :** MLP, CNN et C-LSTM.
- **Attaques :** NES, Boundary, Pointwise, HopSkipJumpAttack et OPT-Attack ; requêtes en boîte noire sur le détecteur.
- **Données :** CSE-CIC-IDS2018 et validation complémentaire CICIDS2017.
- **Support concret :** comparaison modèle–attaque, dont un cas contraint aux caractéristiques temporelles.
- **Limite :** expériences sur vecteurs de caractéristiques ; aucune chaîne complète de rejeu réseau identifiée. Dépôt original non trouvé.
- **Démonstrateur :** utile pour un mode expérimental sur données et pour comparer le nombre de requêtes.

[Article](https://doi.org/10.1109/TNET.2021.3137084) · [Accès école](https://ieeexplore-ieee-org.mediaproxy.imtbs-tsp.eu/document/9674195/)

PDF : `06_Zhang_2022_TIKI_TAKA.pdf`.

## 7. SecFedNIDS — empoisonnement avec code identifié

**Zhang et al., 2022. SecFedNIDS: Robust defense for poisoning attack against federated learning-based network intrusion detection system.** FGCS. DOI : 10.1016/j.future.2022.04.010.

- **Cible concrète du dépôt :** CNN 1D `CNN_UNSW`, entraîné par apprentissage fédéré/FedAvg.
- **Attaque :** label flipping chez des clients compromis : des exemples malveillants reçoivent une étiquette bénigne ; leurs mises à jour influencent le modèle global.
- **Données :** UNSW-NB15 dans le code inspecté ; article également évalué sur CICIDS2018.
- **Code :** `main_poisoned_model_det.py` contient le scénario ; `Net.py` définit le CNN.
- **Limites :** données préparées `X.npy` et `Y_attack.npy` attendues séparément ; environnement et préparation à adapter.
- **Démonstrateur :** fraction de clients compromis, proportion de labels modifiés et rappel du modèle global après entraînement.

[Article](https://doi.org/10.1016/j.future.2022.04.010) · [Accès école](https://www-sciencedirect-com.mediaproxy.imtbs-tsp.eu/science/article/pii/S0167739X22001339) · [Code des auteurs](https://github.com/zhangzhao156/SecFedNIDS)

**PDF non inclus** ; article accessible dans le navigateur via l’école.

## 8. Empoisonnement d’un SVM — scénario centralisé plus simple

**Venkatesan et al., 2021. Poisoning Attacks and Data Sanitization Mitigations for Machine Learning Models in Network Intrusion Detection Systems.** MILCOM. DOI : 10.1109/MILCOM52596.2021.9652916.

- **Cible :** SVM linéaire, C=1, classification trafic bénin/scans Nmap.
- **Attaque :** insertion d’exemples étiquetés « scan » dans le voisinage de données bénignes à forte confiance, pour déplacer la frontière lors du réentraînement.
- **Données :** jeu de flux produit pour l’étude ; variables manipulées comprenant durée, nombre de paquets et octets envoyés, avec contraintes de cohérence.
- **Limite :** attaque évaluée sur caractéristiques ; pas de chaîne de rejeu réseau ni dépôt complet identifiés.
- **Attention :** l’empoisonnement par gradient de Biggio est un comparateur peu efficace dans ce cas ; retenir surtout la méthode proposée.

[Article](https://doi.org/10.1109/MILCOM52596.2021.9652916)

PDF déjà obtenu et conservé : `08_Venkatesan_2021_empoisonnement_SVM.pdf`.

## 9. PCAP-Backdoor — porte dérobée à étiquettes propres dans les PCAP

**Koyatan Chathoth et al., 2026. PCAP-Backdoor: Backdoor Generator in Network Traffic for Intrusion Detection Systems.** ACM TCPS. DOI : 10.1145/3805033.

- **Attaque :** insertion de paquets construits (déclencheur) dans une partie du trafic bénin d’entraînement, sans changer les étiquettes ; à l’inférence, le même déclencheur ajouté au trafic malveillant le fait classer bénin.
- **Données :** plusieurs jeux IoT et industriels, plusieurs modèles.
- **Intérêt :** travaille directement sur des PCAP ; performances normales sans déclencheur, donc compromission invisible à une évaluation classique.

[Article](https://doi.org/10.1145/3805033)

PDF : `09_Chathoth_2026_PCAP_Backdoor_ACM.pdf`.

## 10. CSLM — empoisonnement par changement d’étiquettes (SDN)

**Das, Shukla et Sengupta, 2025. Poisoning the Well: Adversarial Poisoning on ML-Based Software-Defined Network Intrusion Detection Systems.** IEEE TNSE. DOI : 10.1109/TNSE.2024.3492032. Trouvé via FOCUS (médiathèque).

- **Cibles :** Random Forest, SVM et MLP, dans un SDN à un ou trois contrôleurs.
- **Attaque :** profil moyen par classe, comparaison des profils par similarité cosinus ; Max-CSLM remplace une étiquette par la classe la plus proche (discret), Min-CSLM par la plus éloignée (plus destructeur). Un paramètre Φ fixe la part d’étiquettes modifiées (0,1 dans le scénario principal).
- **Données :** UNR-IDD.
- **Résultats :** dégradation d’environ 50 % pour RF (Min-CSLM) et 60 % pour SVM (Max-CSLM) avec un seul contrôleur.
- **Hypothèse forte :** contrôleur SDN compromis, donc accès aux étiquettes d’entraînement.
- **Démonstrateur :** simple à reproduire hors ligne ; faire varier Φ et observer rappel et faux positifs.

[Accès école](https://ieeexplore-ieee-org.mediaproxy.imtbs-tsp.eu/document/10742913/)

PDF : `07_Das_2025_Poisoning_the_Well.pdf` (copie de `articles_ML_NIDS/04_…`).

## 11. Empoisonnement d’une source externe en few-shot

**Alhussien et Aleroud, 2023. A Novel Poisoning Attack on Few-Shot based Network Intrusion Detection.** IEEE/IFIP NOMS. DOI : 10.1109/NOMS56928.2023.10154453. Trouvé via FOCUS (médiathèque).

- **Contexte :** la victime entraîne son détecteur avec des jeux externes et quelques flux internes étiquetés (few-shot / transfert).
- **Attaque :** l’attaquant empoisonne 5 % d’une source externe ; chaque exemple d’attaque est rapproché de flux bénins très influents (classement SBBR) et d’attaques « limites ».
- **Cible :** régression logistique sur un espace projeté commun ; CIC-IDS2018 et UNSW-NB15.
- **Résultats :** TPR de 79 % à 47 % avec 10 % de flux internes étiquetés ; effet nettement réduit avec 20 %.
- **Limite :** implémentation Matlab, pas de code public identifié ; attaque sur caractéristiques.

[Accès école](https://ieeexplore-ieee-org.mediaproxy.imtbs-tsp.eu/document/10154453/)

PDF : `11_Alhussien_2023_Poisoning_few_shot.pdf`.

## 12. Porte dérobée par entraînement sous-traité (IoT)

**Ma et al., 2025. Backdoor Attack and Defense Methods for AI–Based IoT Intrusion Detection System.** IET Information Security. DOI : 10.1049/ise2/6664900. Open access, trouvé via FOCUS (médiathèque).

- **Scénario :** la victime confie l’entraînement à un tiers malveillant et ne vérifie le modèle que sur un jeu de test propre.
- **Attaque :** type BadNets ; 0,1 % des exemples reçoivent un déclencheur (dernières caractéristiques mises à leur valeur maximale) et l’étiquette « bénin ».
- **Cibles :** AdaBoost, GBDT, XGBoost, MLP, CNN et RNN ; CICIoT2023.
- **Résultats :** taux de réussite > 97 % dès 4 caractéristiques déclencheuses ; baisse < 3 % sur trafic propre.
- **Défense proposée :** détection par corrélation déclencheur–classe bénigne puis désapprentissage ; réussite ramenée sous 0,5 %.
- **Limite :** déclencheur défini sur les caractéristiques, pas sur des paquets.

[Article](https://doi.org/10.1049/ise2/6664900)

PDF : `10_Ma_2025_Backdoor_IoT_IDS.pdf`.

## Proposition pour le démonstrateur

Mon choix de départ est **TrafficManipulator + KitNET**, pour disposer d’une base codée avec PCAP, et **SVM + empoisonnement**, pour couvrir un entraînement centralisé relativement simple. Si le code d’empoisonnement disponible est prioritaire, choisir **SecFedNIDS + CNN fédéré**, au prix d’une architecture plus complexe.

L’étude **Okada** est la référence la plus directement alignée avec une démonstration entre machines virtuelles. **TANTRA** fournit une attaque facile à expliquer visuellement. Les **GNN** constituent une extension où la topologie des communications intervient explicitement.

Dans l’interface, une attaque doit être proposée selon le modèle **et son extracteur de caractéristiques**, les accès requis et le budget autorisé. Une attaque sur un vecteur ne devient pas automatiquement applicable aux paquets. L’empoisonnement demande une étape d’entraînement ou de mise à jour ; son effet ne se produit pas simplement en envoyant du trafic au modèle figé.

Pour chaque expérience, conserver une référence avant attaque et mesurer : détection/rappel du trafic malveillant, faux positifs, score, coût en délais/paquets/requêtes ou quantité de données empoisonnées. Pour un scénario en réseau, vérifier aussi que l’activité d’origine fonctionne toujours.
