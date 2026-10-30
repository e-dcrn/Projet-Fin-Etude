# ConCap — génération du dataset d'entraînement

[ConCap](https://github.com/idlab-discover/ConCap) est un framework qui génère des
**datasets d'IDS étiquetés** à partir de scénarios d'attaque en conteneurs. On
l'utilise ici pour produire les **données d'entraînement/évaluation** du ML-IDS,
au **même format que les jeux CIC-IDS** (features CICFlowMeter). Voir
[`docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md) pour la place de ConCap dans le projet.

> ConCap et le démonstrateur (ce dépôt) sont **complémentaires** : ConCap fabrique
> le dataset (hors ligne, en masse) ; le démonstrateur montre les attaques en direct.
> Les deux partagent le format CICFlowMeter, donc un modèle entraîné sur l'un
> fonctionne sur l'autre.

## Ce que fait ConCap (pipeline)

```
scénario YAML ──> pods attaquant + cible (Kubernetes)
              ──> tcpdump sur la cible        → dump.raw.pcap
              ──> tri par horodatage          → dump.pcap
              ──> pcapfix + CICFlowMeter (cfm) → flux (CSV)
              ──> étiquetage depuis le scénario (l'attaquant ne fait que du malveillant)
```

## Prérequis

ConCap tourne sur **Kubernetes** (ce dépôt, lui, tourne sur Docker). Pour un essai
local, un cluster léger suffit :

- [k3s](https://k3s.io/) (le plus simple sur Linux) **ou** [kind](https://kind.sigs.k8s.io/)
  / [minikube](https://minikube.sigs.k8s.io/) ;
- `kubectl`, un environnement **Go**, et Docker pour construire les images d'attaque/cible.

## Mise en route (résumé)

```sh
# 1. Récupérer ConCap
git clone https://github.com/idlab-discover/ConCap && cd ConCap

# 2. Namespace + secret d'accès au registre d'images (ghcr)
kubectl create namespace concap
kubectl -n concap create secret generic ghcr-creds \
  --from-file=.dockerconfigjson="$HOME/.docker/config.json" \
  --type=kubernetes.io/dockerconfigjson

# 3. Étiqueter les nœuds (sur un cluster à un seul nœud, mets les deux rôles dessus)
kubectl label node <nom-du-noeud> concap-role=attacker concap-role=target --overwrite

# 4. Construire et lancer sur nos scénarios
./build.sh                       # ou : make build
./concap --dir /chemin/vers/ce-depot/code/concap/scenarios
```

Chaque scénario produit un `dump.pcap` et un **CSV de flux étiquetés**. Rassemble
les CSV de tous les scénarios (bénins + attaques) pour obtenir le dataset.

## Scénarios fournis

| Fichier | Attaque | Étiquette |
| ------- | ------- | --------- |
| [`scenarios/nmap-syn-scan.yaml`](scenarios/nmap-syn-scan.yaml) | Scan de ports SYN (nmap) | `PortScan` |
| [`scenarios/ssh-bruteforce.yaml`](scenarios/ssh-bruteforce.yaml) | Force brute SSH (hydra) | `SSH-Patator` |

Le format d'un scénario : `type`, `name`, `attacker` (`image`, `atkCommand`, `atkTime`…),
`target`/`targets`, `network` (`bandwidth`, `queueSize`, `delay`) et `labels`. Les
variables `$ATTACKER_IP` / `$TARGET_IP` sont injectées dans `atkCommand`.

> **Images d'attaque** : l'image doit contenir l'outil (nmap, hydra…). `nmap` a une
> image publique (`instrumentisto/nmap`) ; pour `hydra`, construis une petite image
> (hydra + une wordlist) et pousse-la sur ton registre, puis renseigne-la dans le
> scénario.

## Et sans Kubernetes ?

Le démonstrateur sait déjà produire des flux **CICFlowMeter réels** sur ses propres
captures (voir `backend/app/cicflowmeter.py`, qui réutilise l'image CICFlowMeter de
ConCap en Docker). Tu peux donc générer un dataset « façon ConCap » directement
depuis le démonstrateur si monter un cluster est trop lourd — c'est « inspiré de
ConCap » plutôt que ConCap, mais le format de features est identique.
