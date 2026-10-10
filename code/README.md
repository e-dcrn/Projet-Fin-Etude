# IDS Lab – Éditeur de topologie (UI)

Démonstrateur pédagogique d'attaques contre un IDS basé sur du machine learning.
Cette première étape fournit uniquement **l'interface web** : on y construit une topologie
réseau par glisser-déposer, à la manière de Cisco Packet Tracer. Il n'y a pas encore de backend ni de Docker.

## Prérequis

- **Node.js 20.19+ ou 22.12+** (22 LTS recommandé), fourni avec `npm`.
  Vite 8 refuse de démarrer avec une version plus ancienne.

```bash
node -v   # doit afficher v20.19.x, v22.12.x ou plus récent
npm -v
```

Si votre version est trop ancienne :

- avec [nvm](https://github.com/nvm-sh/nvm) (macOS / Linux) : `cd code && nvm install && nvm use` (lit le fichier `.nvmrc`) ;
- avec [nvm-windows](https://github.com/coreybutler/nvm-windows) : `nvm install 22` puis `nvm use 22` ;
- sinon : installer la version LTS depuis [nodejs.org](https://nodejs.org/).

## Lancer le projet

Depuis la racine du dépôt :

```bash
cd code
npm ci           # installe exactement les versions du package-lock.json (à refaire après chaque pull qui modifie package-lock.json)
npm run dev      # lance le serveur de développement
```

Ouvrir **http://localhost:5173** (le navigateur s'ouvre normalement tout seul).
Les modifications du code sont rechargées à chaud. `Ctrl+C` pour arrêter le serveur.

> `npm ci` et `npm install` donnent le même résultat sur un clone propre ; `npm ci` est préférable
> car il respecte strictement le `package-lock.json`, ce qui garantit que les deux membres du
> binôme ont exactement les mêmes dépendances. Utiliser `npm install <paquet>` uniquement pour
> **ajouter** une dépendance, puis commiter `package.json` **et** `package-lock.json`.

Autres commandes :

| Commande          | Rôle                                             |
| ----------------- | ------------------------------------------------ |
| `npm run dev`     | Serveur de développement (hot reload)            |
| `npm run build`   | Build de production dans `dist/`                 |
| `npm run preview` | Sert le build de production en local pour tester |

### Configuration (optionnelle)

Les variables d'environnement se placent dans un fichier `code/.env` (non versionné).
Partir de l'exemple : `cp .env.example .env`. Aucune variable n'est nécessaire pour l'instant.

### Dépannage

| Symptôme | Cause / solution |
| -------- | ---------------- |
| `npm error engine Unsupported engine` ou `Vite requires Node.js version…` | Node trop ancien : voir [Prérequis](#prérequis). |
| `Port 5173 is in use` | Un autre serveur tourne déjà : l'arrêter, ou Vite proposera automatiquement le port suivant (regarder l'URL affichée dans le terminal). |
| Erreur `Cannot find module @rolldown/binding-…` | `node_modules` copié depuis une autre machine/OS : supprimer `node_modules` puis relancer `npm ci`. |
| `npm warn allow-scripts … fsevents` (macOS) | Avertissement sans conséquence : `fsevents` est une dépendance optionnelle livrée précompilée. Rien à faire. |
| Page blanche | Ouvrir la console du navigateur (F12) pour voir l'erreur. |

## Utilisation

| Action                      | Comment                                                                  |
| --------------------------- | ------------------------------------------------------------------------ |
| Ajouter un équipement       | Glisser un élément de la palette (gauche) sur le canvas : l'icône se pose là où on la lâche |
| Déplacer                    | Glisser l'équipement sur le canvas                                       |
| Relier deux équipements     | Bouton **🔌 Câble**, puis clic sur l'équipement A, puis sur l'équipement B |
| Annuler / quitter le câblage | `Échap` (1ᵉʳ appui : annule le câble en cours ; 2ᵉ appui : quitte le mode) |
| Éditer nom / IP             | Cliquer sur l'équipement : le panneau de droite s'affiche                |
| Supprimer                   | Sélectionner un équipement ou un câble, puis `Suppr` / `Retour arrière`, ou le bouton du panneau |
| Valider                     | Bouton **✔ Valider la topologie** : le JSON s'affiche dans la console du navigateur (F12) |

Les adresses IP acceptent la forme `192.168.1.10` ou `192.168.1.10/24`.
La validation signale (sans bloquer) les IP invalides ou en double, les noms en double
et les équipements non reliés.

## Format JSON produit

```json
{
  "version": 1,
  "generatedAt": "2026-10-10T09:00:00.000Z",
  "nodes": [
    { "id": "pc-1", "type": "pc", "position": { "x": 120, "y": 80 },
      "properties": { "name": "PC-1", "ip": "192.168.1.10/24" } },
    { "id": "ids-1", "type": "ids", "position": { "x": 320, "y": 80 },
      "properties": { "name": "IDS-1", "ip": "192.168.1.250/24" } }
  ],
  "links": [
    { "id": "link-pc-1-ids-1", "source": "pc-1", "target": "ids-1" }
  ]
}
```

Types disponibles : `pc`, `server`, `router`, `switch`, `ids`.

`position` est exprimée en coordonnées du canvas (zoom 1) et désigne le **milieu du bord supérieur**
de l'équipement (`nodeOrigin = [0.5, 0]` dans React Flow). Elle ne sert qu'à l'affichage.

## Architecture

```
code/
├── index.html
├── package.json / package-lock.json   # dépendances (versions figées par le lock)
├── vite.config.js
├── .nvmrc / .npmrc                    # version de Node attendue (vérifiée à l'installation)
├── .env.example                       # modèle de configuration locale
└── src/
    ├── main.jsx                  # Point d'entrée React
    ├── App.jsx                   # ReactFlowProvider + éditeur
    ├── styles/app.css            # Styles globaux
    ├── config/
    │   └── deviceTypes.js        # Catalogue des équipements et des champs éditables
    ├── components/
    │   ├── TopologyEditor.jsx    # Assemble barre d'outils, palette, canvas et panneau
    │   ├── Toolbar.jsx           # Câble, Valider, Tout effacer
    │   ├── Palette.jsx           # Équipements que l'on fait glisser
    │   ├── TopologyCanvas.jsx    # React Flow : dépôt, sélection, clics de câblage
    │   ├── DeviceNode.jsx        # Rendu d'un équipement
    │   ├── PropertiesPanel.jsx   # Formulaire nom / IP, suppression
    │   └── icons/DeviceIcons.jsx # Icônes SVG
    ├── hooks/
    │   ├── useTopology.js        # État nœuds/liens + actions métier
    │   └── useCableTool.js       # Logique « clic A puis clic B »
    ├── utils/
    │   ├── serializeTopology.js  # État React Flow → JSON neutre
    │   └── validators.js         # Validation IP + contrôles de cohérence
    └── services/
        └── topologyApi.js        # Point de branchement du futur backend
```

### Points d'extension

- **Ajouter un type d'équipement** (pare-feu, machine attaquante…) : ajouter une entrée dans
  `src/config/deviceTypes.js`, avec une icône dans `components/icons/DeviceIcons.jsx`.
- **Ajouter une propriété éditable** (masque, passerelle, modèle ML de la sonde…) : ajouter un champ
  dans `PROPERTY_FIELDS` (`src/config/deviceTypes.js`) ; le panneau le prend en compte automatiquement.
- **Brancher le backend** : remplacer le corps de `submitTopology()` dans `src/services/topologyApi.js`
  par un `fetch` vers l'API (l'URL se configure avec `VITE_API_BASE_URL` dans un fichier `.env`).
  Le format JSON ci-dessus sert de contrat entre le front et le back.

## Stack

- [React](https://react.dev/) 19
- [React Flow](https://reactflow.dev/) (`@xyflow/react` v12)
- [Vite](https://vite.dev/)
