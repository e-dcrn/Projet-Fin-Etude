import {
  PcIcon,
  ServerIcon,
  RouterIcon,
  SwitchIcon,
  IdsIcon,
} from '../components/icons/DeviceIcons.jsx';

/**
 * Catalogue des types d'équipements disponibles dans la palette.
 *
 * C'est la source de vérité unique : pour ajouter un nouvel équipement
 * (pare-feu, attaquant…), il suffit d'ajouter une entrée ici.
 *
 * - label        : libellé affiché dans la palette
 * - namePrefix   : préfixe du nom généré automatiquement (ex. « PC-1 »)
 * - color        : couleur d'accent de l'équipement
 * - Icon         : composant icône
 * - description  : info-bulle dans la palette
 *
 * Plus tard, le backend pourra associer chaque type à une image Docker
 * (ex. ids → image de la sonde, pc → image client…).
 */
export const DEVICE_TYPES = {
  pc: {
    label: 'PC',
    namePrefix: 'PC',
    color: '#2563eb',
    Icon: PcIcon,
    description: 'Poste client',
  },
  server: {
    label: 'Serveur',
    namePrefix: 'Serveur',
    color: '#7c3aed',
    Icon: ServerIcon,
    description: 'Serveur (web, DNS, base de données…)',
  },
  router: {
    label: 'Routeur',
    namePrefix: 'Routeur',
    color: '#ea580c',
    Icon: RouterIcon,
    description: 'Routeur inter-réseaux',
  },
  switch: {
    label: 'Switch',
    namePrefix: 'Switch',
    color: '#0891b2',
    Icon: SwitchIcon,
    description: 'Commutateur de niveau 2',
  },
  ids: {
    label: 'Sonde IDS',
    namePrefix: 'IDS',
    color: '#dc2626',
    Icon: IdsIcon,
    description: 'Sonde de détection d\'intrusion basée sur du ML',
  },
};

/**
 * Champs éditables dans le panneau de propriétés, communs à tous les équipements.
 * Le panneau est générique : ajouter un champ ici l'affiche automatiquement.
 */
export const PROPERTY_FIELDS = [
  { key: 'name', label: 'Nom', placeholder: 'ex. PC-1', required: true },
  { key: 'ip', label: 'Adresse IP', placeholder: 'ex. 192.168.1.10/24', type: 'ip' },
];

/** Type MIME personnalisé utilisé pour le drag & drop palette → canvas. */
export const DND_MIME_TYPE = 'application/x-ids-device-type';

/**
 * Géométrie d'un nœud sur le canvas (doit rester cohérente avec .device-node dans app.css).
 * Les nœuds utilisent nodeOrigin = [0.5, 0] : leur position désigne le milieu de leur bord
 * supérieur. Le centre de l'icône est donc toujours à (0, NODE_ICON_CENTER_Y) de cette position,
 * quelle que soit la longueur du nom affiché dessous.
 */
export const NODE_ORIGIN = [0.5, 0];
export const NODE_ICON_SIZE = 52; // largeur/hauteur de .device-node__icon
export const NODE_PADDING_TOP = 6; // padding haut de .device-node
export const NODE_ICON_CENTER_Y = NODE_PADDING_TOP + NODE_ICON_SIZE / 2;
