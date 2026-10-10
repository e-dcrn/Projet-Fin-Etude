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
 * - label             : libellé affiché dans la palette
 * - namePrefix        : préfixe du nom généré automatiquement (ex. « PC-1 »)
 * - color             : couleur d'accent de l'équipement
 * - Icon              : composant icône
 * - description       : info-bulle dans la palette
 * - isNetwork         : l'équipement EST un réseau (switch) : les autres s'y relient
 * - hasTerminal       : une fois allumé, un clic ouvre son terminal (ping, curl…)
 * - defaultProperties : propriétés initiales, en plus du nom
 *
 * Modèle de données :
 *   - un switch est un réseau ; les autres équipements sont des nœuds ;
 *   - un câble relie toujours un nœud à un switch et porte la configuration
 *     de l'interface du nœud (nom, IP, masque) : un routeur relié à trois
 *     switches a donc trois interfaces, chacune avec son adresse ;
 *   - l'adressage est automatique par défaut (voir utils/ipam.js).
 */
export const DEVICE_TYPES = {
  pc: {
    label: 'PC',
    namePrefix: 'PC',
    color: '#2563eb',
    Icon: PcIcon,
    description: 'Poste client',
    hasTerminal: true,
    defaultProperties: () => ({ gateway: '', gatewayAuto: true }),
  },
  server: {
    label: 'Serveur',
    namePrefix: 'Serveur',
    color: '#7c3aed',
    Icon: ServerIcon,
    description: 'Serveur (web, DNS, base de données…)',
    hasTerminal: true,
    defaultProperties: () => ({ gateway: '', gatewayAuto: true, services: [] }),
  },
  router: {
    label: 'Routeur',
    namePrefix: 'Routeur',
    color: '#ea580c',
    Icon: RouterIcon,
    description: 'Routeur inter-réseaux',
    defaultProperties: () => ({ routes: [] }),
  },
  switch: {
    label: 'Switch',
    namePrefix: 'Switch',
    color: '#0891b2',
    Icon: SwitchIcon,
    description: 'Commutateur de niveau 2 : définit un réseau',
    isNetwork: true,
    defaultProperties: () => ({ vlan: '', subnet: '' }), // subnet : attribué par l'IPAM à la création
  },
  ids: {
    label: 'Sonde IDS',
    namePrefix: 'IDS',
    color: '#dc2626',
    Icon: IdsIcon,
    description: 'Sonde de détection d\'intrusion basée sur du ML',
    defaultProperties: () => ({ monitoredSegment: '' }),
  },
};

export const isNetworkType = (deviceType) => Boolean(DEVICE_TYPES[deviceType]?.isNetwork);

/** Services proposés à l'ajout sur un serveur (le port reste modifiable). */
export const SERVICE_PRESETS = [
  { name: 'http', port: 80, protocol: 'tcp', label: 'HTTP (web)' },
  { name: 'https', port: 443, protocol: 'tcp', label: 'HTTPS (web chiffré)' },
  { name: 'ssh', port: 22, protocol: 'tcp', label: 'SSH (accès distant)' },
  { name: 'ftp', port: 21, protocol: 'tcp', label: 'FTP (transfert de fichiers)' },
  { name: 'telnet', port: 23, protocol: 'tcp', label: 'Telnet' },
  { name: 'smtp', port: 25, protocol: 'tcp', label: 'SMTP (messagerie)' },
  { name: 'dns', port: 53, protocol: 'udp', label: 'DNS' },
  { name: 'mysql', port: 3306, protocol: 'tcp', label: 'MySQL (base de données)' },
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
