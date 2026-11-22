import { PcIcon, ServerIcon, RouterIcon, SwitchIcon, IdsIcon } from '../components/icons/DeviceIcons.jsx';

/** Apparence de chaque type d'équipement sur le schéma : couleur, icône, info-bulle. */
export const DEVICE_TYPES = {
  pc: { color: '#2563eb', Icon: PcIcon, description: 'Poste client' },
  server: { color: '#7c3aed', Icon: ServerIcon, description: 'Serveur (HTTP, SSH, FTP)' },
  router: { color: '#ea580c', Icon: RouterIcon, description: 'Routeur inter-réseaux' },
  switch: { color: '#0891b2', Icon: SwitchIcon, description: 'Switch : définit un réseau' },
  ids: { color: '#dc2626', Icon: IdsIcon, description: 'Sonde IDS : reçoit une copie du trafic du switch' },
};
