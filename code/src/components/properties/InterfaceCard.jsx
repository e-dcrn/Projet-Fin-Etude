import { AutoButton, TextField } from './fields.jsx';
import { interfaceNameError, ipFieldError, maskFieldError } from '../../utils/validators.js';

/**
 * Configuration d'une interface (= un câble vers un switch) : nom, IP, masque.
 *
 * Par défaut l'adresse est attribuée par l'IPAM (`edge.data.auto`, voir utils/ipam.js) ;
 * la modifier à la main fait passer l'interface en mode manuel.
 *
 * @param edge          câble React Flow ({ data: { interface, ip, mask, auto } })
 * @param networkName   nom du switch à l'autre bout
 * @param subnet        réseau du switch (parseSubnet), ou null
 * @param editableName  le nom de l'interface est modifiable (routeurs)
 * @param ipOptional    l'adresse peut rester vide (sonde IDS)
 */
export default function InterfaceCard({ edge, networkName, subnet, editableName = false, ipOptional = false, onChange }) {
  const { interface: name, ip, mask, auto } = edge.data;
  let hint;
  if (ipOptional && !ip) hint = 'Vide : la sonde écoute sans adresse fixe';
  else if (auto) hint = `Adresse automatique dans le réseau de ${networkName}${subnet ? ` (${subnet.cidr})` : ''}`;
  else hint = subnet && `Réseau de ${networkName} : ${subnet.cidr}`;

  // Toute saisie d'adresse ou de masque passe l'interface en mode manuel
  const manual = (patch) => onChange({ ...patch, auto: false });

  return (
    <div className="iface">
      <div className="iface__header">
        {editableName ? (
          <input
            className={`iface__name-input${interfaceNameError(name) ? ' field__input--error' : ''}`}
            value={name}
            spellCheck={false}
            aria-label="Nom de l'interface"
            onChange={(e) => onChange({ interface: e.target.value.trim() })}
          />
        ) : (
          <span className="iface__name">{name}</span>
        )}
        <span className="iface__arrow">→</span>
        <span className="iface__network">{networkName}</span>
        {edge.data.port && <span className="iface__port">{edge.data.port}</span>}
        <span className={`iface__mode${auto ? ' iface__mode--auto' : ''}`}>{auto ? 'auto' : 'manuel'}</span>
      </div>
      <div className="iface__grid">
        <TextField
          compact
          mono
          label="Adresse IP"
          value={ip}
          placeholder={subnet ? subnet.cidr.split('/')[0].replace(/\d+$/, 'x') : 'ex. 192.168.1.10'}
          error={ipFieldError(ip, { required: !ipOptional })}
          onChange={(value) => manual({ ip: value })}
        />
        <TextField
          compact
          mono
          label="Masque"
          value={mask}
          placeholder="255.255.255.0"
          error={maskFieldError(mask, { required: Boolean(ip) })}
          onChange={(value) => manual({ mask: value })}
        />
      </div>
      {hint && <p className="iface__hint">{hint}</p>}
      {!auto && <AutoButton onClick={() => onChange({ auto: true })} />}
    </div>
  );
}
