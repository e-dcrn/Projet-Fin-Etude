import { RemoveButton, Section, SelectField, TextField } from './fields.jsx';
import { cidrFieldError, ipFieldError } from '../../utils/validators.js';
import { parseInterface } from '../../utils/ipv4.js';

const EMPTY_ROUTE = { destination: '', gateway: '', interface: '' };

/**
 * Table de routage d'un routeur.
 *  - routes connectées : déduites des interfaces, en lecture seule (comme « C » dans show ip route) ;
 *  - routes statiques : éditables (destination, passerelle, interface de sortie).
 *
 * @param links   câbles du routeur (= ses interfaces)
 * @param routes  routes statiques
 */
export default function RoutingTableSection({ links, routes, networkNameOf, onChange }) {
  const connected = links
    .map((l) => ({ link: l, iface: parseInterface(l.data.ip, l.data.mask) }))
    .filter(({ iface }) => iface);

  const interfaceOptions = [
    { value: '', label: 'auto' },
    ...links.map((l) => ({ value: l.data.interface, label: l.data.interface })),
  ];

  const updateRoute = (index, patch) => onChange(routes.map((r, i) => (i === index ? { ...r, ...patch } : r)));

  return (
    <Section title="Table de routage" count={connected.length + routes.length}>
      {connected.length > 0 && (
        <table className="route-table">
          <tbody>
            {connected.map(({ link, iface }) => (
              <tr key={link.id} title={`Réseau de ${networkNameOf(link.target)}`}>
                <td className="route-table__kind">C</td>
                <td className="mono">{iface.cidr}</td>
                <td className="route-table__dim">directement connecté</td>
                <td className="mono">{link.data.interface}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {routes.map((route, i) => (
        <div key={i} className="row-card">
          <div className="row-card__head">
            <span className="row-card__index">Route statique {i + 1}</span>
            <RemoveButton title="Supprimer la route" onClick={() => onChange(routes.filter((_, j) => j !== i))} />
          </div>
          <TextField
            compact
            mono
            label="Réseau de destination"
            value={route.destination}
            placeholder="10.0.3.0/24"
            error={cidrFieldError(route.destination)}
            onChange={(destination) => updateRoute(i, { destination })}
          />
          <div className="row-card__grid">
            <TextField
              compact
              mono
              label="Passerelle"
              value={route.gateway}
              placeholder="10.0.2.254"
              error={ipFieldError(route.gateway)}
              onChange={(gateway) => updateRoute(i, { gateway })}
            />
            <SelectField
              compact
              label="Sortie"
              value={route.interface}
              options={interfaceOptions}
              onChange={(value) => updateRoute(i, { interface: value })}
            />
          </div>
        </div>
      ))}

      <button type="button" className="btn btn--ghost btn--block" onClick={() => onChange([...routes, { ...EMPTY_ROUTE }])}>
        + Ajouter une route
      </button>
      <p className="panel-hint panel-hint--tight">0.0.0.0/0 comme destination définit la route par défaut.</p>
    </Section>
  );
}
