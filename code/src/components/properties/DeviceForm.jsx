import { AutoButton, IssuesList, Section, SelectField, TextField } from './fields.jsx';
import InterfaceCard from './InterfaceCard.jsx';
import RoutingTableSection from './RoutingTableSection.jsx';
import ServicesSection from './ServicesSection.jsx';
import { DEVICE_TYPES } from '../../config/deviceTypes.js';
import { formatInterface } from '../../utils/ipv4.js';
import { deviceLinks, networkLinks, networkSubnet, nodeName } from '../../utils/topologyQueries.js';
import { ipFieldError, subnetFieldError, vlanFieldError } from '../../utils/validators.js';

/**
 * Formulaire d'un équipement : sections affichées selon son type.
 *
 *            Général   Interfaces   Passerelle   Routage   Ports   Segment
 *   PC          ✓          ✓            ✓
 *   Serveur     ✓          ✓            ✓                     ✓
 *   Routeur     ✓          ✓                        ✓
 *   Switch      ✓ (+VLAN, réseau, équipements reliés)
 *   Sonde IDS   ✓          ✓                                          ✓
 */
export default function DeviceForm({ node, nodes, edges, issues, onChange, onUpdateLink, onDelete }) {
  const { deviceType, properties } = node.data;
  const definition = DEVICE_TYPES[deviceType];
  const links = definition.isNetwork ? [] : deviceLinks(edges, node.id);
  const networkNameOf = (id) => nodeName(nodes, id);

  return (
    <>
      <h2 className="panel-title" style={{ '--device-color': definition.color }}>
        <span className="properties__type-dot" />
        {definition.label}
      </h2>
      <p className="panel-hint">Identifiant : {node.id}</p>

      <IssuesList issues={issues} />

      <TextField
        label="Nom"
        value={properties.name}
        placeholder={`ex. ${definition.namePrefix}-1`}
        error={properties.name.trim() ? null : 'Champ obligatoire'}
        onChange={(name) => onChange({ name })}
      />

      {deviceType === 'switch' && <SwitchSection node={node} nodes={nodes} edges={edges} onChange={onChange} />}

      {!definition.isNetwork && (
        <Section title="Interfaces" count={links.length}>
          {links.length === 0 && (
            <p className="panel-hint panel-hint--tight">Aucune interface : reliez l'équipement à un switch avec l'outil 🔌 Câble.</p>
          )}
          {links.map((link) => (
            <InterfaceCard
              key={link.id}
              edge={link}
              networkName={networkNameOf(link.target)}
              subnet={networkSubnet(nodes, link.target)}
              editableName={deviceType === 'router'}
              ipOptional={deviceType === 'ids'}
              onChange={(patch) => onUpdateLink(link.id, patch)}
            />
          ))}
        </Section>
      )}

      {(deviceType === 'pc' || deviceType === 'server') && (
        <GatewayField
          value={properties.gateway}
          auto={properties.gatewayAuto !== false}
          links={links}
          nodes={nodes}
          edges={edges}
          onChange={onChange}
        />
      )}

      {deviceType === 'server' && <ServicesSection services={properties.services} onChange={(services) => onChange({ services })} />}

      {deviceType === 'router' && (
        <RoutingTableSection
          links={links}
          routes={properties.routes}
          networkNameOf={networkNameOf}
          onChange={(routes) => onChange({ routes })}
        />
      )}

      {deviceType === 'ids' && (
        <Section title="Surveillance">
          <SelectField
            label="Segment surveillé"
            value={properties.monitoredSegment}
            onChange={(monitoredSegment) => onChange({ monitoredSegment })}
            options={[
              { value: '', label: links.length ? '— choisir un switch —' : '— reliez d’abord la sonde à un switch —' },
              ...links.map((l) => ({ value: l.target, label: networkNameOf(l.target) })),
            ]}
          />
          <p className="panel-hint panel-hint--tight">La sonde reçoit une copie de tout le trafic circulant sur ce switch.</p>
        </Section>
      )}

      <button type="button" className="btn btn--danger btn--block" onClick={onDelete}>
        Supprimer l'équipement
      </button>
    </>
  );
}

/**
 * Passerelle par défaut (PC, serveur).
 * Automatique : adresse du routeur relié au même switch (voir utils/ipam.js).
 * Saisie manuelle possible, avec les adresses des routeurs voisins en suggestion.
 */
function GatewayField({ value, auto, links, nodes, edges, onChange }) {
  const listId = `gateways-${links[0]?.source ?? 'none'}`;
  const switchIds = new Set(links.map((l) => l.target));
  const suggestions = edges.filter(
    (e) => switchIds.has(e.target) && e.data.ip && nodes.find((n) => n.id === e.source)?.data.deviceType === 'router',
  );

  return (
    <Section title="Passerelle par défaut">
      <TextField
        mono
        value={value}
        placeholder={auto ? 'aucun routeur sur ce réseau' : suggestions[0]?.data.ip ?? 'ex. 192.168.1.1'}
        list={listId}
        error={ipFieldError(value)}
        hint={
          auto
            ? 'Automatique : routeur relié au même switch.'
            : 'Routeur vers lequel envoyer le trafic destiné aux autres réseaux.'
        }
        onChange={(gateway) => onChange({ gateway, gatewayAuto: false })}
      />
      {!auto && <AutoButton onClick={() => onChange({ gatewayAuto: true })} />}
      <datalist id={listId}>
        {suggestions.map((e) => (
          <option key={e.id} value={e.data.ip}>
            {nodeName(nodes, e.source)} ({e.data.interface})
          </option>
        ))}
      </datalist>
    </Section>
  );
}

const byPort = (a, b) => (a.data.port ?? '').localeCompare(b.data.port ?? '', undefined, { numeric: true });

/** Switch : réseau des équipements branchés (adressage automatique), VLAN, ports occupés. */
function SwitchSection({ node, nodes, edges, onChange }) {
  const links = networkLinks(edges, node.id);
  const { subnet } = node.data.properties;

  return (
    <>
      <TextField
        label="Réseau des équipements branchés"
        mono
        value={subnet}
        placeholder="ex. 10.0.1.0/24"
        error={subnetFieldError(subnet)}
        hint="Le switch n'a pas d'adresse IP : c'est le réseau (LAN) des équipements qui y sont branchés. Ils en reçoivent automatiquement une adresse (routeurs : .1, .2… ; autres : à partir de .10)."
        onChange={(value) => onChange({ subnet: value.trim() })}
      />
      <TextField
        label="VLAN (optionnel)"
        value={node.data.properties.vlan}
        placeholder="ex. 10"
        error={vlanFieldError(node.data.properties.vlan)}
        onChange={(vlan) => onChange({ vlan: vlan.replace(/\D/g, '') })}
      />
      <Section title="Ports" count={links.length}>
        <ul className="attached">
          {[...links].sort(byPort).map((l) => (
            <li key={l.id}>
              <span>
                <span className="attached__port">{l.data.port}</span> → {nodeName(nodes, l.source)}{' '}
                <span className="attached__iface">{l.data.interface}</span>
              </span>
              <span className="mono">{l.data.ip ? formatInterface(l.data.ip, l.data.mask) : '—'}</span>
            </li>
          ))}
        </ul>
      </Section>
    </>
  );
}
