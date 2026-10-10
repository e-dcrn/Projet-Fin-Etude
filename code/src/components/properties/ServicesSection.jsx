import { RemoveButton, Section, SelectField, TextField } from './fields.jsx';
import { SERVICE_PRESETS } from '../../config/deviceTypes.js';
import { portFieldError } from '../../utils/validators.js';

const PROTOCOL_OPTIONS = [
  { value: 'tcp', label: 'TCP' },
  { value: 'udp', label: 'UDP' },
];

/**
 * Ports ouverts d'un serveur, avec le service associé.
 * L'ajout se fait depuis une liste de services courants (port pré-rempli)
 * ou en « Autre » pour un service personnalisé.
 */
export default function ServicesSection({ services, onChange }) {
  const updateService = (index, patch) => onChange(services.map((s, i) => (i === index ? { ...s, ...patch } : s)));

  const addService = (presetName) => {
    const preset = SERVICE_PRESETS.find((p) => p.name === presetName);
    const service = preset
      ? { name: preset.name, port: preset.port, protocol: preset.protocol }
      : { name: '', port: '', protocol: 'tcp' };
    onChange([...services, service]);
  };

  const usedPorts = new Set(services.map((s) => `${s.port}/${s.protocol}`));

  return (
    <Section title="Ports ouverts" count={services.length}>
      {services.length === 0 && <p className="panel-hint panel-hint--tight">Aucun service : le serveur ne répond sur aucun port.</p>}

      {services.length > 0 && (
        <div className="services">
          <div className="services__row services__row--head">
            <span>Service</span>
            <span>Port</span>
            <span>Proto.</span>
            <span />
          </div>
          {services.map((service, i) => (
            <div key={i} className="services__row">
              <TextField compact value={service.name} placeholder="nom" list="service-names" onChange={(name) => updateService(i, { name })} />
              <TextField
                compact
                mono
                value={String(service.port)}
                error={Boolean(portFieldError(service.port))}
                onChange={(port) => updateService(i, { port: port.replace(/\D/g, '') })}
              />
              <SelectField compact value={service.protocol} options={PROTOCOL_OPTIONS} onChange={(protocol) => updateService(i, { protocol })} />
              <RemoveButton title="Fermer ce port" onClick={() => onChange(services.filter((_, j) => j !== i))} />
            </div>
          ))}
        </div>
      )}

      <datalist id="service-names">
        {SERVICE_PRESETS.map((p) => (
          <option key={p.name} value={p.name} />
        ))}
      </datalist>

      <select className="field__input add-select" value="" onChange={(e) => addService(e.target.value)}>
        <option value="" disabled>
          + Ouvrir un port…
        </option>
        {SERVICE_PRESETS.map((p) => (
          <option key={p.name} value={p.name} disabled={usedPorts.has(`${p.port}/${p.protocol}`)}>
            {p.label} — {p.port}/{p.protocol}
          </option>
        ))}
        <option value="__custom">Autre service…</option>
      </select>
    </Section>
  );
}
