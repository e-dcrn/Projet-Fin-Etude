/**
 * Légende des paquets animés (mode « paquets »), posée sur le canvas. Tout est à
 * vitesse réelle (×1) : la couleur d'une boule indique le protocole. Voir
 * useSimulation / SimulationLayer.
 */
export default function SimulationControls() {
  return (
    <div className="sim-controls nokey">
      <div className="sim-controls__head"><strong>Paquets en temps réel</strong></div>
      <div className="sim-legend">
        <span className="sim-legend__item"><span className="sim-dot sim-dot--tcp" /> TCP</span>
        <span className="sim-legend__item"><span className="sim-dot sim-dot--icmp" /> ICMP</span>
        <span className="sim-legend__item"><span className="sim-dot sim-dot--udp" /> UDP</span>
        <span className="sim-legend__item"><span className="sim-dot sim-dot--arp" /> ARP</span>
      </div>
    </div>
  );
}
