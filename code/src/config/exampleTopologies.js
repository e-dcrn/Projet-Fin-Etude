/**
 * Topologies d'exemple, chargeables en un clic depuis la barre d'outils.
 *
 * Chaque exemple est un fichier JSON de examples/topologies/ : une topologie au
 * format de serializeTopology (version, nodes, networks, links), complétée d'un
 * bloc de présentation ignoré au chargement :
 *
 *   "example": { "name": "…", "description": "…", "difficulty": "débutant" }
 *
 * Pour ajouter un exemple, il suffit d'y déposer un nouveau fichier : l'ordre du
 * menu est celui des noms de fichiers (d'où le préfixe 01-, 02-…).
 */

export const DIFFICULTIES = {
  débutant: { label: 'Débutant', className: 'difficulty--easy' },
  intermédiaire: { label: 'Intermédiaire', className: 'difficulty--medium' },
  avancé: { label: 'Avancé', className: 'difficulty--hard' },
};

const files = import.meta.glob('/examples/topologies/*.json', { eager: true, import: 'default' });

export const EXAMPLE_TOPOLOGIES = Object.entries(files)
  .sort(([a], [b]) => a.localeCompare(b, undefined, { numeric: true }))
  .map(([path, topology]) => ({
    id: path.split('/').pop().replace(/\.json$/, ''),
    name: topology.example?.name ?? path.split('/').pop(),
    description: topology.example?.description ?? '',
    difficulty: topology.example?.difficulty ?? '',
    topology,
  }));
