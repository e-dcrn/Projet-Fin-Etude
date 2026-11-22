import * as api from '../services/topologyApi.js';
import { useRecords } from './useRecords.js';

const MODELS_API = {
  list: api.fetchModels,
  start: api.startTraining,
  remove: api.deleteModel,
  listKey: 'models',
};

/**
 * Modèles ML-IDS entraînés (voir backend/app/training.py) : modèles sauvegardés
 * et entraînement d'un nouveau modèle (voir useRecords pour `run`).
 */
export function useModels(active) {
  const records = useRecords(active, MODELS_API);
  return {
    ...records,
    models: records.records,
    train: records.start,
    fileUrl: api.modelFileUrl,
  };
}
