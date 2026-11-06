import * as api from '../services/topologyApi.js';
import { useRecords } from './useRecords.js';

const MODELS_API = {
  list: api.fetchModels,
  start: api.startTraining,
  follow: api.followTrainingJob,
  cancel: api.cancelTrainingJob,
  remove: api.deleteModel,
  listKey: 'models',
  resultKey: 'model',
};

const NO_OPTIONS = { models: [], modes: [], splits: [] };

/**
 * Modèles ML-IDS entraînés (voir backend/app/training.py) : modèles sauvegardés
 * et entraînement d'un nouveau modèle (voir useRecords pour `run`).
 */
export function useModels(active) {
  const records = useRecords(active, MODELS_API);
  return {
    ...records,
    models: records.records,
    options: records.info.options ?? NO_OPTIONS,
    train: records.start,
    fileUrl: api.modelFileUrl,
  };
}
