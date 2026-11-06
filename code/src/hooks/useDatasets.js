import * as api from '../services/topologyApi.js';
import { useRecords } from './useRecords.js';

const DATASETS_API = {
  list: api.fetchDatasets,
  start: api.startDataset,
  follow: api.followDatasetJob,
  cancel: api.cancelDatasetJob,
  remove: api.deleteDataset,
  listKey: 'datasets',
  resultKey: 'dataset',
};

/**
 * Datasets étiquetés (voir backend/app/datasets.py) : datasets sauvegardés et
 * génération d'un nouveau dataset (voir useRecords pour `run`).
 */
export function useDatasets(active) {
  const records = useRecords(active, DATASETS_API);
  return { ...records, datasets: records.records, generate: records.start, fileUrl: api.datasetFileUrl };
}
