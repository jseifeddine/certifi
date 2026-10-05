import { useEffect, useState } from 'react';
import { api } from './client';
import type { KeyAlgorithms } from '../types';

export const keyAlgorithmsApi = {
  list: () => api.get<KeyAlgorithms>('/api/key-algorithms'),
};

/** The server's supported key algorithms; `null` until loaded or on error. */
export function useKeyAlgorithms(): KeyAlgorithms | null {
  const [algos, setAlgos] = useState<KeyAlgorithms | null>(null);
  useEffect(() => {
    let cancelled = false;
    keyAlgorithmsApi.list()
      .then((data) => { if (!cancelled) setAlgos(data); })
      .catch(() => {});
    return () => { cancelled = true; };
  }, []);
  return algos;
}

/** Display label for a key algorithm id, falling back to the raw id. */
export function keyAlgoLabel(algos: KeyAlgorithms | null, id: string | null): string {
  if (!id) return '—';
  return algos?.algorithms.find((a) => a.id === id)?.label ?? id;
}
