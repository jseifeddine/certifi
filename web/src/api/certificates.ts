import { api } from './client';
import type { Certificate, CreateCertRequest, PemBundle, PfxResponse } from '../types';

export const certsApi = {
  list: () => api.get<Certificate[]>('/api/certificates'),
  get: (id: string) => api.get<Certificate>(`/api/certificates/${id}`),
  create: (req: CreateCertRequest) => api.post<Certificate>('/api/certificates', req),
  renew: (id: string) => api.post<Certificate>(`/api/certificates/${id}/renew`),
  delete: (id: string) => api.delete<{ ok: true }>(`/api/certificates/${id}`),
  setAutoRenew: (id: string, autoRenew: boolean) =>
    api.put<{ ok: true }>(`/api/certificates/${id}/auto-renew`, { auto_renew: autoRenew }),
  setDescription: (id: string, description: string | null) =>
    api.put<{ ok: true }>(`/api/certificates/${id}/description`, { description }),
  pemBundle: (id: string) => api.get<PemBundle>(`/api/certificates/${id}/pem`),
  generatePfx: (id: string) => api.post<PfxResponse>(`/api/certificates/${id}/download/pfx`),
};

export const certDownloadPath = (id: string, kind: 'fullchain' | 'privkey' | 'cert' | 'chain') =>
  `/api/certificates/${id}/download/${kind}.pem`;
