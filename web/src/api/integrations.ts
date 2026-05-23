import { api } from './client';
import type {
  CreateIntegrationRequest,
  Integration,
  IntegrationListResponse,
  IntegrationTestResult,
  UpdateIntegrationRequest,
} from '../types';

export const integrationsApi = {
  list: () => api.get<IntegrationListResponse>('/api/integrations'),
  get: (id: string) => api.get<Integration>(`/api/integrations/${id}`),
  create: (req: CreateIntegrationRequest) =>
    api.post<Integration>('/api/integrations', req),
  update: (id: string, req: UpdateIntegrationRequest) =>
    api.put<Integration>(`/api/integrations/${id}`, req),
  delete: (id: string) => api.delete<{ ok: true }>(`/api/integrations/${id}`),
  test: (id: string) => api.post<IntegrationTestResult>(`/api/integrations/${id}/test`),
};

/** Sentinel returned by the server in place of secret config values. */
export const SECRET_MASK = '***';
