import { api } from './client';
import type { Settings, SettingsUpdate } from '../types';

export const settingsApi = {
  get: () => api.get<Settings>('/api/settings'),
  update: (body: SettingsUpdate) => api.put<{ ok: true }>('/api/settings', body),
  registerAcme: () => api.post<{ ok: true; account_url: string }>('/api/settings/acme/register'),
};
