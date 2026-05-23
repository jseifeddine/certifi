import { api } from './client';

export const domainsApi = {
  list: () => api.get<string[]>('/api/domains'),
};
