import { api } from './client';
import type { Token, CreatedToken } from '../types';

export interface CreateTokenRequest {
  name: string;
  expires_at?: string;
  /** Optional permission ceiling. Omit to inherit the issuing user's set. */
  permissions?: string[];
}

export const tokensApi = {
  list: () => api.get<Token[]>('/api/tokens'),
  create: (req: CreateTokenRequest) =>
    api.post<CreatedToken>('/api/tokens', {
      name: req.name,
      expires_at: req.expires_at || undefined,
      permissions: req.permissions,
    }),
  delete: (id: string) => api.delete<{ ok: true }>(`/api/tokens/${id}`),
};
