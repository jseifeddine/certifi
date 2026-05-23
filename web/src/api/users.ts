import { api } from './client';
import type { User } from '../types';

export interface CreateUserRequest {
  username: string;
  password: string;
  email?: string;
  is_admin?: boolean;
}

export interface UpdateUserRequest {
  email?: string | null;
  is_admin?: boolean;
}

export const usersApi = {
  list: () => api.get<User[]>('/api/users'),
  create: (req: CreateUserRequest) => api.post<User>('/api/users', req),
  update: (id: string, req: UpdateUserRequest) => api.put<User>(`/api/users/${id}`, req),
  delete: (id: string) => api.delete<{ ok: true }>(`/api/users/${id}`),
  changePassword: (id: string, newPassword: string) =>
    api.put<{ ok: true }>(`/api/users/${id}/password`, { new_password: newPassword }),
};
