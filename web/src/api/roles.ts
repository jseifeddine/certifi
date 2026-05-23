import { api } from './client';
import type { PermissionView, RoleAssignmentView, RoleView } from '../types';

export type Role = RoleView;
export type Permission = PermissionView;

export const rolesApi = {
  list: () => api.get<RoleView[]>('/api/roles'),
  listPermissions: () => api.get<PermissionView[]>('/api/permissions'),
  create: (req: { name: string; description?: string; permissions: string[] }) =>
    api.post<RoleView>('/api/roles', req),
  delete: (id: string) => api.delete<{ ok: true }>(`/api/roles/${id}`),

  listAssignments: (userId: string) =>
    api.get<RoleAssignmentView[]>(`/api/users/${userId}/roles`),
  assign: (userId: string, req: { role_id: string; scope?: string }) =>
    api.post<RoleAssignmentView>(`/api/users/${userId}/roles`, req),
  revoke: (userId: string, assignmentId: string) =>
    api.delete<{ ok: true }>(`/api/users/${userId}/roles/${assignmentId}`),
};
