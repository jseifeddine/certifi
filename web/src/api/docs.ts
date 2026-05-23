import { api, ApiError, getToken } from './client';

export type DocSummary = { slug: string; title: string };

export const docsApi = {
  list: () => api.get<DocSummary[]>('/api/docs'),

  /**
   * The doc endpoint returns raw markdown, not JSON, so it can't reuse the
   * shared `api.get` helper (which always tries to JSON.parse). We send the
   * Authorization header only if we happen to have one — the endpoint is
   * unauthenticated but a bearer token is harmless.
   */
  async raw(slug: string): Promise<string> {
    const token = getToken();
    const res = await fetch(`/api/docs/${slug}`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
    if (!res.ok) throw new ApiError(`Doc '${slug}' not found`, res.status);
    return res.text();
  },
};
