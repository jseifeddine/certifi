const TOKEN_KEY = 'certifi.token';

export class ApiError extends Error {
  constructor(message: string, public status: number) {
    super(message);
  }
}

let onUnauthorized: (() => void) | null = null;

export function setOnUnauthorized(fn: () => void) {
  onUnauthorized = fn;
}

export function getToken(): string | null {
  return sessionStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string) {
  sessionStorage.setItem(TOKEN_KEY, token);
}

export function clearToken() {
  sessionStorage.removeItem(TOKEN_KEY);
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  const hadToken = !!getToken();
  if (hadToken) headers['Authorization'] = `Bearer ${getToken()}`;

  const res = await fetch(path, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

  const text = await res.text();
  const data = text ? safeParse(text) : null;
  const bodyMessage =
    data && typeof data === 'object' && 'error' in data
      ? String((data as Record<string, unknown>).error)
      : null;

  // A 401 means two very different things depending on whether we had a token:
  //   - With token  → the JWT was rejected. The session expired (or the secret
  //                   rotated). Clear it and bounce to login.
  //   - No token    → this is a login attempt against /api/auth/login (or any
  //                   unauthenticated endpoint). Surface the real message so
  //                   the user sees "Invalid username or password" instead of
  //                   the misleading "Session expired".
  if (res.status === 401 && hadToken) {
    clearToken();
    onUnauthorized?.();
    throw new ApiError('Session expired', 401);
  }

  if (!res.ok) {
    throw new ApiError(bodyMessage || `HTTP ${res.status}`, res.status);
  }

  return data as T;
}

function safeParse(s: string): unknown {
  try { return JSON.parse(s); } catch { return null; }
}

export const api = {
  get: <T>(path: string) => request<T>('GET', path),
  post: <T>(path: string, body?: unknown) => request<T>('POST', path, body),
  put: <T>(path: string, body?: unknown) => request<T>('PUT', path, body),
  delete: <T>(path: string) => request<T>('DELETE', path),
  async downloadBlob(path: string): Promise<Blob> {
    const token = getToken();
    const res = await fetch(path, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
    if (!res.ok) throw new ApiError('Download failed', res.status);
    return res.blob();
  },
};

export function saveBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
