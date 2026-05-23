/**
 * App identity surfaced in the UI — running version + canonical GitHub links.
 *
 * The version is the one compiled into the server binary (Cargo workspace
 * version), read at runtime from `GET /api/health`. Cutting a release bumps
 * that one version and every link below re-points itself, so the footer always
 * references the release and docs that ship with the running build.
 */

import { useEffect, useState } from 'react';
import { api } from '../api/client';

/** Canonical repository URL. */
export const REPO_URL = 'https://github.com/jseifeddine/certifi';

/** This version's GitHub release page (the `vX.Y.Z` tag). */
export const releaseUrl = (version: string) => `${REPO_URL}/releases/tag/v${version}`;

/**
 * Documentation for THIS version — pinned to the matching git tag so the link
 * resolves to the docs that shipped with the running build, not whatever `main`
 * happens to be. (The tag is created as part of cutting the release.)
 */
export const docsUrl = (version: string) => `${REPO_URL}/tree/v${version}/docs`;

/**
 * Fetch the running server version from `/api/health`. Returns `null` until it
 * loads (or if health is unreachable) so callers can hide the version
 * gracefully rather than render a broken link.
 */
export function useAppVersion(): string | null {
  const [version, setVersion] = useState<string | null>(null);
  useEffect(() => {
    let active = true;
    api
      .get<{ version: string }>('/api/health')
      .then((h) => {
        if (active) setVersion(h.version);
      })
      .catch(() => {
        /* footer simply omits the version if health can't be reached */
      });
    return () => {
      active = false;
    };
  }, []);
  return version;
}
