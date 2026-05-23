/**
 * Permission keys mirrored from the Rust `rbac::perms` module. Use these
 * constants instead of hardcoded strings so a typo in a route gate becomes
 * a TypeScript error at the call site.
 *
 * The server is the source of truth; this file is here so the SPA can hide
 * affordances the user can't act on. Real authorization still happens on
 * each API request.
 */
export const perms = {
  CERTIFICATE_LIST:     'certificate.list',
  CERTIFICATE_READ:     'certificate.read',
  CERTIFICATE_CREATE:   'certificate.create',
  CERTIFICATE_RENEW:    'certificate.renew',
  CERTIFICATE_UPDATE:   'certificate.update',
  CERTIFICATE_DELETE:   'certificate.delete',
  CERTIFICATE_DOWNLOAD: 'certificate.download',

  TOKEN_MANAGE_ALL: 'token.manage_all',

  USER_LIST:            'user.list',
  USER_CREATE:          'user.create',
  USER_UPDATE:          'user.update',
  USER_DELETE:          'user.delete',
  USER_PASSWORD_UPDATE: 'user.password.update',

  INTEGRATION_LIST:    'integration.list',
  INTEGRATION_READ:    'integration.read',
  INTEGRATION_CREATE:  'integration.create',
  INTEGRATION_UPDATE:  'integration.update',
  INTEGRATION_DELETE:  'integration.delete',
  INTEGRATION_TEST:    'integration.test',

  SETTINGS_READ:          'settings.read',
  SETTINGS_UPDATE:        'settings.update',
  SETTINGS_ACME_REGISTER: 'settings.acme.register',

  DOMAIN_LIST: 'domain.list',

  ROLE_LIST:   'role.list',
  ROLE_CREATE: 'role.create',
  ROLE_UPDATE: 'role.update',
  ROLE_DELETE: 'role.delete',
  ROLE_ASSIGN: 'role.assign',

  AUDIT_READ: 'audit.read',
} as const;

export type PermissionKey = (typeof perms)[keyof typeof perms];

/** True iff the supplied permission list contains the given key. */
export function hasPerm(permissions: readonly string[] | undefined, key: PermissionKey): boolean {
  return !!permissions && permissions.includes(key);
}
