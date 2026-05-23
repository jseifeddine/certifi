import { Navigate, Route, Routes } from 'react-router-dom';
import { RequireAuth, RequirePermission } from './auth';
import { Layout } from './components/Layout';
import { perms } from './lib/perms';
import { Audit } from './pages/Audit';
import { CertificateDetail } from './pages/CertificateDetail';
import { CertificateNew } from './pages/CertificateNew';
import { Certificates } from './pages/Certificates';
import { Docs } from './pages/Docs';
import { Login } from './pages/Login';
import { Roles } from './pages/Roles';
import { Security } from './pages/Security';
import { Settings, SettingsAcme, SettingsIntegrations, SettingsPassword } from './pages/Settings';
import { Sso } from './pages/Sso';
import { Tokens } from './pages/Tokens';
import { Users } from './pages/Users';

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route
        element={
          <RequireAuth>
            <Layout />
          </RequireAuth>
        }
      >
        <Route index element={<Navigate to="/certificates" replace />} />
        <Route path="/certificates" element={<Certificates />} />
        <Route path="/certificates/new" element={<CertificateNew />} />
        <Route path="/certificates/:id" element={<CertificateDetail />} />
        <Route path="/tokens" element={<Tokens />} />
        <Route path="/security" element={<Security />} />
        <Route path="/settings" element={<Settings />}>
          <Route index element={<Navigate to="acme" replace />} />
          <Route path="acme" element={<SettingsAcme />} />
          <Route path="integrations" element={<SettingsIntegrations />} />
          <Route path="password" element={<SettingsPassword />} />
          <Route
            path="users"
            element={<RequirePermission perm={perms.USER_LIST}><Users /></RequirePermission>}
          />
          <Route
            path="roles"
            element={<RequirePermission perm={perms.ROLE_LIST}><Roles /></RequirePermission>}
          />
          <Route
            path="sso"
            element={<RequirePermission perm={perms.SETTINGS_READ}><Sso /></RequirePermission>}
          />
          <Route
            path="audit"
            element={<RequirePermission perm={perms.AUDIT_READ}><Audit /></RequirePermission>}
          />
        </Route>
        {/* Backwards-compat redirects — old top-level URLs land on the
            corresponding settings tab so existing bookmarks keep working. */}
        <Route path="/users"  element={<Navigate to="/settings/users"  replace />} />
        <Route path="/roles"  element={<Navigate to="/settings/roles"  replace />} />
        <Route path="/sso"    element={<Navigate to="/settings/sso"    replace />} />
        <Route path="/audit"  element={<Navigate to="/settings/audit"  replace />} />
        <Route path="/docs" element={<Docs />} />
        <Route path="/docs/:slug" element={<Docs />} />
        <Route path="*" element={<Navigate to="/certificates" replace />} />
      </Route>
    </Routes>
  );
}
