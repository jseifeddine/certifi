import { useEffect, useMemo, useState } from 'react';
import { Outlet } from 'react-router-dom';
import { useAuth } from '../auth';
import { integrationsApi, SECRET_MASK } from '../api/integrations';
import { settingsApi } from '../api/settings';
import { usersApi } from '../api/users';
import { useConfirm } from '../components/ConfirmDialog';
import { Check, Plus, RefreshCw, Trash2 } from 'lucide-react';
const IconCheck   = (p: React.SVGProps<SVGSVGElement>) => <Check     className="h-4 w-4" {...p} />;
const IconPlus    = (p: React.SVGProps<SVGSVGElement>) => <Plus      className="h-4 w-4" {...p} />;
const IconRefresh = (p: React.SVGProps<SVGSVGElement>) => <RefreshCw className="h-4 w-4" {...p} />;
const IconTrash   = (p: React.SVGProps<SVGSVGElement>) => <Trash2    className="h-4 w-4" {...p} />;
import { usePageTitle } from '../components/Layout';
import { Modal } from '../components/Modal';
import { useToast } from '../components/Toast';
import type {
  Integration,
  IntegrationField,
  IntegrationListResponse,
  IntegrationMeta,
  Settings as SettingsType,
  SettingsUpdate,
} from '../types';

/**
 * The /settings path is just a pass-through now — each sub-route has its
 * own sidebar entry under "Admin settings", so the old in-page tab strip
 * is redundant. Sub-pages own their own `<header>` block.
 */
export function Settings() {
  usePageTitle('Settings');
  return <Outlet />;
}

// ── Public tab wrappers — each fetches its own data so the routes can be
//    mounted independently of any parent state. ─────────────────────────────

export function SettingsAcme() {
  const [settings, setSettings] = useState<SettingsType | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [reload, setReload] = useState(0);
  useEffect(() => {
    settingsApi.get()
      .then(setSettings)
      .catch((ex) => setError(ex instanceof Error ? ex.message : 'Failed to load'));
  }, [reload]);
  if (error) return <div className="alert alert-error">{error}</div>;
  if (!settings) return <div className="flex items-center gap-2 text-muted"><span className="spinner" /> Loading...</div>;
  return <AcmeTab settings={settings} onReload={() => setReload((r) => r + 1)} />;
}

export function SettingsIntegrations() {
  return <IntegrationTab />;
}

export function SettingsPassword() {
  return <PasswordTab />;
}

function LockedHint({ envVar }: { envVar: string }) {
  return (
    <div className="text-[11px] text-warn mt-1">
      Locked — set via <code className="font-mono">{envVar}</code> environment variable
    </div>
  );
}

function LockBadge() {
  return <span className="text-[10px] text-warn font-normal ml-1">🔒 env</span>;
}

function AcmeTab({ settings, onReload }: { settings: SettingsType; onReload: () => void }) {
  const confirm = useConfirm();
  const locked = settings.locked;
  const acmeCaLocked = locked.includes('acme_ca');
  const [acmeCa, setAcmeCa] = useState(settings.acme_ca);
  const [keyAlgo, setKeyAlgo] = useState(settings.key_algo);
  const [msg, setMsg] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null);
  const [registering, setRegistering] = useState(false);

  async function save() {
    const body: SettingsUpdate = {};
    if (!acmeCaLocked) body.acme_ca = acmeCa;
    body.key_algo = keyAlgo;
    try {
      await settingsApi.update(body);
      setMsg({ kind: 'ok', text: 'ACME settings saved' });
      setTimeout(() => setMsg(null), 3000);
    } catch (ex) {
      setMsg({ kind: 'err', text: ex instanceof Error ? ex.message : 'Failed' });
    }
  }

  async function register() {
    const ok = await confirm({
      title: settings.acme_registered ? 'Re-register ACME account' : 'Register ACME account',
      body: 'This will create a new ACME account at the configured CA (or re-register). Existing certificates will continue to work.',
      confirmLabel: settings.acme_registered ? 'Re-register' : 'Register',
    });
    if (!ok) return;
    setRegistering(true);
    try {
      const res = await settingsApi.registerAcme();
      setMsg({ kind: 'ok', text: `ACME account registered: ${res.account_url}` });
      setTimeout(onReload, 1500);
    } catch (ex) {
      setMsg({ kind: 'err', text: ex instanceof Error ? ex.message : 'Failed' });
    } finally {
      setRegistering(false);
    }
  }

  return (
    <div className="table-wrap p-6 max-w-[600px]">
      {msg && <div className={msg.kind === 'ok' ? 'alert alert-success' : 'alert alert-error'}>{msg.text}</div>}

      <div className="flex items-center gap-3 px-4 py-3.5 bg-surface3 border border-border rounded-md mb-4">
        <div>
          {settings.acme_registered
            ? <span className="badge badge-ok"><IconCheck /> Registered</span>
            : <span className="badge badge-muted">Not registered</span>}
        </div>
        <div className="flex-1">
          <strong className="block text-[13px]">{settings.acme_registered ? 'ACME account active' : 'No ACME account'}</strong>
          <span className="text-[12px] text-muted break-all">
            {settings.acme_registered ? settings.acme_account_url : 'Register to start issuing certificates'}
          </span>
        </div>
        <button
          className={`btn btn-sm ${settings.acme_registered ? 'btn-warning' : 'btn-primary'}`}
          onClick={register}
          disabled={registering}
        >
          {registering
            ? <span className="spinner" />
            : settings.acme_registered ? <><IconRefresh /> Re-register</> : <><IconPlus /> Register</>}
        </button>
      </div>

      <div className="mb-4">
        <label className="block text-[13px] font-medium text-muted mb-1.5">
          ACME CA Directory URL{acmeCaLocked && <LockBadge />}
        </label>
        <input value={acmeCa} name="acme-ca-url" disabled={acmeCaLocked} onChange={(e) => setAcmeCa(e.target.value)} className={acmeCaLocked ? 'opacity-60' : ''} autoComplete="off" data-1p-ignore data-lpignore="true" />
        {acmeCaLocked
          ? <LockedHint envVar="ACME_CA_URL" />
          : (
            <div className="text-[11px] text-dim mt-1">
              Let's Encrypt Production: https://acme-v02.api.letsencrypt.org/directory<br />
              Let's Encrypt Staging: https://acme-staging-v02.api.letsencrypt.org/directory
            </div>
          )}
      </div>

      <div className="mb-4">
        <label className="block text-[13px] font-medium text-muted mb-1.5">Key Algorithm</label>
        <select value={keyAlgo} onChange={(e) => setKeyAlgo(e.target.value)} autoComplete="off">
          <option value="ec-p384">ECDSA P-384 (recommended)</option>
          <option value="ec-p256">ECDSA P-256</option>
        </select>
      </div>

      <button className="btn btn-primary" onClick={save}>Save Settings</button>
    </div>
  );
}

function IntegrationTab() {
  const toast = useToast();
  const confirm = useConfirm();
  const [data, setData] = useState<IntegrationListResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [reload, setReload] = useState(0);
  const [editing, setEditing] = useState<Integration | null>(null);
  const [creatingKind, setCreatingKind] = useState<string | null>(null);
  const [pickerOpen, setPickerOpen] = useState(false);
  const [testingId, setTestingId] = useState<string | null>(null);

  useEffect(() => {
    integrationsApi
      .list()
      .then(setData)
      .catch((ex) => setError(ex instanceof Error ? ex.message : 'Failed to load'));
  }, [reload]);

  // Detect zone-suffix overlap between providers. Cheap heuristic: an
  // integration's NAME suggests its zone, but the real answer comes from
  // a /test call. We don't auto-test on load — but we do detect when two
  // integrations of the same kind exist (rare but worth warning about).
  const dupeKindWarning = useMemo(() => {
    if (!data) return null;
    const seen: Record<string, number> = {};
    for (const i of data.integrations) {
      if (!i.enabled) continue;
      seen[i.kind] = (seen[i.kind] ?? 0) + 1;
    }
    const dupes = Object.entries(seen).filter(([_, n]) => n > 1).map(([k]) => k);
    if (dupes.length === 0) return null;
    return `Multiple integrations of the same kind are configured (${dupes.join(', ')}). The first match by creation order wins when zones overlap.`;
  }, [data]);

  async function handleDelete(i: Integration) {
    const ok = await confirm({
      title: 'Delete integration',
      body: `Delete "${i.name}"? Certificates that depend on it will fail to renew until you reconfigure.`,
      confirmLabel: 'Delete',
      danger: true,
    });
    if (!ok) return;
    try {
      await integrationsApi.delete(i.id);
      toast.success(`Deleted ${i.name}`);
      setReload((r) => r + 1);
    } catch (ex) {
      toast.error('Delete failed: ' + (ex instanceof Error ? ex.message : ex));
    }
  }

  async function handleToggle(i: Integration) {
    try {
      await integrationsApi.update(i.id, { enabled: !i.enabled });
      setReload((r) => r + 1);
    } catch (ex) {
      toast.error('Toggle failed: ' + (ex instanceof Error ? ex.message : ex));
    }
  }

  async function handleTest(i: Integration) {
    setTestingId(i.id);
    try {
      const res = await integrationsApi.test(i.id);
      toast.success(`${i.name}: ${res.zone_count} zone(s) — ${res.zones.slice(0, 5).join(', ')}${res.zones.length > 5 ? '…' : ''}`);
    } catch (ex) {
      toast.error(`${i.name}: ${ex instanceof Error ? ex.message : ex}`);
    } finally {
      setTestingId(null);
    }
  }

  if (error) return <div className="alert alert-error">{error}</div>;
  if (!data) return <div className="flex items-center gap-2 text-muted"><span className="spinner" /> Loading...</div>;

  const kindByIdMap: Record<string, IntegrationMeta> = Object.fromEntries(
    data.available_kinds.map((k) => [k.id, k]),
  );

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <div>
          <h2 className="text-base font-semibold">DNS Integrations</h2>
          <p className="text-[12px] text-muted mt-0.5">
            Configure one or more authoritative DNS providers. Zones from all enabled integrations are unioned;
            the first integration whose zone covers a requested domain handles the ACME DNS-01 challenge.
          </p>
        </div>
        <button className="btn btn-primary" onClick={() => setPickerOpen(true)}>
          <IconPlus /> Add Integration
        </button>
      </div>

      {dupeKindWarning && (
        <div className="alert alert-warning">{dupeKindWarning}</div>
      )}

      {data.integrations.length === 0 ? (
        <div className="text-center py-16 text-muted border border-dashed border-border rounded-lg">
          <p className="text-base mb-1">No DNS integrations configured yet.</p>
          <p className="text-[12px]">Add one to start issuing certificates.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {data.integrations.map((i) => (
            <IntegrationCard
              key={i.id}
              integration={i}
              kindLabel={kindByIdMap[i.kind]?.name ?? i.kind}
              testing={testingId === i.id}
              onEdit={() => setEditing(i)}
              onDelete={() => handleDelete(i)}
              onToggle={() => handleToggle(i)}
              onTest={() => handleTest(i)}
            />
          ))}
        </div>
      )}

      {pickerOpen && (
        <KindPicker
          kinds={data.available_kinds}
          onPick={(kind) => { setPickerOpen(false); setCreatingKind(kind); }}
          onClose={() => setPickerOpen(false)}
        />
      )}
      {creatingKind && (
        <IntegrationFormModal
          mode="create"
          meta={kindByIdMap[creatingKind]}
          initial={null}
          onSave={async (body) => {
            await integrationsApi.create({ ...body, kind: creatingKind });
            setCreatingKind(null);
            setReload((r) => r + 1);
            toast.success('Integration added');
          }}
          onClose={() => setCreatingKind(null)}
        />
      )}
      {editing && (
        <IntegrationFormModal
          mode="edit"
          meta={kindByIdMap[editing.kind]}
          initial={editing}
          onSave={async (body) => {
            await integrationsApi.update(editing.id, body);
            setEditing(null);
            setReload((r) => r + 1);
            toast.success('Integration updated');
          }}
          onClose={() => setEditing(null)}
        />
      )}
    </div>
  );
}

function IntegrationCard({
  integration, kindLabel, testing, onEdit, onDelete, onToggle, onTest,
}: {
  integration: Integration;
  kindLabel: string;
  testing: boolean;
  onEdit: () => void;
  onDelete: () => void;
  onToggle: () => void;
  onTest: () => void;
}) {
  return (
    <div className="bg-bg border border-border rounded-lg p-4 flex flex-col gap-3">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="font-semibold truncate">{integration.name}</div>
          <div className="text-[12px] text-muted">{kindLabel}</div>
        </div>
        <span className={`badge ${integration.enabled ? 'badge-ok' : 'badge-muted'} text-[10px]`}>
          {integration.enabled ? 'enabled' : 'disabled'}
        </span>
      </div>
      <div className="flex flex-wrap gap-2">
        <button className="btn btn-secondary btn-sm" onClick={onTest} disabled={testing}>
          {testing ? <><span className="spinner" /> Testing…</> : <><IconRefresh /> Test</>}
        </button>
        <button className="btn btn-secondary btn-sm" onClick={onEdit}>Edit</button>
        <button
          className={`btn btn-sm ${integration.enabled ? 'btn-warning' : 'btn-success'}`}
          onClick={onToggle}
        >
          {integration.enabled ? 'Disable' : 'Enable'}
        </button>
        <button className="btn btn-danger btn-sm" onClick={onDelete}><IconTrash /></button>
      </div>
    </div>
  );
}

function KindPicker({
  kinds, onPick, onClose,
}: {
  kinds: IntegrationMeta[];
  onPick: (id: string) => void;
  onClose: () => void;
}) {
  return (
    <Modal title="Add DNS Integration" onClose={onClose}>
      <p className="text-[13px] text-muted mb-3">Pick a provider to configure:</p>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
        {kinds.map((k) => (
          <button
            key={k.id}
            className="text-left bg-surface2 hover:bg-surface3 border border-border rounded-md px-3 py-2 transition-colors"
            onClick={() => onPick(k.id)}
          >
            <div className="font-semibold">{k.name}</div>
            <div className="text-[11px] text-dim">{k.id}</div>
          </button>
        ))}
      </div>
    </Modal>
  );
}

function IntegrationFormModal({
  mode, meta, initial, onSave, onClose,
}: {
  mode: 'create' | 'edit';
  meta: IntegrationMeta | undefined;
  initial: Integration | null;
  onSave: (body: { name: string; config: Record<string, string>; enabled: boolean }) => Promise<void>;
  onClose: () => void;
}) {
  const [name, setName] = useState(initial?.name ?? '');
  const [enabled, setEnabled] = useState(initial?.enabled ?? true);
  const [values, setValues] = useState<Record<string, string>>(() => {
    const v: Record<string, string> = {};
    if (meta) {
      for (const f of meta.fields) {
        v[f.key] = initial?.config[f.key] ?? f.default;
      }
    }
    return v;
  });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!meta) {
    return (
      <Modal title="Unknown integration kind" onClose={onClose}>
        <div className="alert alert-error">No metadata available for this integration kind.</div>
      </Modal>
    );
  }

  async function submit() {
    setError(null);
    if (!name.trim()) { setError('Name is required'); return; }
    for (const f of meta!.fields) {
      if (f.required && !(values[f.key] ?? '').trim()) {
        setError(`${f.label} is required`);
        return;
      }
    }
    setBusy(true);
    try {
      // Strip empty optional fields so they don't overwrite stored values on edit.
      const config: Record<string, string> = {};
      for (const f of meta!.fields) {
        const v = values[f.key] ?? '';
        // On edit, the masked sentinel means "no change". Pass it through;
        // the server will preserve the existing secret.
        if (v === '' && mode === 'edit') continue;
        config[f.key] = v;
      }
      await onSave({ name: name.trim(), config, enabled });
    } catch (ex) {
      setError(ex instanceof Error ? ex.message : 'Save failed');
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      title={`${mode === 'create' ? 'Add' : 'Edit'} ${meta.name} integration`}
      onClose={onClose}
      footer={
        <>
          <button className="btn btn-secondary" onClick={onClose} disabled={busy}>Cancel</button>
          <button className="btn btn-primary" onClick={submit} disabled={busy}>
            {busy ? <><span className="spinner" /> Saving…</> : (mode === 'create' ? 'Add' : 'Save')}
          </button>
        </>
      }
    >
      {error && <div className="alert alert-error">{error}</div>}

      <div className="mb-4">
        <label className="block text-[13px] font-medium text-muted mb-1.5">Name</label>
        <input
          type="text"
          name="integration-name"
          autoFocus
          value={name}
          placeholder="e.g. Production Cloudflare, Internal PowerDNS"
          onChange={(e) => setName(e.target.value)}
          autoComplete="off"
          data-1p-ignore
          data-lpignore="true"
        />
        <div className="text-[11px] text-dim mt-1">Free-text label shown on the integrations page.</div>
      </div>

      <div className="mb-4 flex items-center gap-2">
        <input
          id="integration-enabled"
          type="checkbox"
          className="w-auto m-0 cursor-pointer"
          checked={enabled}
          onChange={(e) => setEnabled(e.target.checked)}
        />
        <label htmlFor="integration-enabled" className="m-0 cursor-pointer font-normal text-text text-[13px]">
          Enabled
        </label>
      </div>

      {meta.fields.map((f) => (
        <IntegConfigField
          key={f.key}
          field={f}
          value={values[f.key] ?? ''}
          isSecret={f.field_type === 'password'}
          editMode={mode === 'edit'}
          onChange={(v) => setValues({ ...values, [f.key]: v })}
        />
      ))}
    </Modal>
  );
}

function IntegConfigField({
  field, value, isSecret, editMode, onChange,
}: {
  field: IntegrationField;
  value: string;
  isSecret: boolean;
  editMode: boolean;
  onChange: (v: string) => void;
}) {
  const placeholder = isSecret && editMode && value === SECRET_MASK
    ? 'Leave blank to keep the current value'
    : field.placeholder;
  // On edit mode with a masked secret, show an empty input so the user can
  // type a new value (or leave blank to preserve). Storing the literal mask
  // would be confusing.
  const display = isSecret && editMode && value === SECRET_MASK ? '' : value;
  return (
    <div className="mb-4">
      <label className="block text-[13px] font-medium text-muted mb-1.5">{field.label}</label>
      <input
        type={field.field_type}
        name={`integration-${field.key}`}
        value={display}
        placeholder={placeholder}
        onChange={(e) => onChange(e.target.value)}
        autoComplete={isSecret ? 'new-password' : 'off'}
        data-1p-ignore
        data-lpignore="true"
      />
      {field.hint && <div className="text-[11px] text-dim mt-1">{field.hint}</div>}
    </div>
  );
}

function PasswordTab() {
  const { user } = useAuth();
  const [pw, setPw] = useState('');
  const [confirmPw, setConfirmPw] = useState('');
  const [msg, setMsg] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null);

  async function submit() {
    if (pw.length < 8) { setMsg({ kind: 'err', text: 'Password must be at least 8 characters' }); return; }
    if (pw !== confirmPw) { setMsg({ kind: 'err', text: 'Passwords do not match' }); return; }
    if (!user) return;
    try {
      await usersApi.changePassword(user.id, pw);
      setMsg({ kind: 'ok', text: 'Password changed' });
      setPw('');
      setConfirmPw('');
      setTimeout(() => setMsg(null), 3000);
    } catch (ex) {
      setMsg({ kind: 'err', text: ex instanceof Error ? ex.message : 'Failed' });
    }
  }

  return (
    <div className="table-wrap p-6 max-w-[400px]">
      {msg && <div className={msg.kind === 'ok' ? 'alert alert-success' : 'alert alert-error'}>{msg.text}</div>}
      <div className="mb-4">
        <label className="block text-[13px] font-medium text-muted mb-1.5">New Password</label>
        <input type="password" name="new-password" placeholder="Min 8 characters" value={pw} onChange={(e) => setPw(e.target.value)} autoComplete="new-password" />
      </div>
      <div className="mb-4">
        <label className="block text-[13px] font-medium text-muted mb-1.5">Confirm Password</label>
        <input type="password" name="confirm-password" value={confirmPw} onChange={(e) => setConfirmPw(e.target.value)} autoComplete="new-password" />
      </div>
      <button className="btn btn-primary" onClick={submit}>Change Password</button>
    </div>
  );
}
