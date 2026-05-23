/**
 * Compat shim — the bespoke SVG components that used to live here have all
 * been replaced in their call sites by `lucide-react` imports. This file is
 * kept so any third-party module that imports `components/Icons` keeps
 * resolving; the re-exports below match the prior names but render the
 * lucide equivalents at the historic `h-4 w-4` size.
 *
 * New code should `import { Plus, Trash2, … } from 'lucide-react'` directly.
 */

import type { SVGProps } from 'react';
import {
  BookOpen,
  Check,
  Copy,
  Download,
  File as FileIcon,
  KeyRound,
  LayoutDashboard,
  LogOut,
  Lock,
  Monitor,
  Moon,
  Plus,
  RefreshCw,
  ScrollText,
  Settings,
  Shield,
  ShieldCheck,
  ShieldHalf,
  Sun,
  Trash2,
  Users,
} from 'lucide-react';

type AnyIcon = React.ComponentType<SVGProps<SVGSVGElement>>;
const sized = (Cmp: AnyIcon): AnyIcon =>
  (p: SVGProps<SVGSVGElement>) => <Cmp className="h-4 w-4" {...p} />;

export const IconDashboard = sized(LayoutDashboard);
export const IconCert      = sized(ScrollText);
export const IconKey       = sized(KeyRound);
export const IconSettings  = sized(Settings);
export const IconUsers     = sized(Users);
export const IconLogout    = sized(LogOut);
export const IconDownload  = sized(Download);
export const IconPlus      = sized(Plus);
export const IconRefresh   = sized(RefreshCw);
export const IconTrash     = sized(Trash2);
export const IconFile      = sized(FileIcon);
export const IconShield    = sized(Shield);
export const IconCheck     = sized(Check);
export const IconBook      = sized(BookOpen);
export const IconShieldKey = sized(ShieldHalf);
export const IconRoles     = sized(ShieldCheck);
export const IconAudit     = sized(ScrollText);
export const IconLock      = sized(Lock);
export const IconSun       = sized(Sun);
export const IconMoon      = sized(Moon);
export const IconMonitor   = sized(Monitor);
export const IconCopy      = sized(Copy);
