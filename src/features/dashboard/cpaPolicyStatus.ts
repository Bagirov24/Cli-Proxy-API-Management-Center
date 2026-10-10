import { buildPluginResourceRoute } from '@/features/plugins/pluginResources';
import type { PluginListResponse } from '@/types';

export type CpaPolicyState =
  | 'enabled'
  | 'disabled'
  | 'missing'
  | 'error'
  | 'unsupported'
  | 'loading'
  | 'offline';

export interface CpaPolicySnapshot {
  state: CpaPolicyState;
  version: string | null;
  route: string | null;
}

/** Read-only view of the installed plugin; never infer that credentials are valid. */
export function summarizeCpaPolicy(plugins: PluginListResponse): CpaPolicySnapshot {
  const plugin = plugins.plugins.find((entry) => entry.id === 'cpa-key-policy');
  if (!plugin) {
    return { state: 'missing', version: null, route: null };
  }

  const enabled = plugins.pluginsEnabled && plugin.effectiveEnabled;
  const menuIndex = plugin.menus.findIndex((menu) => Boolean(menu.path.trim()));
  return {
    state: enabled ? 'enabled' : 'disabled',
    version: plugin.metadata?.version?.trim() || null,
    route:
      enabled && menuIndex !== -1 ? buildPluginResourceRoute(plugin.id, menuIndex) : null,
  };
}

