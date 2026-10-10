import { useCallback, useEffect, useState } from 'react';
import { pluginsApi } from '@/services/api';
import { useAuthStore } from '@/stores';
import { summarizeCpaPolicy, type CpaPolicySnapshot } from '../cpaPolicyStatus';

interface LoadedPolicy {
  apiBase: string;
  revision: number;
  snapshot: CpaPolicySnapshot;
}

/**
 * Only reads the v8 Management API on an authenticated connection.
 * Connection switches, refreshes and unmounts invalidate older responses.
 */
export function useCpaPolicyStatus() {
  const apiBase = useAuthStore((state) => state.apiBase);
  const connected = useAuthStore((state) => state.connectionStatus === 'connected');
  const supportsPlugin = useAuthStore((state) => state.supportsPlugin);
  const [revision, setRevision] = useState(0);
  const [loaded, setLoaded] = useState<LoadedPolicy | null>(null);

  useEffect(() => {
    let cancelled = false;
    if (connected && supportsPlugin) {
      void pluginsApi.list().then(
        (plugins) => {
          if (!cancelled) {
            setLoaded({ apiBase, revision, snapshot: summarizeCpaPolicy(plugins) });
          }
        },
        () => {
          if (!cancelled) {
            setLoaded({
              apiBase,
              revision,
              snapshot: { state: 'error', version: null, route: null },
            });
          }
        }
      );
    }
    return () => {
      cancelled = true;
    };
  }, [apiBase, connected, revision, supportsPlugin]);

  const refresh = useCallback(() => setRevision((current) => current + 1), []);

  const snapshot: CpaPolicySnapshot = !connected
    ? { state: 'offline', version: null, route: null }
    : !supportsPlugin
      ? { state: 'unsupported', version: null, route: null }
      : loaded?.apiBase === apiBase && loaded.revision === revision
        ? loaded.snapshot
        : { state: 'loading', version: null, route: null };

  return { snapshot, refresh, supportsPlugin };
}
