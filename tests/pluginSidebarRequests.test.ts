import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';

const layout = readFileSync(
  new URL('../src/components/layout/MainLayout.tsx', import.meta.url),
  'utf8'
);

// Source contracts: runtime network races still require an authenticated browser integration test.
describe('plugin sidebar navigation on management connection changes', () => {
  test('assigns an increasing request ID whenever plugin resources reload', () => {
    expect(layout).toContain('const pluginResourcesRequestRef = useRef(0);');
    expect(layout).toMatch(
      /const loadPluginResources = useCallback\(async \(\) => \{\s*const requestID = \+\+pluginResourcesRequestRef\.current;/
    );
  });

  test('rejects stale successful and failed plugin-list responses', () => {
    const load = layout.split('const loadPluginResources = useCallback(async () => {')[1]
      ?.split('const loadAuthFilesCount = useCallback')[0];
    expect(load).toBeDefined();
    expect(load?.match(/if \(requestID !== pluginResourcesRequestRef\.current\) return;/g))
      .toHaveLength(2);
  });

  test('invalidates outstanding requests on cleanup and connection changes', () => {
    expect(layout).toMatch(
      /return \(\) => \{\s*pluginResourcesRequestRef\.current \+= 1;\s*authFilesCountRequestRef\.current \+= 1;/
    );
    expect(layout).toContain(
      '}, [apiBase, loadPluginResources, loadAuthFilesCount]);'
    );
  });
});
