/**
 * Optional LOCAL-ONLY fixture HTTP server.
 *
 * NEVER starts automatically. Refuses Railway/production and binds loopback
 * unconditionally. Uses fresh, short-lived SYNTHETIC sessions, no Core,
 * Gateway, VPN, OAuth, CPA secrets or /data. Not a deployment entrypoint.
 *
 * Example (local clone, from repo root):
 *   SAAS_CONTROL_SYNTHETIC_SERVER=true bun scripts/saas-control-local.mjs
 */
import { createControlHttpHandler } from '../src/features/saasBlueprint/controlApi/server/httpHandler.ts';
import { SyntheticSessionRegistry } from '../src/features/saasBlueprint/controlApi/server/syntheticSessions.ts';
import { createSyntheticControlBackend } from '../src/features/saasBlueprint/controlApi/server/syntheticBackend.ts';
import { DEMO_SNAPSHOT } from '../src/features/saasBlueprint/demo/demoData.ts';

if (process.env.SAAS_CONTROL_SYNTHETIC_SERVER !== 'true' ||
    process.env.NODE_ENV === 'production' ||
    process.env.RAILWAY_ENVIRONMENT ||
    process.env.RAILWAY_PROJECT_ID) {
  throw new Error('Refusing to run: explicit LOCAL synthetic opt-in required; Railway/production forbidden');
}

const nowMs = () => Date.now();
const actors = new Map([
  ['actor-north', {
    id: 'actor-north',
    memberships: [{ tenantId: 'demo-north', role: 'tenant-admin', status: 'active' }],
  }],
  ['actor-orbit', {
    id: 'actor-orbit',
    memberships: [{ tenantId: 'demo-orbit', role: 'tenant-viewer', status: 'active' }],
  }],
]);

const sessions = new SyntheticSessionRegistry(nowMs);
const backend = createSyntheticControlBackend({
  actors, snapshot: () => DEMO_SNAPSHOT, nowMs,
});
const fetch = createControlHttpHandler({ sessions, ...backend });

// Listen on IPv4 loopback ONLY. No environment override of hostname allowed.
const server = Bun.serve({ hostname: '127.0.0.1', port: 18551, fetch });
const northToken = await sessions.issue('actor-north', 10 * 60_000);
console.info('LOCAL SIMULATED CONTROL API: http://127.0.0.1:' + server.port);
console.info('Short-lived SYNTHETIC test bearer for North Studio (never use with Core):');
console.info(northToken);
console.info('Try: GET /control-api/v1/tenants/demo-north/metadata/accounts');
console.info('Ctrl+C stops the server. No data is persisted.');
