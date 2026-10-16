/**
 * Backend 07: NON-DEPLOYABLE Bun.SQL identity pool discard experiment.
 *
 * The ONLY caller is disposable GitHub PostgreSQL16 CI. Real staging must
 * replace this guard/configuration with independently reviewed drivers,
 * private ingress, secrets and non-superuser provisioning.
 *
 * Bun ReservedSQL.release() returns a connection to its pool. It is not a
 * physical discard primitive. A suspect connection MUST poison the entire
 * single-connection pool; release is followed by SQL.close({timeout:0}),
 * while synchronous quarantine blocks new reservations.
 */
import {SQL} from 'bun';
import {PG_IDENTITY_SQL} from
  '../../src/features/saasBlueprint/controlApi/server/pgDurableIdentitySessionAuthority.ts';

const ARITY = new Map([
  [PG_IDENTITY_SQL.begin, 0],
  [PG_IDENTITY_SQL.role, 0],
  [PG_IDENTITY_SQL.actor, 2],
  [PG_IDENTITY_SQL.session, 3],
  [PG_IDENTITY_SQL.memberships, 1],
  [PG_IDENTITY_SQL.commit, 0],
  [PG_IDENTITY_SQL.rollback, 0],
]);

function ciOnly() {
  const env = process.env;
  return env.GITHUB_ACTIONS === 'true' &&
    env.SAAS_ISOLATED_IDENTITY_DISCARD_CI === 'true' &&
    env.PGHOST === '127.0.0.1' &&
    env.PGPORT === '5432' &&
    env.PGDATABASE === 'saas_ephemeral_test' &&
    env.PGUSER === 'postgres' &&
    env.NODE_ENV !== 'production' &&
    !env.RAILWAY_PROJECT_ID && !env.RAILWAY_ENVIRONMENT &&
    !env.RAILWAY_SERVICE_ID;
}

function refused() {
  throw new Error('Isolated identity pool is restricted to disposable PostgreSQL16 CI');
}

/**
 * @param {{
 *   password: string,
 *   observeBackendPid?: (pid: number) => void,
 *   simulateLostCommitAckOnce?: boolean,
 * }} options
 *
 * A missing key/credential never triggers an alternative DB or fallback
 * role. No free-form SQL/host/database/user is accepted by the factory.
 */
export function createCiIsolatedIdentityPool(options) {
  if (!ciOnly() || !options ||
      typeof options.password !== 'string' ||
      !/^[0-9a-f]{48}$/.test(options.password) ||
      (options.observeBackendPid !== undefined &&
        typeof options.observeBackendPid !== 'function') ||
      (options.simulateLostCommitAckOnce !== undefined &&
        typeof options.simulateLostCommitAckOnce !== 'boolean') ||
      Object.keys(options).some(key => ![
        'password', 'observeBackendPid', 'simulateLostCommitAckOnce',
      ].includes(key))) refused();

  const sql = new SQL({
    hostname: '127.0.0.1', port: 5432,
    database: 'saas_ephemeral_test',
    username: 'saas_identity_ci', password: options.password,
    max: 1, connectionTimeout: 5, idleTimeout: 5,
    prepare: false, tls: false,
  });
  let poisoned = false;
  let active = 0;
  let closePromise;
  let actualCommitAcks = 0;
  let syntheticLostAcks = 0;
  let loseAck = options.simulateLostCommitAckOnce === true;

  function shutdown() {
    if (!closePromise) closePromise = sql.close({timeout: 0});
    return closePromise;
  }

  // Quarantine is SYNCHRONOUS: even queued reserve() callers must recheck.
  function quarantine() {
    poisoned = true;
    // If there is no active reservation, close immediately. If there is one,
    // let release(true) relinquish it first to avoid Bun reserved-close hang.
    if (active === 0) void shutdown().catch(() => {});
  }

  async function connect(signal) {
    if (poisoned || !signal || signal.aborted) {
      throw new Error('Private identity connection unavailable');
    }
    let reserved;
    try {
      reserved = await sql.reserve({signal});
    } catch {
      quarantine();
      throw new Error('Private identity reservation unavailable');
    }
    // A reservation may resolve AFTER a concurrent quarantine/abort.
    if (poisoned || signal.aborted) {
      quarantine();
      try {reserved.release();} finally {await shutdown();}
      throw new Error('Private identity reservation abandoned');
    }
    active++;
    let released = false;
    let inFlight = false;
    const connection = {
      async query(statement, params, querySignal) {
        const count = ARITY.get(statement);
        if (released || inFlight || count === undefined ||
            !Array.isArray(params) || params.length !== count ||
            params.some(v => typeof v !== 'string')) {
          quarantine();
          throw new Error('Private identity SQL refused');
        }
        if (poisoned && statement !== PG_IDENTITY_SQL.rollback) {
          throw new Error('Private identity pool retired');
        }
        if (!querySignal ||
            (querySignal.aborted && statement !== PG_IDENTITY_SQL.rollback)) {
          quarantine();
          throw new Error('Private identity query cancelled');
        }
        inFlight = true;
        let query;
        const cancel = () => {
          quarantine();
          try {query?.cancel();} catch { /* pool will be discarded */ }
        };
        try {
          query = reserved.unsafe(statement, [...params]).execute();
          querySignal.addEventListener('abort', cancel, {once: true});
          const rows = await query;
          if (querySignal.aborted && statement !== PG_IDENTITY_SQL.rollback) {
            throw new Error('Private identity query aborted');
          }
          if (statement === PG_IDENTITY_SQL.commit) {
            actualCommitAcks++;
            if (loseAck) {
              // The PG COMMIT ACK was ACTUALLY received; only the local
              // application ACK is simulated as lost. Not a network split.
              loseAck = false;
              syntheticLostAcks++;
              throw new Error('Synthetic post-COMMIT ACK loss');
            }
          }
          return {rows};
        } catch {
          quarantine();
          // Always mask driver/DB diagnostics. Caller returns 503, no retry.
          throw new Error('Private identity query unavailable');
        } finally {
          querySignal.removeEventListener('abort', cancel);
          inFlight = false;
        }
      },
      async release(discard) {
        if (released) throw new Error('Private identity connection double release');
        released = true;
        if (discard || signal.aborted) quarantine();
        let failed = false;
        try {
          reserved.release();
        } catch {
          failed = true;
          quarantine();
        } finally {
          active--;
        }
        if (poisoned) {
          try {
            await shutdown();
          } catch {
            failed = true;
          }
        }
        if (failed) throw new Error('Private identity connection release unavailable');
      },
    };
    try {
      // Test-only instrumentation on EXACTLY this reserved physical backend.
      // Not a new general SQL method available to the HTTP authority.
      const rows = await reserved.unsafe(
        'SELECT pg_backend_pid()::integer AS backend_pid'
      ).execute();
      const pid = rows?.[0]?.backend_pid;
      if (!Array.isArray(rows) || rows.length !== 1 ||
          !Number.isSafeInteger(pid) || pid < 1) {
        throw new Error('Invalid private PostgreSQL backend PID');
      }
      options.observeBackendPid?.(pid);
      if (poisoned || signal.aborted) {
        throw new Error('Private identity reservation cancelled');
      }
    } catch {
      quarantine();
      await connection.release(true);
      throw new Error('Private identity reservation verification unavailable');
    }
    return Object.freeze(connection);
  }

  return Object.freeze({
    connect, quarantine,
    stats() {
      return Object.freeze({
        poisoned, active, actualCommitAcks, syntheticLostAcks,
      });
    },
    async close() {
      quarantine();
      if (active !== 0) {
        throw new Error('Private identity close has outstanding reservations');
      }
      await shutdown();
    },
  });
}
