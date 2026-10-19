/**
 * Backend16.15 disposable CI ONLY: real Bun HTTPS/mTLS client.
 * Controlled by a Node24 local-only mTLS server; no Railway host/socket,
 * real password, runtime trust pin or approved production certificate.
 */
import assert from 'node:assert/strict';
import {createHash,X509Certificate} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {
  createBackend16DisposableCiMtlsSecretReader,
} from '../../src/features/saasBlueprint/controlApi/server/backend16PrivateMtlsVersionedSecretReader.ts';

if(process.env.GITHUB_ACTIONS!=='true'||
   process.env.SAAS_B16_EPHEMERAL_CI!=='true'||
   process.env.SAAS_B16_BROKER_MTLS_CI!=='true'||
   process.env.RAILWAY_PROJECT_ID||process.env.RAILWAY_ENVIRONMENT_ID||
   process.env.RAILWAY_SERVICE_ID||process.env.NODE_ENV==='production')
  throw new Error('B16 disposable Bun broker test refused');
const [portRaw,rootFile,certFile,keyFile]=process.argv.slice(2);
const port=Number(portRaw);
if(!Number.isSafeInteger(port)||port<1024||port>65535||
   !rootFile||!certFile||!keyFile)
  throw new Error('B16 disposable Bun broker fixture missing');
const rootPem=readFileSync(rootFile,'utf8');
const certPem=readFileSync(certFile,'utf8');
const sha=(pem:string)=>createHash('sha256').update(
  new X509Certificate(pem).raw).digest('hex');
const reader=createBackend16DisposableCiMtlsSecretReader({
  caPem:rootPem,approvedCaDerSha256:sha(rootPem),
  clientCertPem:certPem,approvedClientCertDerSha256:sha(certPem),
  clientPrivateKeyPem:readFileSync(keyFile,'utf8'),
},port);
const version='a'.repeat(32);
const id='b16-stg-pg-'+('a'.repeat(20));
const row=await reader.readVersion(
  id,version,new AbortController().signal,
);
assert.ok(row&&typeof row==='object');
const x=row as Record<string,unknown>;
assert.equal(x.username,'saas_b16_reader_a');
assert.equal(x.version,version);
assert.equal(x.password,'synthetic_ci_pg_password_'+('x'.repeat(42)));
assert.ok(typeof x.expiresAtMs==='number'&&
  x.expiresAtMs>Date.now()+60_000);
assert.equal(Object.keys(x).sort().join(','),
  'expiresAtMs,password,username,version');
console.info('B16_MTLS_BROKER_BUN_CLIENT_PASS');
