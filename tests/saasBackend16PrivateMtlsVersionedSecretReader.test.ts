import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';

const file=new URL(
  '../src/features/saasBlueprint/controlApi/server/backend16PrivateMtlsVersionedSecretReader.ts',
  import.meta.url);
const source=readFileSync(file,'utf8');
const ci=readFileSync(new URL(
  '../scripts/saas-staging/verify-backend16-mtls-secret-broker-ci.ts',
  import.meta.url),'utf8');

test('broker endpoint, SNI and path are fixed; no secret enumeration or fallback',()=>{
  for(const marker of [
    "const HOST='saas-secret-broker.railway.internal'",
    "const PORT=443",
    "method:'GET',agent:false",
    "'/v1/staging/principals/'+secretId+'/versions/'+version",
    "servername:HOST",
    "rejectUnauthorized:true",
    "minVersion:'TLSv1.2'",
    "checkHost(",
    "{subject:'never'}",
    "dnsSans.split(/,\\s*/).includes('DNS:'+HOST)",
    "return nativeCheckServerIdentity(hostname,peer)",
    "ca:identity.ca,cert:identity.cert,key:identity.key",
    "timeout:3_900",
    "FETCH_DEADLINE_MS=4_200",
    "MAX_BODY_BYTES=2_048",
    "response.statusCode!==200",
    "response.headers['cache-control']!=='no-store'",
    "response.headers['content-type']!=='application/json'",
    "TextDecoder('utf-8',{fatal:true})",
    "JSON.stringify({",
    "client.keyUsage?.includes('1.3.6.1.5.5.7.3.2')",
    "expected.length!==actual.length",
    "releaseAllowed=permitted()&&isTime(settledAt)",
    "settledAt+MIN_ROOT_REMAINING_MS<identity.rootValidUntil",
    "settledAt+MIN_CLIENT_REMAINING_MS<identity.clientValidUntil",
    "if(releaseAllowed)resolve(record)",
  ])assert.ok(source.includes(marker),marker);
  assert.equal((source.match(/req\.end\(\)/g)||[]).length,1);
  assert.doesNotMatch(source,
    /Bun\.serve|\.listen\(|new WebSocket|fetch\(|retry\s*\(|setInterval\(|DATABASE_URL|DATABASE_PUBLIC_URL|console\.(?:log|info|error)|Location\s*:/);
});

test('staging profile must refuse CI, TLS downgrade and unrelated Railway resources',()=>{
  for(const marker of [
    'RAILWAY_PROJECT_ID===PROJECT',
    'RAILWAY_ENVIRONMENT_ID===ENVIRONMENT',
    "RAILWAY_ENVIRONMENT_NAME==='staging'",
    'RAILWAY_SERVICE_ID===CONTROL_API',
    "SAAS_B16_STAGING_PRIVATE_ONLY==='true'",
    "SAAS_B16_SECRET_BROKER_APPROVED==='true'",
    "GITHUB_ACTIONS!=='true'",
    "NODE_TLS_REJECT_UNAUTHORIZED!=='0'",
    "hostname:address",
  ])assert.ok(source.includes(marker),marker);
  assert.match(source,/createBackend16DisposableCiMtlsSecretReader\(/);
  assert.match(source,/address:typeof HOST\|'127\.0\.0\.1'/);
  assert.match(source,/env\(\)/);
  assert.doesNotMatch(source,/localhost:\d+|http:\/\/|rejectUnauthorized:false/);
});

test('source does not trust extra fields, duplicate JSON keys or unpinned certificates',()=>{
  for(const marker of [
    "approvedCaDerSha256",
    "approvedClientCertDerSha256",
    "binaryPin(config.approvedCaDerSha256,root.raw)",
    "binaryPin(config.approvedClientCertDerSha256,client.raw)",
    "root.checkIssued(root)",
    "root.verify(root.publicKey)",
    "client.checkIssued(root)",
    "client.verify(root.publicKey)",
    "timingSafeEqual(expected,actual)",
    "SINGLE_PEM.test(config.caPem)",
    "PRIVATE_PEM.test(config.clientPrivateKeyPem)",
    "text!==JSON.stringify({",
    "plain(record,RESPONSE_KEYS)",
    "x.version!==version",
    "expiry-now<=MIN_SECRET_LEASE_MS",
    "expiry-now>MAX_SECRET_LEASE_MS",
  ])assert.ok(source.includes(marker),marker);
  assert.doesNotMatch(source,/API_KEY|Bearer\s+|Authorization:|clientSecret|process\.env\.(?:PGPASSWORD|DATABASE_URL)/);
});

test('disposable acceptance includes authenticated mTLS and deny/revoke paths',()=>{
  for(const marker of [
    "requestCert:true,rejectUnauthorized:true",
    'clientAuthorized:auth',
    "B16_MTLS_BROKER_CI_AUTHORIZED_PASS",
    "B16_MTLS_BROKER_CI_REVOCATION_AND_MALFORMED_DENY",
    "B16_MTLS_BROKER_CI_HUNG_ABORT_DENY",
    "B16_MTLS_BROKER_CI_INFLIGHT_APPROVAL_REVOKED_DENY",
    "B16_MTLS_VAULT_CI_INFLIGHT_APPROVAL_REVOKED_DENY",
    "const vaultRequest=vault.readPrincipal(A",
    "B16_MTLS_BROKER_CI_UNTRUSTED_IDENTITY_DENY",
    "B16_MTLS_BROKER_CI_WRONG_SERVER_SAN_DENY",
    "B16_MTLS_BROKER_CI_WILDCARD_SERVER_SAN_DENY",
    "wrong-version","duplicate","redirect","oversize",
    "good.waitForDeferred()","good.releaseDeferred()",
    "createBackend16StagingVersionedPrincipalVault({",
    "rmSync(dir,{recursive:true,force:true})",
  ])assert.ok(ci.includes(marker),marker);
  assert.doesNotMatch(ci,/https:\/\/saas-secret-broker\.railway\.internal|railway up|DATABASE_URL/);
});
