/**
 * Ephemeral root/leaf TLS certificates generated solely in opt-in GitHub CI.
 * NO CERTIFICATE/PRIVATE KEY IS CHECKED INTO THE REPOSITORY. Never touches
 * Railway, production secret storage, staging high-water or real OAuth IdP.
 */
import { createHash, X509Certificate } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

export function m1nCiEnabled() {
  const env=process.env;
  return env.GITHUB_ACTIONS==='true' &&
    env.SAAS_EPHEMERAL_M1N_TLS_CI==='true' &&
    env.SAAS_EPHEMERAL_M1M_PKCE_CI==='true' &&
    env.NODE_ENV!=='production' &&
    !env.RAILWAY_PROJECT_ID &&
    !env.RAILWAY_ENVIRONMENT &&
    !env.RAILWAY_SERVICE_ID;
}
function run(args,workdir) {
  const result=spawnSync('openssl',args,{
    cwd:workdir,stdio:['ignore','pipe','pipe'],timeout:12000,
  });
  if(result.status!==0)throw new Error('M1n disposable OpenSSL fixture generation failed');
}
function spki(pem) {
  const cert=new X509Certificate(pem);
  return createHash('sha256')
    .update(cert.publicKey.export({type:'spki',format:'der'}))
    .digest('hex');
}
export function createDisposableM1nTlsFixture() {
  if(!m1nCiEnabled())throw new Error('M1n ephemeral TLS certificates disabled');
  const workdir=mkdtempSync(join(tmpdir(),'saas-m1n-tls-'));
  const generateCa=name=>{
    run(['req','-x509','-newkey','rsa:2048','-nodes','-sha256',
      '-days','1','-subj','/CN=M1n-Disposable-'+name,
      '-addext','basicConstraints=critical,CA:TRUE',
      '-addext','keyUsage=critical,keyCertSign,cRLSign',
      '-keyout',name+'.key','-out',name+'.crt'],workdir);
    return {pem:readFileSync(join(workdir,name+'.crt'),'utf8')};
  };
  const generateLeaf=(root,name,host='localhost')=>{
    run(['req','-new','-newkey','rsa:2048','-nodes',
      '-keyout',name+'.key','-out',name+'.csr',
      '-subj','/CN='+host],workdir);
    writeFileSync(join(workdir,name+'.ext'),[
      'basicConstraints=critical,CA:FALSE',
      'keyUsage=critical,digitalSignature,keyEncipherment',
      'extendedKeyUsage=serverAuth',
      'subjectAltName=DNS:'+host+',IP:127.0.0.1',
    ].join('\n')+'\n',{mode:0o600});
    run(['x509','-req','-in',name+'.csr',
      '-CA',root+'.crt','-CAkey',root+'.key','-CAcreateserial',
      '-out',name+'.crt','-days','1','-sha256',
      '-extfile',name+'.ext'],workdir);
    const cert=readFileSync(join(workdir,name+'.crt'),'utf8');
    return Object.freeze({
      cert, key:readFileSync(join(workdir,name+'.key'),'utf8'),
      spkiSha256:spki(cert),
    });
  };
  try {
    const trustedCa=generateCa('root');
    const rogueCa=generateCa('rogue');
    const primary=generateLeaf('root','primary');
    const rotated=generateLeaf('root','rotated');
    const untrusted=generateLeaf('rogue','untrusted');
    const wrongHost=generateLeaf('root','wronghost','wronghost.invalid');
    return Object.freeze({
      trustedCaPem:trustedCa.pem,
      rogueCaPem:rogueCa.pem,
      primary,rotated,untrusted,wrongHost,
      dispose(){rmSync(workdir,{recursive:true,force:true});},
    });
  } catch(err) {
    rmSync(workdir,{recursive:true,force:true});
    throw err;
  }
}
