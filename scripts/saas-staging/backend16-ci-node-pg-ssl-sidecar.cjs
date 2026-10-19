'use strict';
// Backend16.14 CI-only local PostgreSQL SSLRequest -> TLS server for Bun client.
// No external interface, real DB, tenant, HTTP or production use.
const net=require('node:net');
const tls=require('node:tls');
const fs=require('node:fs');
const REQUEST=Buffer.from([0,0,0,8,4,210,22,47]);
const mode=process.argv[2],certPath=process.argv[3],keyPath=process.argv[4];
if(process.env.GITHUB_ACTIONS!=='true'||
   process.env.SAAS_B16_EPHEMERAL_CI!=='true'||
   process.env.SAAS_B16_VERIFYFULL_CI!=='true'||
   process.env.RAILWAY_PROJECT_ID||process.env.RAILWAY_ENVIRONMENT_ID||
   !['tls','no-ssl'].includes(mode))process.exit(63);
let context;
if(mode==='tls'){
  try{
    context=tls.createSecureContext({
      cert:fs.readFileSync(certPath),key:fs.readFileSync(keyPath),
    });
  }catch{process.exit(64);}
}
const sockets=new Set();
const server=net.createServer(socket=>{
  sockets.add(socket);
  socket.on('close',()=>sockets.delete(socket));
  socket.on('error',()=>socket.destroy());
  socket.once('data',payload=>{
    if(!payload.equals(REQUEST)){socket.destroy();return;}
    process.stdout.write('REQUEST\n');
    if(mode==='no-ssl'){socket.end('N');return;}
    socket.write('S',()=>{
      try{
        const encrypted=new tls.TLSSocket(socket,{
          isServer:true,secureContext:context,
        });
        encrypted.on('error',()=>encrypted.destroy());
      }catch{socket.destroy();}
    });
  });
});
server.listen(0,'127.0.0.1',()=>{
  process.stdout.write('PORT:'+server.address().port+'\n');
});
process.once('SIGTERM',()=>{
  for(const socket of sockets)socket.destroy();
  server.close(()=>process.exit(0));
  setTimeout(()=>process.exit(0),1500).unref();
});
