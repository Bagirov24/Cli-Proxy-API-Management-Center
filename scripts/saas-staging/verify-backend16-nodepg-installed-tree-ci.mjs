/**
 * Backend16 CI-only byte-tree provenance check AFTER two independently
 * resolved, genuine, frozen Node24 pg installs, BEFORE real physical PG16 E2E.
 * An observed matching tree is NOT an approved server artifact or release.
 */
import {createHash} from 'node:crypto';
import {closeSync,constants,fstatSync,lstatSync,openSync,
  readdirSync,readFileSync} from 'node:fs';
import {basename,isAbsolute,join} from 'node:path';

const DENIED='Backend16 installed NodePG tree CI refused';
const MAX_ENTRIES=20_000;
const MAX_FILES=12_000;
const MAX_BYTES=100_000_000;
const MAX_FILE_BYTES=24_000_000;
const MAX_DEPTH=18;
const FORMAT='backend16-nodepg-install-tree-sha256-v1';
const refuse=()=>{throw new Error(DENIED);};
const badName=name=>name==='.'||name==='..'||/[\\\x00-\x1f\x7f]/.test(name);

export function inspectBackend16NodePgInstalledTree(root){
  if(typeof root!=='string'||!isAbsolute(root)||
     basename(root)!=='node_modules')refuse();
  let count=0;
  let totalBytes=0;
  const files=[];
  function walk(dir,relative,depth){
    if(depth>MAX_DEPTH)refuse();
    let stat,listing;
    try{
      stat=lstatSync(dir);
      if(!stat.isDirectory()||stat.isSymbolicLink()||
         (stat.mode&0o022))refuse();
      listing=readdirSync(dir,{withFileTypes:true});
    }catch{refuse();}
    for(const ent of listing){
      count++;
      if(count>MAX_ENTRIES||badName(ent.name)||ent.name==='pg-native'||
         ent.name==='node-gyp'||ent.name.endsWith('.node'))refuse();
      const relativePath=relative?relative+'/'+ent.name:ent.name;
      const path=join(dir,ent.name);
      let item;
      try{item=lstatSync(path);}catch{refuse();}
      if(item.isSymbolicLink()||(item.mode&0o022))refuse();
      if(item.isDirectory()){
        walk(path,relativePath,depth+1);
        continue;
      }
      if(!item.isFile()||!Number.isSafeInteger(item.size)||
         item.size<0||item.size>MAX_FILE_BYTES||
         totalBytes>MAX_BYTES-item.size)refuse();
      const executable=(item.mode&0o111)!==0;
      let fd,contents;
      try{
        // Refuse a symlink swapped in between lstat() and open().
        fd=openSync(path,constants.O_RDONLY|constants.O_NOFOLLOW);
        const opened=fstatSync(fd);
        if(!opened.isFile()||opened.ino!==item.ino||
           opened.dev!==item.dev||opened.size!==item.size)refuse();
        contents=readFileSync(fd);
        if(contents.length!==item.size)refuse();
      }catch{refuse();}
      finally{if(fd!==undefined)try{closeSync(fd);}catch{refuse();}}
      totalBytes+=contents.length;
      files.push([
        relativePath,contents.length,executable?1:0,
        createHash('sha256').update(contents).digest('hex'),
      ]);
      if(files.length>MAX_FILES)refuse();
    }
  }
  walk(root,'',0);
  if(files.length<2||!files.some(entry=>entry[0]==='pg/package.json'))
    refuse();
  files.sort((a,b)=>a[0]<b[0]?-1:a[0]>b[0]?1:0);
  const digest=createHash('sha256').update(
    JSON.stringify({format:FORMAT,files})).digest('hex');
  return Object.freeze({
    format:FORMAT,digest,fileCount:files.length,totalBytes,
  });
}
export function assertMatchingBackend16NodePgInstalledTrees(a,b){
  if(!a||!b||a===b||a.format!==FORMAT||b.format!==FORMAT||
     a.digest!==b.digest||!/^[a-f0-9]{64}$/.test(a.digest)||
     a.fileCount!==b.fileCount||a.totalBytes!==b.totalBytes||
     !Number.isSafeInteger(a.fileCount)||a.fileCount<2||
     !Number.isSafeInteger(a.totalBytes)||a.totalBytes<1)
    refuse();
  return 'B16_NODEPG_FROZEN_TREE_INDEPENDENT_MATCH_PASS';
}
