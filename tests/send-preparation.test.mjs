import test from 'node:test';
import {AsyncLocalStorage} from 'node:async_hooks';
import assert from 'node:assert/strict';
import {generateKeyPairSync,randomBytes} from 'node:crypto';
import {BaseClient} from '@evex/linejs/base';
import {LineDriver} from '../server/drivers.mjs';
import {prepareText} from '../server/send-preparation.mjs';
import {publicError,SendRejectedError} from '../server/errors.mjs';
import {ProtocolWorker} from '../server/worker.mjs';
import {Store} from '../server/store.mjs';
import {Vault} from '../server/vault.mjs';
import {Hub,adminActor} from '../server/hub.mjs';
import {gatewayRequest} from '../client/request.mjs';
import {preparationDiagnostic} from '../client/send-diagnostic.mjs';
import {errorText} from '../public/locale.js';

function pair(){const p=generateKeyPairSync('x25519');return {privKey:p.privateKey.export({format:'der',type:'pkcs8'}).subarray(-32).toString('base64'),pubKey:p.publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('base64'),keyId:'123'};}
function fixture(){
  const self=pair(),receiver=pair(),values=new Map(),client=new BaseClient({device:'IOSIPAD',storage:{get:async key=>values.get(key),set:async(key,value)=>values.set(key,value)},fetch:async()=>{throw Error('No network allowed');}});
  client.profile={mid:'u'+'1'.repeat(32)};values.set('e2eeKeys:'+client.profile.mid,JSON.stringify(self));
  client.talk.negotiateE2EEPublicKey=async()=>({specVersion:2,publicKey:{keyId:456,keyData:Buffer.from(receiver.pubKey,'base64')}});
  client.e2ee.getE2EELocalPublicKey=async()=>receiver;
  let sends=0;client.talk.sendMessage=async()=>{sends++;return {id:'synthetic-ack'};};
  const driver=Object.create(LineDriver.prototype);driver.client=client;driver.requestSignal=new AsyncLocalStorage();client.request.request=async()=>({});
  return {client,driver,values,sends:()=>sends};
}
const direct={id:'u'+'2'.repeat(32),kind:'direct'},group={id:'c'+'3'.repeat(32),kind:'group'};
const fault=(name,code)=>Object.assign(new Error('SECRET message body, key, URL and token must never appear'),{name,data:{code}});

test('real pinned SDK encrypts synthetic direct/group text without mutating shared methods',async()=>{
  const f=fixture(),encrypt=f.client.e2ee.encryptE2EEMessage,negotiate=f.client.talk.negotiateE2EEPublicKey;
  for(const chat of [direct,group]){const chunks=await prepareText(f.client,chat,'synthetic only');assert.equal(chunks.length,5);assert.ok(chunks.every(Buffer.isBuffer));}
  assert.equal(f.client.e2ee.encryptE2EEMessage,encrypt);assert.equal(f.client.talk.negotiateE2EEPublicKey,negotiate);assert.equal(f.sends(),0);
});

test('missing self key, unsupported peer, malformed negotiation, timeout, group key and crypto errors retain safe stage',async()=>{
  const cases=[
    ['SELF_KEY_LOOKUP_SELF_KEY_MISSING',f=>{f.values.clear();f.client.talk.getE2EEPublicKeys=async()=>[];}],
    ['RECIPIENT_KEY_NEGOTIATION_E2EE_UNSUPPORTED',f=>{f.client.talk.negotiateE2EEPublicKey=async()=>({specVersion:-1});}],
    ['RECIPIENT_KEY_NEGOTIATION_SDK_TYPE_ERROR',f=>{f.client.talk.negotiateE2EEPublicKey=async()=>({specVersion:2});}],
    ['RECIPIENT_KEY_NEGOTIATION_TIMEOUT',f=>{f.client.talk.negotiateE2EEPublicKey=async()=>{throw fault('TimeoutError');};}],
    ['RECIPIENT_KEY_NEGOTIATION_NOT_AUTHORIZED_DEVICE',f=>{f.client.talk.negotiateE2EEPublicKey=async()=>{throw fault('RequestError','NOT_AUTHORIZED_DEVICE');};}],
    ['ENCRYPTION_SDK_TYPE_ERROR',f=>{f.client.e2ee.encryptE2EETextMessage=()=>{throw fault('TypeError');};}],
    ['RECIPIENT_KEY_NEGOTIATION_LINE_REJECTED',f=>{f.client.talk.negotiateE2EEPublicKey=async()=>{throw fault('RequestError','SECRET_TOKEN');};}]
  ];
  for(const [diagnostic,change,chat=direct] of cases){const f=fixture();change(f);await assert.rejects(f.driver.send(chat,'SECRET message'),error=>{
    assert.ok(error instanceof SendRejectedError);const safe=publicError(error);assert.equal(safe.code,'send_preparation_failed');assert.equal(preparationDiagnostic(safe.message),diagnostic);assert.ok(errorText(safe.code,safe.message).includes(diagnostic));assert.doesNotMatch(JSON.stringify(safe),/SECRET/);return true;
  });assert.equal(f.sends(),0);}
});

test('concurrent preparations retain their own stages and SDK-handled exceptions retain original identity',async()=>{
  const f=fixture();let reject;const pending=new Promise((_r,j)=>reject=j);
  f.client.talk.negotiateE2EEPublicKey=()=>pending;
  const one=f.driver.send(direct,'synthetic');const oneCheck=assert.rejects(one,/RECIPIENT_KEY_NEGOTIATION_TIMEOUT/);
  f.client.e2ee.getE2EELocalPublicKey=async()=>{throw fault('RequestError','NOT_AUTHORIZED_DEVICE');};
  await assert.rejects(f.driver.send(group,'synthetic'),/GROUP_KEY_LOOKUP_NOT_AUTHORIZED_DEVICE/);reject(fault('TimeoutError'));await oneCheck;
  const original=fault('RequestError','NOT_FOUND');f.client.talk.getLastE2EEGroupSharedKey=async()=>{throw original;};
  f.client.e2ee.encryptE2EEMessage=async function(){try{await this.client.talk.getLastE2EEGroupSharedKey();}catch(error){assert.equal(error,original);return ['synthetic handled'];}};
  assert.deepEqual(await prepareText(f.client,group,'synthetic'),['synthetic handled']);
  f.client.e2ee.encryptE2EEMessage=()=>{throw fault('TypeError');};
  await assert.rejects(prepareText(f.client,direct,'synthetic'),error=>{assert.doesNotMatch(JSON.stringify(error),/SECRET/);assert.equal(error.original.name,'TypeError');return true;});
});

test('explicit LINE E2EE_RETRY_PLAIN remains the only fallback, and requests are never retried',async()=>{
  const f=fixture();f.client.talk.negotiateE2EEPublicKey=async()=>{throw fault('RequestError','E2EE_RETRY_PLAIN');};
  assert.equal((await f.driver.send(direct,'synthetic')).protection,'line_transport');assert.equal(f.sends(),1);
  f.client.talk.negotiateE2EEPublicKey=async()=>({specVersion:-1});await assert.rejects(f.driver.send(direct,'synthetic'),/E2EE_UNSUPPORTED/);assert.equal(f.sends(),1);
});

test('safe diagnostic survives worker serialization, durable rejection, and idempotent replay without dispatch',async t=>{
  const f=fixture();f.client.talk.negotiateE2EEPublicKey=async()=>({specVersion:-1});let failure;try{await f.driver.send(direct,'synthetic');}catch(e){failure=e;}
  const wire=publicError(failure),worker=new ProtocolWorker(null,null,null);let received;
  worker.pending.set('send',{timer:setTimeout(()=>{},1000),reject:error=>received=error});worker.handle({type:'result',id:'send',error:{...wire,rejected_send:true}});
  assert.equal(received.message,wire.message);
  const store=new Store(':memory:'),hub=new Hub(store,new Vault(randomBytes(32),'synthetic'));t.after(()=>{hub.close();store.close();});
  const account=await hub.addAccount({label:'Synthetic',kind:'demo'});let calls=0;hub.driver(account.id).send=async()=>{calls++;throw received;};
  await assert.rejects(hub.send(adminActor,account.id,'demo-group','synthetic','preparation-diagnostic-1'),/RECIPIENT_KEY_NEGOTIATION_E2EE_UNSUPPORTED/);
  assert.equal(calls,1);const saved=store.send('local-admin','preparation-diagnostic-1');assert.equal(saved.state,'rejected');assert.equal(JSON.parse(saved.result).message,wire.message);
  // A rejection sent nothing, so the same key may run again (for example after a fix).
  await assert.rejects(hub.send(adminActor,account.id,'demo-group','synthetic','preparation-diagnostic-1'),/RECIPIENT_KEY_NEGOTIATION_E2EE_UNSUPPORTED/);assert.equal(calls,2);
  await assert.rejects(hub.send(adminActor,account.id,'demo-group','different text','preparation-diagnostic-1'),{code:'idempotency_conflict'});assert.equal(calls,2);
  hub.driver(account.id).send=async()=>{calls++;return {messageId:'ok-1',timestamp:null,delivery:'accepted_by_line',protection:'letter_sealing'};};
  assert.equal((await hub.send(adminActor,account.id,'demo-group','synthetic','preparation-diagnostic-1')).replayed,false);assert.equal(calls,3);
  assert.equal((await hub.send(adminActor,account.id,'demo-group','synthetic','preparation-diagnostic-1')).replayed,true,'A sent message is never repeated');assert.equal(calls,3);
  // An unknown outcome is never retried, even with the same key.
  hub.driver(account.id).send=async()=>{calls++;throw new Error('connection reset');};
  await assert.rejects(hub.send(adminActor,account.id,'demo-group','synthetic','unknown-outcome-1'),{code:'delivery_unknown'});
  await assert.rejects(hub.send(adminActor,account.id,'demo-group','synthetic','unknown-outcome-1'),{code:'delivery_unknown'});assert.equal(calls,4);
});

test('CLI distinguishes validated pre-dispatch rejection from uncertain 5xx without reflecting arbitrary text',async()=>{
  for(const valid of [true,false]){let calls=0;const message=valid?'Message preparation failed (SELF_KEY_LOOKUP_SELF_KEY_MISSING). No message was sent. SECRET raw suffix':'Message preparation failed (SECRET_TOKEN). No message was sent.';
    await assert.rejects(gatewayRequest({url:'http://127.0.0.1:3211',credentials:{token:'synthetic'},path:'/synthetic',method:'POST',send:true,fetchImpl:async()=>{calls++;return new Response(JSON.stringify({error:'send_preparation_failed',message}),{status:502});}}),error=>{assert.equal(error.code,valid?'send_preparation_failed':'delivery_unknown');assert.equal(error.exitCode,valid?6:8);assert.doesNotMatch(error.message,/SECRET/);return true;});assert.equal(calls,1);
  }
});

test('a group without a Letter Sealing key is sent with transport encryption; nothing else downgrades',async()=>{
  const f=fixture();let sent;f.client.talk.sendMessage=async options=>{sent=options;return {id:'synthetic-ack'};};
  f.client.e2ee.getE2EELocalPublicKey=async()=>{throw fault('RequestError','NOT_FOUND');};
  const result=await f.driver.send(group,'synthetic');
  assert.equal(result.protection,'line_transport');assert.match(result.notice,/no Letter Sealing group key/);
  assert.deepEqual({to:sent.to,e2ee:sent.e2ee,text:sent.text,chunks:sent.chunks},{to:group.id,e2ee:false,text:'synthetic',chunks:undefined});
  // Only this exact group condition: other group failures and direct chats still refuse.
  const other=fixture();other.client.e2ee.getE2EELocalPublicKey=async()=>{throw fault('RequestError','NOT_AUTHORIZED_DEVICE');};
  await assert.rejects(other.driver.send(group,'synthetic'),/GROUP_KEY_LOOKUP_NOT_AUTHORIZED_DEVICE/);assert.equal(other.sends(),0);
  const timeout=fixture();timeout.client.e2ee.getE2EELocalPublicKey=async()=>{throw fault('TimeoutError');};
  await assert.rejects(timeout.driver.send(group,'synthetic'),/GROUP_KEY_LOOKUP_TIMEOUT/);assert.equal(timeout.sends(),0);
  // The SDK never registers a replacement group key on the way.
  const registered=fixture();let registrations=0;registered.client.e2ee.tryRegisterE2EEGroupKey=async()=>{registrations++;return {};};
  registered.client.e2ee.getE2EELocalPublicKey=async()=>{throw fault('RequestError','NOT_FOUND');};
  assert.equal((await registered.driver.send(group,'synthetic')).protection,'line_transport');assert.equal(registrations,0);
});
