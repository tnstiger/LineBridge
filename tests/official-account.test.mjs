import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,randomBytes} from 'node:crypto';
import {Readable} from 'node:stream';
import {createServer} from 'node:net';
import {LineDriver} from '../server/drivers.mjs';
import {SendRejectedError} from '../server/errors.mjs';
import {Store} from '../server/store.mjs';
import {Vault} from '../server/vault.mjs';
import {Hub} from '../server/hub.mjs';
import {ProtocolWorker} from '../server/worker.mjs';
import {prepareSendIntent} from '../public/send-intent.js';
import {runCli} from '../client/cli.mjs';
import {createApps} from '../server/app.mjs';
import {Tunnels} from '../server/tunnels.mjs';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StreamableHTTPClientTransport} from '@modelcontextprotocol/sdk/client/streamableHttp.js';

const direct={id:'u'+'2'.repeat(32),kind:'direct',name:'Synthetic OA'};
const ack={acknowledgeOaTransport:true};
function pair(){const p=generateKeyPairSync('x25519');return {privKey:p.privateKey.export({format:'der',type:'pkcs8'}).subarray(-32).toString('base64'),pubKey:p.publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('base64'),keyId:123};}
function fixture(t){
  const values=new Map(),driver=new LineDriver({device:'IOSIPAD'},{get:async k=>values.get(k),set:async(k,v)=>values.set(k,v)},{qr(){},pin(){},fault(){}});
  t.after(()=>driver.stop());const client=driver.client,self=pair(),peer=pair();client.profile={mid:'u'+'1'.repeat(32)};
  values.set('e2eeKeys:'+client.profile.mid,JSON.stringify(self));client.getReqseq=async()=>1;
  const f={driver,client,values,calls:[],negotiation:{specVersion:-1},buddy:{mid:direct.id,businessAccount:true,botType:'OFFICIAL'},response:{id:'synthetic-accepted'},peer:{specVersion:2,publicKey:{keyId:456,keyData:Buffer.from(peer.pubKey,'base64')}}};
  client.fetch=async()=>assert.fail('No real network allowed');
  client.request.request=async(...args)=>{const [payload,method,protocol,parse,path]=args;f.calls.push(args);
    if(method==='negotiateE2EEPublicKey'){if(f.negotiation instanceof Error)throw f.negotiation;return f.negotiation;}
    if(method==='getBuddyDetail'){assert.deepEqual([payload,protocol,parse,path],[[[11,4,direct.id]],4,true,'/BUDDY4']);if(f.buddy instanceof Error)throw f.buddy;return f.buddy;}
    if(method==='sendMessage'){if(f.response instanceof Error)throw f.response;return f.response;}
    assert.fail('Unexpected RPC '+method);
  };
  const send=client.talk.sendMessage;client.talk.sendMessage=function(options){f.options=options;return send.call(this,options);};
  f.sends=()=>f.calls.filter(c=>c[1]==='sendMessage').length;return f;
}

test('verified OA requires explicit acknowledgment and uses pinned Talk text transport exactly once',async t=>{
  const f=fixture(t);assert.equal((await f.driver.textCapability(direct)).officialAccount,true);
  await assert.rejects(f.driver.send(direct,'synthetic'),{code:'oa_transport_acknowledgment_required'});assert.equal(f.sends(),0);
  // OA text does not need or register Letter Sealing keys.
  f.values.clear();const result=await f.driver.send(direct,'synthetic',ack);
  assert.equal(result.protection,'line_transport');assert.match(result.notice,/not Letter Sealed/);assert.equal(f.sends(),1);
  assert.deepEqual(f.options,{to:direct.id,text:'synthetic',e2ee:false});assert.equal(f.values.size,0);
  f.response=Object.assign(new Error('private'),{name:'RequestError',data:{code:'E2EE_RETRY_ENCRYPT'}});
  await assert.rejects(f.driver.send(direct,'synthetic',ack),{code:'line_send_rejected'});assert.equal(f.sends(),2);
});

test('normal recipients retain real E2EE even with the OA acknowledgment; groups never query Buddy',async t=>{
  const f=fixture(t);f.negotiation=f.peer;
  const result=await f.driver.send(direct,'synthetic',ack);assert.equal(result.protection,'letter_sealing');assert.equal(result.notice,undefined);
  assert.equal(f.options.e2ee,true);assert.equal(f.options.text,undefined);assert.equal(f.options.chunks.length,5);assert.equal(f.calls.some(c=>c[1]==='getBuddyDetail'),false);
  f.client.e2ee.getE2EELocalPublicKey=async()=>{throw Object.assign(new Error('private'),{name:'RequestError',data:{code:'NOT_FOUND'}});};
  // A group without a Letter Sealing key goes out with transport encryption, still without any Buddy lookup.
  const unsealed=await f.driver.send({id:'c'+'3'.repeat(32),kind:'group'},'synthetic',ack);assert.equal(unsealed.protection,'line_transport');assert.match(unsealed.notice,/no Letter Sealing group key/);
  assert.equal(f.sends(),2);assert.equal(f.calls.some(c=>c[1]==='getBuddyDetail'),false);
});

test('observed LINE_AT with businessAccount false requires acknowledgment and matching authenticated MID',async t=>{
  for(const botType of ['LINE_AT',3]){
    const f=fixture(t);f.buddy={mid:direct.id,businessAccount:false,botType,botActiveStatus:'ACTIVE'};
    assert.equal((await f.driver.textCapability(direct)).officialAccount,true);
    await assert.rejects(f.driver.send(direct,'synthetic'),{code:'oa_transport_acknowledgment_required'});assert.equal(f.sends(),0);
    const result=await f.driver.send(direct,'synthetic',ack);assert.equal(result.protection,'line_transport');assert.equal(f.sends(),1);
    assert.deepEqual(f.options,{to:direct.id,text:'synthetic',e2ee:false});
    f.negotiation=f.peer;assert.equal((await f.driver.send(direct,'synthetic',ack)).protection,'letter_sealing');assert.equal(f.options.e2ee,true);
    f.negotiation={specVersion:-1,publicKey:{}};assert.equal((await f.driver.textCapability(direct)).officialAccount,false);
    await assert.rejects(f.driver.send(direct,'synthetic',ack),{code:'send_preparation_failed'});assert.equal(f.sends(),2);
  }
});

test('LINE_AT exception rejects wrong MID, malformed business flag, LINE_AT_0, personal and unknown types',async t=>{
  const f=fixture(t),observed={mid:direct.id,businessAccount:false,botType:'LINE_AT'};
  const cases=[{...observed,mid:'u-other'},...['LINE_AT_0',2,'OFFICIAL',1,'RESERVED',0,99,'3','LINE_AT ',true,{},null].map(botType=>({...observed,botType})),...[undefined,null,0,1,'false','true',{}].map(businessAccount=>({...observed,businessAccount}))];
  for(const buddy of cases){f.buddy=buddy;assert.equal((await f.driver.textCapability(direct)).officialAccount,false);await assert.rejects(f.driver.send(direct,'synthetic',ack),{code:'send_preparation_failed'});}
  assert.equal(f.sends(),0);
});

test('unknown identity, contradictory capability, malformed metadata and timeouts cannot enable OA transport',async t=>{
  const f=fixture(t);
  for(const buddy of [{},{...f.buddy,mid:'u-other'},{...f.buddy,businessAccount:false},{...f.buddy,botType:'RESERVED'},{...f.buddy,botType:99}]){
    f.buddy=buddy;await assert.rejects(f.driver.send(direct,'synthetic',ack),{code:'send_preparation_failed'});
  }
  f.buddy={mid:direct.id,businessAccount:true,botType:1};
  for(const negotiation of [null,{}, {specVersion:2},{specVersion:'-1'},{specVersion:-1,publicKey:{}},Object.assign(new Error('SECRET'),{name:'TimeoutError'})]){
    f.negotiation=negotiation;await assert.rejects(f.driver.send(direct,'synthetic',ack),error=>{assert.equal(error.code,'send_preparation_failed');assert.doesNotMatch(error.message,/SECRET/);return true;});
  }
  f.negotiation={specVersion:-1};f.buddy=Object.assign(new Error('SECRET'),{name:'TimeoutError'});
  await assert.rejects(f.driver.send(direct,'synthetic',ack),/BUDDY_LOOKUP_TIMEOUT/);
  f.buddy=Object.assign(new Error('SECRET'),{name:'RequestError',data:{code:'E2EE_RETRY_PLAIN'}});
  await assert.rejects(f.driver.send(direct,'synthetic',ack),/BUDDY_LOOKUP_LINE_REJECTED/);assert.equal(f.sends(),0);
});

async function hubFixture(t){
  const f=fixture(t),store=new Store(':memory:'),hub=new Hub(store,new Vault(randomBytes(32),'test'));t.after(()=>{hub.close();store.close();});
  const account=await hub.addAccount({label:'Synthetic',kind:'demo'});store.putChat(account.id,direct);hub.designate(account.id,direct.id,true);
  const adapter=hub.driver(account.id);adapter.send=f.driver.send.bind(f.driver);adapter.textCapability=f.driver.textCapability.bind(f.driver);
  const token=hub.createToken({name:'synthetic-send-only',grants:[{accountId:account.id,read:false,send:true,chatIds:[direct.id]}]});
  return Object.assign(f,{store,hub,id:account.id,actor:hub.authenticate(token.token),token});
}

test('OA acknowledgment is idempotency-bound; unknown delivery is durable and never retried',async t=>{
  const f=await hubFixture(t),send=(key,options=ack)=>f.hub.send(f.actor,f.id,direct.id,'synthetic',key,'text',options);
  await assert.rejects(send('missing-ack',{}),{code:'oa_transport_acknowledgment_required'});assert.equal(f.store.send(f.actor.id,'missing-ack').state,'rejected');
  await assert.rejects(send('missing-ack'),{code:'idempotency_conflict'});
  assert.equal((await send('approved-oa')).protection,'line_transport');assert.equal((await send('approved-oa')).replayed,true);assert.equal(f.sends(),1);
  await assert.rejects(send('approved-oa',{}),{code:'idempotency_conflict'});
  f.response=new Error('uncertain socket');for(let i=0;i<2;i++)await assert.rejects(send('unknown-oa'),{code:'delivery_unknown'});
  assert.equal(f.store.send(f.actor.id,'unknown-oa').state,'unknown');assert.equal(f.sends(),2);
  await assert.rejects(send('invalid-ack',{acknowledgeOaTransport:'true'}),{code:'invalid_input'});
});

test('OA capability requires send scope, and revoked token/designation blocks dispatch after preparation',async t=>{
  for(const revoke of ['token','chat','pause']){
    const f=await hubFixture(t);assert.equal((await f.hub.textCapability(f.actor,f.id,direct.id)).officialAccount,true);
    await assert.rejects(f.hub.read(f.actor,f.id,direct.id),{code:'scope_denied'});
    const raw=f.client.request.request;f.client.request.request=async(...args)=>{const value=await raw(...args);if(args[1]==='getBuddyDetail'){
      if(revoke==='token')f.store.revoke(f.token.id);else if(revoke==='chat')f.hub.designate(f.id,direct.id,false);else f.store.setSetting('aiEnabled',false);
    }return value;};
    await assert.rejects(f.hub.send(f.actor,f.id,direct.id,'synthetic','revoked-'+revoke,'text',ack),{code:'send_authorization_revoked'});assert.equal(f.sends(),0);
    assert.equal(f.store.send(f.actor.id,'revoked-'+revoke).state,'rejected');
  }
  const f=await hubFixture(t),readOnly=f.hub.createToken({name:'read-only',grants:[{accountId:f.id,read:true,send:false,chatIds:[direct.id]}]});
  await assert.rejects(f.hub.textCapability(f.hub.authenticate(readOnly.token),f.id,direct.id),{code:'scope_denied'});assert.equal(f.calls.length,0);
});

test('worker dispatch permission handshake denies expired requests and rechecks only the bound pending send',()=>{
  const worker=new ProtocolWorker(null,null,null),replies=[];worker.write=value=>replies.push(value);let checks=0;
  worker.pending.set('allowed',{method:'send',beforeDispatch:()=>{checks++;}});
  worker.pending.set('revoked',{method:'send',beforeDispatch:()=>{throw new SendRejectedError(403,'denied','synthetic');}});
  worker.pending.set('read',{method:'read',beforeDispatch:()=>assert.fail('Not a send')});
  for(const id of ['allowed','revoked','expired','read'])worker.handle({type:'authorize_send',id});
  assert.deepEqual(replies.map(r=>r.ok),[true,false,false,false]);assert.equal(checks,1);
});

test('revocation or expiry while the real SDK waits for reqseq persistence prevents dispatch',async t=>{
  for(const change of ['revoke','expire']){
    const f=await hubFixture(t);delete f.client.getReqseq;
    let entered,release;const writing=new Promise(r=>entered=r),acknowledged=new Promise(r=>release=r);
    const originalSet=f.client.storage.set;
    f.client.storage.set=async(key,value)=>{if(key==='reqseq'){entered();await acknowledged;}return originalSet(key,value);};
    const sending=f.hub.send(f.actor,f.id,direct.id,'synthetic',`reqseq-${change}`,'text',ack);
    const rejected=assert.rejects(sending,{code:'send_authorization_revoked'});
    await writing;assert.equal(f.sends(),0);
    if(change==='revoke')f.store.revoke(f.token.id);
    else f.store.db.prepare('UPDATE tokens SET expires_at=? WHERE id=?').run('2000-01-01T00:00:00Z',f.token.id);
    release();await rejected;assert.equal(f.sends(),0);assert.equal(f.store.send(f.actor.id,`reqseq-${change}`).state,'rejected');
  }
});

test('per-send authorization runs after real reqseq storage and leaves concurrent unrelated RPCs unchanged',async t=>{
  const f=fixture(t);delete f.client.getReqseq;
  let entered,release,checks=0;const writing=new Promise(r=>entered=r),acknowledged=new Promise(r=>release=r);
  const originalSet=f.client.storage.set,originalRequest=f.client.request.request,originalTalk=f.client.talk;
  f.client.storage.set=async(key,value)=>{if(key==='reqseq'){entered();await acknowledged;}return originalSet(key,value);};
  f.client.request.request=async(...args)=>args[1]==='getProfile'?{mid:'synthetic-profile'}:originalRequest(...args);
  const request=f.client.request.request;
  const sending=f.driver.send(direct,'synthetic',ack,()=>{checks++;assert.ok(f.values.has('reqseq'));});
  await writing;assert.equal(checks,0);assert.equal((await f.client.talk.getProfile()).mid,'synthetic-profile');assert.equal(checks,0);
  release();assert.equal((await sending).messageId,'synthetic-accepted');assert.equal(checks,1);assert.equal(f.sends(),1);
  assert.equal(f.client.request.request,request);assert.equal(f.client.talk,originalTalk);
});

test('UI confirmation happens before reserving intent; cancellation sends nothing; uncertain intent stays unchanged',async()=>{
  let confirmations=0,keys=0;const options={capability:async()=>({officialAccount:true}),confirm:async()=>{confirmations++;return false;},newKey:()=>String(++keys)};
  assert.equal(await prepareSendIntent(null,'a',direct.id,'synthetic',options),null);assert.equal(keys,0);
  options.confirm=async()=>{confirmations++;return true;};const intent=await prepareSendIntent(null,'a',direct.id,'synthetic',options);assert.equal(intent.acknowledgeOaTransport,true);
  options.capability=()=>assert.fail('Uncertain retry must not create new intent');assert.equal(await prepareSendIntent(intent,'a',direct.id,'synthetic',options),intent);assert.equal(confirmations,2);assert.equal(keys,1);
});

test('CLI OA opt-in is explicit, scoped to the send body, and error guidance never reflects upstream secrets',async()=>{
  for(const allowed of [false,true]){let calls=0,output='';
    const code=await runCli(['send','--account','synthetic','--chat',direct.id,'--key','synthetic-key','--text','synthetic',...(allowed?['--acknowledge-oa-transport']:[])],{
      env:{LINE_BRIDGE_TOKEN:'synthetic'},stdin:Readable.from([]),stdout:{write:s=>output+=s},stderr:{write(){}},fetchImpl:async(_url,options)=>{calls++;assert.deepEqual(JSON.parse(options.body),{text:'synthetic',...(allowed?ack:{})});return allowed?new Response(JSON.stringify({messageId:'synthetic'})):new Response(JSON.stringify({error:'oa_transport_acknowledgment_required',message:'SECRET'}),{status:409});}
    });assert.equal(calls,1);assert.equal(code,allowed?0:6);assert.doesNotMatch(output,/SECRET/);if(!allowed)assert.match(output,/not Letter Sealed/);
  }
});

test('HTTP and MCP carry OA acknowledgment through authenticated send scopes and reject missing approval',async t=>{
  const probe=createServer();await new Promise(r=>probe.listen(0,'127.0.0.1',r));const port=probe.address().port;await new Promise(r=>probe.close(r));
  const f=await hubFixture(t),tunnels=new Tunnels(f.store,f.hub.vault,process.cwd(),port);t.after(()=>tunnels.close());
  const {gateway}=createApps({hub:f.hub,tunnels,root:process.cwd(),adminPort:0,gatewayPort:port});
  const server=gateway.listen(port,'127.0.0.1');await new Promise(r=>server.once('listening',r));t.after(()=>{server.closeAllConnections();server.close();});
  const base=`http://127.0.0.1:${server.address().port}`,headers={Authorization:`Bearer ${f.token.token}`,'Content-Type':'application/json'},url=`${base}/api/v1/accounts/${f.id}/chats/${direct.id}/messages`;
  assert.equal((await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text:'synthetic',...ack})})).status,401);
  const missing=await fetch(url,{method:'POST',headers:{...headers,'Idempotency-Key':'http-no-ack'},body:JSON.stringify({text:'synthetic'})});assert.equal(missing.status,409);assert.equal((await missing.json()).error,'oa_transport_acknowledgment_required');
  const accepted=await fetch(url,{method:'POST',headers:{...headers,'Idempotency-Key':'http-with-ack'},body:JSON.stringify({text:'synthetic',...ack})});assert.equal(accepted.status,200);assert.equal((await accepted.json()).protection,'line_transport');
  const client=new Client({name:'oa-synthetic-test',version:'1'});await client.connect(new StreamableHTTPClientTransport(new URL(`${base}/mcp`),{requestInit:{headers}}));t.after(()=>client.close());
  const denied=await client.callTool({name:'line_send_message',arguments:{accountId:f.id,chatId:direct.id,text:'synthetic',idempotencyKey:'mcp-no-ack'}});assert.equal(denied.isError,true);assert.equal(JSON.parse(denied.content[0].text).error,'oa_transport_acknowledgment_required');
  const result=await client.callTool({name:'line_send_message',arguments:{accountId:f.id,chatId:direct.id,text:'synthetic',idempotencyKey:'mcp-with-ack',...ack}});assert.equal(result.isError,undefined);assert.equal(JSON.parse(result.content[0].text).protection,'line_transport');assert.equal(f.sends(),2);
});
